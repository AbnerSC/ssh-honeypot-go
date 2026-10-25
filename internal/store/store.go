// Package store 提供攻击日志的 SQLite 持久化存储。
//
// 表结构与 JSONL 事件类型对应关系（与 Java 版 SqliteLogStore 逐字一致）：
//
//	session_open  -> sessions（插入）
//	session_close -> sessions（更新 closed_at / duration_ms）
//	auth_attempt  -> auth_attempts
//	command       -> commands
//	download      -> downloads
//	ip_locked     -> ip_locks
//
// 并发模型：写连接只有一条（database/sql 连接池上限 1），由 attacklog 的
// 单写入协程串行调用，因此无需额外加锁；WAL 模式允许 Web 端只读连接并发查询而不阻塞写入。
package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，CGO_ENABLED=0 可交叉编译
)

// schemaVersion 当前数据库版本（PRAGMA user_version）。
// 1：初始表结构；2：sessions 增加 location；3：其余含来源 IP 的事件表增加 location。
const schemaVersion = 3

// schemaTables 建表语句（幂等）。数据库版本通过 user_version 管理，便于以后迁移。
var schemaTables = []string{
	`
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL UNIQUE,   -- 会话编号（对应 JSONL 的 session 字段）
    protocol        TEXT    NOT NULL,          -- 协议: ssh / telnet / mysql / postgresql / redis
    src_ip          TEXT    NOT NULL,          -- 攻击者来源 IP
    src_port        INTEGER,                   -- 攻击者来源端口
    opened_at       TEXT    NOT NULL,          -- 会话开始时间 yyyy-MM-dd HH:mm:ss.SSS
    opened_epoch_ms INTEGER NOT NULL,          -- 会话开始时间（epoch 毫秒，便于时间范围统计）
    closed_at       TEXT,                      -- 会话结束时间（异常断开时为 NULL）
    duration_ms     INTEGER,                   -- 会话持续时长（毫秒）
    location        TEXT                       -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
)`,
	`
CREATE TABLE IF NOT EXISTS auth_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,              -- 事件时间 yyyy-MM-dd HH:mm:ss.SSS
    ts_epoch_ms INTEGER NOT NULL,              -- 事件时间（epoch 毫秒）
    session_id  TEXT,                          -- 所属会话编号
    protocol    TEXT,                          -- 协议: ssh / telnet / mysql / postgresql / redis
    src_ip      TEXT    NOT NULL,              -- 攻击者来源 IP
    username    TEXT    NOT NULL,              -- 尝试登录的用户名
    password    TEXT    NOT NULL,              -- 尝试登录的口令
    success     INTEGER NOT NULL CHECK (success IN (0, 1)),  -- 是否登录成功(蜜罐放行)
    location    TEXT                           -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
)`,
	`
CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    ts_epoch_ms INTEGER NOT NULL,
    session_id  TEXT,
    src_ip      TEXT    NOT NULL,
    username    TEXT,
    command     TEXT    NOT NULL,              -- 执行的完整命令行
    location    TEXT                           -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
)`,
	`
CREATE TABLE IF NOT EXISTS downloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    ts_epoch_ms INTEGER NOT NULL,
    session_id  TEXT,
    src_ip      TEXT    NOT NULL,
    username    TEXT,
    url         TEXT    NOT NULL,              -- 恶意下载 URL
    location    TEXT                           -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
)`,
	`
CREATE TABLE IF NOT EXISTS ip_locks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,
    ts_epoch_ms  INTEGER NOT NULL,
    src_ip       TEXT    NOT NULL,             -- 被锁定的源 IP
    locked_until TEXT    NOT NULL,             -- 锁定解除时间
    location     TEXT                          -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
)`,
}

// schemaIndexes 建索引语句（幂等）。必须在补列迁移之后执行：
// 旧库（user_version<3）的事件表没有 location 列，提前建索引会报 no such column。
var schemaIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_opened ON sessions(opened_epoch_ms)`,
	// 协议分布统计走覆盖索引，避免大表全表扫描
	`CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_src_ip ON auth_attempts(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(ts_epoch_ms)`,
	// 口令排行 / 地区排行统计走覆盖索引，避免大表全表扫描
	`CREATE INDEX IF NOT EXISTS idx_auth_password ON auth_attempts(password)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_location ON auth_attempts(location)`,
	`CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)`,
	`CREATE INDEX IF NOT EXISTS idx_commands_src_ip ON commands(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_commands_ts ON commands(ts_epoch_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_downloads_src_ip ON downloads(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_downloads_ts ON downloads(ts_epoch_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_ip_locks_src_ip ON ip_locks(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_ip_locks_ts ON ip_locks(ts_epoch_ms)`,
}

// locationTables 需要 location 列的事件表（user_version 3 起的迁移目标）。
var locationTables = []string{"sessions", "auth_attempts", "commands", "downloads", "ip_locks"}

const (
	sqlInsertSession = `INSERT INTO sessions(session_id, protocol, src_ip, src_port, opened_at, opened_epoch_ms, location) VALUES(?,?,?,?,?,?,?)`
	sqlCloseSession  = `UPDATE sessions SET closed_at = ?, duration_ms = ? WHERE session_id = ?`
	sqlInsertAuth    = `INSERT INTO auth_attempts(ts, ts_epoch_ms, session_id, protocol, src_ip, username, password, success, location) VALUES(?,?,?,?,?,?,?,?,?)`
	sqlInsertCommand = `INSERT INTO commands(ts, ts_epoch_ms, session_id, src_ip, username, command, location) VALUES(?,?,?,?,?,?,?)`
	sqlInsertDown    = `INSERT INTO downloads(ts, ts_epoch_ms, session_id, src_ip, username, url, location) VALUES(?,?,?,?,?,?,?)`
	sqlInsertIpLock  = `INSERT INTO ip_locks(ts, ts_epoch_ms, src_ip, locked_until, location) VALUES(?,?,?,?,?)`

	// sqlCloseOrphanSessions 启动时补齐上次进程遗留的未关闭会话（进程被强杀/OOM/断电）。
	// 新进程启动时不存在任何在途会话，残留的 closed_at IS NULL 会让 Web 端「在线会话」永远显示在线。
	sqlCloseOrphanSessions = `UPDATE sessions
SET closed_at = strftime('%Y-%m-%d %H:%M:%f','now','localtime'),
    duration_ms = MAX(0, CAST((julianday('now','localtime') - julianday(opened_at)) * 86400000 AS INTEGER))
WHERE closed_at IS NULL`
)

// Store 攻击日志持久化存储。
type Store struct {
	db     *sql.DB
	logger *slog.Logger

	insertSession  *sql.Stmt
	closeSession   *sql.Stmt
	insertAuth     *sql.Stmt
	insertCommand  *sql.Stmt
	insertDownload *sql.Stmt
	insertIPLock   *sql.Stmt
}

// Open 打开（必要时创建）数据库并完成建表与版本迁移。
func Open(path string, logger *slog.Logger) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("解析数据库路径 %s 失败: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}

	db, err := sql.Open("sqlite", dsn(abs))
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 单写连接：写操作由单协程串行调用，也保证连接级 PRAGMA 只设置一次且始终生效
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, logger: logger}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.prepare(); err != nil {
		db.Close()
		return nil, err
	}
	infof(logger, "SQLite 数据库: "+abs)
	return s, nil
}

// dsn 构造带连接级 PRAGMA 的 DSN：每次新建连接都自动生效，避免连接重建后丢失设置。
func dsn(abs string) string {
	params := []string{
		"_pragma=journal_mode(WAL)",   // 读写并发：Web 端查询不阻塞蜜罐写入
		"_pragma=synchronous(NORMAL)", // WAL 模式下兼顾写入性能与可靠性
		"_pragma=busy_timeout(5000)",
		"_pragma=cache_size(-600)", // 页缓存收紧至约 600KB，降低常驻内存
	}
	return "file:" + filepath.ToSlash(abs) + "?" + strings.Join(params, "&")
}

// init 执行建表、补列迁移、建索引与 user_version 写入。
// 顺序不可调换：旧库的事件表缺少 location 列时必须先补列，否则建索引会报 no such column。
func (s *Store) init() error {
	for _, ddl := range schemaTables {
		if _, err := s.db.Exec(ddl); err != nil {
			return fmt.Errorf("初始化表结构失败: %w", err)
		}
	}

	// 旧库迁移：不依赖 user_version，逐表检查 location 是否存在（对新建库为空操作，更健壮）
	for _, table := range locationTables {
		s.ensureColumn(table, "location", "ALTER TABLE "+table+" ADD COLUMN location TEXT")
	}

	for _, ddl := range schemaIndexes {
		if _, err := s.db.Exec(ddl); err != nil {
			return fmt.Errorf("初始化索引失败: %w", err)
		}
	}

	// 崩溃恢复：进程启动即意味着上次的连接已全部消失，把残留的未关闭会话补齐，
	// 否则 Web 控制台的「在线会话」会永久留在在线状态。
	if _, err := s.db.Exec(sqlCloseOrphanSessions); err != nil {
		return fmt.Errorf("清理残留会话失败: %w", err)
	}

	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		return fmt.Errorf("写入数据库版本失败: %w", err)
	}
	return nil
}

// ensureColumn 列不存在时补加，失败仅告警（不阻塞启动）。
func (s *Store) ensureColumn(table, column, alterStmt string) {
	exists, err := s.hasColumn(table, column)
	if err != nil {
		warnf(s.logger, fmt.Sprintf("检查列 %s.%s 失败: %v", table, column, err))
		return
	}
	if exists {
		return
	}
	if _, err := s.db.Exec(alterStmt); err != nil {
		warnf(s.logger, fmt.Sprintf("迁移语句跳过（%s）: %v", alterStmt, err))
	}
}

// hasColumn 通过 PRAGMA table_info 判断列是否存在。
func (s *Store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// prepare 预编译写入语句，供单写入协程复用。
func (s *Store) prepare() error {
	targets := []struct {
		query string
		dest  **sql.Stmt
	}{
		{sqlInsertSession, &s.insertSession},
		{sqlCloseSession, &s.closeSession},
		{sqlInsertAuth, &s.insertAuth},
		{sqlInsertCommand, &s.insertCommand},
		{sqlInsertDown, &s.insertDownload},
		{sqlInsertIpLock, &s.insertIPLock},
	}
	for _, t := range targets {
		stmt, err := s.db.Prepare(t.query)
		if err != nil {
			return fmt.Errorf("预编译 SQL 失败（%s）: %w", t.query, err)
		}
		*t.dest = stmt
	}
	return nil
}

// Healthy 数据库是否可用（Web 控制台依赖数据库，不可用时不启动）。
func (s *Store) Healthy() bool {
	return s != nil && s.db != nil
}

// RecordSessionOpen 记录会话开始。
func (s *Store) RecordSessionOpen(ts string, epochMs int64, sessionID, protocol, ip string, port int, location string) error {
	return s.exec(s.insertSession, sessionID, protocol, ip, port, ts, epochMs, nullable(location))
}

// RecordSessionClose 更新会话结束时间与时长。
func (s *Store) RecordSessionClose(ts, sessionID string, durationMs int64) error {
	return s.exec(s.closeSession, ts, durationMs, sessionID)
}

// RecordAuthAttempt 记录一次登录尝试。
func (s *Store) RecordAuthAttempt(ts string, epochMs int64, sessionID, protocol, ip,
	username, password string, success bool, location string) error {
	return s.exec(s.insertAuth, ts, epochMs, nullable(sessionID), nullable(protocol), ip,
		username, password, boolToInt(success), nullable(location))
}

// RecordCommand 记录一条命令。
func (s *Store) RecordCommand(ts string, epochMs int64, sessionID, ip, username, cmdline, location string) error {
	return s.exec(s.insertCommand, ts, epochMs, nullable(sessionID), ip, nullable(username), cmdline, nullable(location))
}

// RecordDownload 记录一次恶意下载。
func (s *Store) RecordDownload(ts string, epochMs int64, sessionID, ip, username, url, location string) error {
	return s.exec(s.insertDownload, ts, epochMs, nullable(sessionID), ip, nullable(username), url, nullable(location))
}

// RecordIPLocked 记录一次源 IP 锁定；until 文本由调用方按同一时间格式生成。
func (s *Store) RecordIPLocked(ts string, epochMs int64, ip, until, location string) error {
	return s.exec(s.insertIPLock, ts, epochMs, ip, until, nullable(location))
}

func (s *Store) exec(stmt *sql.Stmt, args ...any) error {
	if _, err := stmt.Exec(args...); err != nil {
		return fmt.Errorf("写入 SQLite 失败: %w", err)
	}
	return nil
}

// Close 关闭数据库：先做 WAL checkpoint 收敛日志，再释放连接。
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	for _, stmt := range []*sql.Stmt{s.insertSession, s.closeSession, s.insertAuth,
		s.insertCommand, s.insertDownload, s.insertIPLock} {
		if stmt != nil {
			_ = stmt.Close()
		}
	}
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		warnf(s.logger, "WAL checkpoint 失败: "+err.Error())
	}
	return s.db.Close()
}

// nullable 空串转 NULL，保持与 Java 版「null 字段写 NULL」一致的语义。
func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func infof(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Info(msg)
	}
}

func warnf(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Warn(msg)
	}
}

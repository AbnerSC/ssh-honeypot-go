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
//
// 预聚合统计：在明细表之外新增 stats_daily / stats_ip_daily（user_version 4），
// 每次事件写入时用两条 UPSERT 累加（按天 + 按天&来源 IP）；
// user_version 5 再补 stats_usernames / stats_passwords / stats_locations 三张累计排行表。
// Web 端统计接口直接读聚合结果，不再对百万级明细表做全表 COUNT / GROUP BY；
// 排行表不带 day 维度：排行榜只按累计次数排序，按天再拆只会把行数放大到「天数 × 去重值」。
// user_version 6 退役明细表上的口令 / 归属地索引（见 schemaRetiredIndexes）。
// user_version 7 给 stats_locations 补 country 列：多词国家名（South Korea）无法从
// 「国家 省份 城市」反推，按国家聚合只能依赖解析时单独保留的国家段。
//
// init 中的建表与数据迁移都是幂等的，全部成功后才写入 user_version；Go 版是唯一实现，
// 升级后不回退到 Java 版，因此版本号可以正常递增（见 schemaVersion）。
package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，CGO_ENABLED=0 可交叉编译
)

// schemaVersion 当前数据库版本（PRAGMA user_version）。
// 1：初始表结构；2：sessions 增加 location；3：其余含来源 IP 的事件表增加 location；
// 4：新增预聚合统计表 stats_daily / stats_ip_daily；
// 5：新增累计排行表 stats_usernames / stats_passwords / stats_locations；
// 6：退役 auth_attempts(password) / auth_attempts(location) 两条明细索引；
// 7：stats_locations 增加 country 列（多词国家名无法从拼接结果反推）。
//
// Go 版是唯一实现，升级后不再回退到 Java 版，因此版本号按需正常递增。
// 版本号标识库结构代次（供 checkdb 与运维自检）；数据迁移的触发条件则由
// migrateStats 依据聚合表与明细表的实际状态判断，不依赖版本号。
const schemaVersion = 7

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
	// 以下三张为 Go 版新增的预聚合统计表（Java 版没有，比对时按扩展表跳过）：
	// 明细写入时同步累加，Web 统计接口直接读聚合结果。
	`
CREATE TABLE IF NOT EXISTS stats_daily (
    day              TEXT    PRIMARY KEY,       -- 统计日 yyyy-MM-dd（本地时区）
    sessions         INTEGER NOT NULL DEFAULT 0,
    auth_attempts    INTEGER NOT NULL DEFAULT 0,
    commands         INTEGER NOT NULL DEFAULT 0,
    downloads        INTEGER NOT NULL DEFAULT 0,
    ip_locks         INTEGER NOT NULL DEFAULT 0,
    updated_epoch_ms INTEGER NOT NULL DEFAULT 0  -- 最近一次累加时间（epoch 毫秒）
)`,
	`
CREATE TABLE IF NOT EXISTS stats_ip_daily (
    day              TEXT    NOT NULL,          -- 统计日 yyyy-MM-dd
    src_ip           TEXT    NOT NULL,          -- 攻击者来源 IP
    sessions         INTEGER NOT NULL DEFAULT 0,
    auth_attempts    INTEGER NOT NULL DEFAULT 0,
    commands         INTEGER NOT NULL DEFAULT 0,
    downloads        INTEGER NOT NULL DEFAULT 0,
    ip_locks         INTEGER NOT NULL DEFAULT 0,
    location         TEXT,                      -- 来源 IP 归属地（回溯重建时取自明细表）
    updated_epoch_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, src_ip)
)`,
	// user_version 5：按「用户名 / 口令 / 归属地」的累计排行表（登录尝试维度）。
	// 键取去重后的取值，行数与尝试次数无关；归属地空串单独成键（Web 端归入「未知」）。
	`
CREATE TABLE IF NOT EXISTS stats_usernames (
    username         TEXT    NOT NULL PRIMARY KEY,
    auth_attempts    INTEGER NOT NULL DEFAULT 0
)`,
	`
CREATE TABLE IF NOT EXISTS stats_passwords (
    password         TEXT    NOT NULL PRIMARY KEY,
    auth_attempts    INTEGER NOT NULL DEFAULT 0
)`,
	`
CREATE TABLE IF NOT EXISTS stats_locations (
    location         TEXT    NOT NULL PRIMARY KEY,   -- 归属地原文（国家 省份 城市），空串表示未知
    country          TEXT    NOT NULL DEFAULT '',    -- 国家段（user_version 7）：按国家聚合用，旧数据为空串
    auth_attempts    INTEGER NOT NULL DEFAULT 0
)`,
}

// schemaIndexes 建索引语句（幂等）。必须在补列迁移之后执行：
// 旧库（user_version<3）的事件表没有 location 列，提前建索引会报 no such column。
//
// 只建被查询实际命中的索引。src_ip / username / ts 三类索引看似「只给 LIKE 用」，
// 但 SQLite 会把它们当作**覆盖索引扫描**：`WHERE src_ip LIKE '%x%'` 虽然无法用索引定位，
// 却可以只扫窄索引而不读整行宽表（实测登录表计数 133ms vs 全表 213ms），因此保留。
var schemaIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_opened ON sessions(opened_epoch_ms)`,
	// 协议分布统计走覆盖索引，避免大表全表扫描
	`CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_src_ip ON auth_attempts(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username)`,
	`CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(ts_epoch_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)`,
	`CREATE INDEX IF NOT EXISTS idx_commands_src_ip ON commands(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_commands_ts ON commands(ts_epoch_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_downloads_src_ip ON downloads(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_downloads_ts ON downloads(ts_epoch_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_ip_locks_src_ip ON ip_locks(src_ip)`,
	`CREATE INDEX IF NOT EXISTS idx_ip_locks_ts ON ip_locks(ts_epoch_ms)`,
	// 聚合表按 IP 排行：覆盖索引避免扫描全表
	`CREATE INDEX IF NOT EXISTS idx_stats_ip_daily_ip ON stats_ip_daily(src_ip, auth_attempts)`,
}

// schemaRetiredIndexes 退役索引（user_version 6）：建表建索引之后从老库里删除。
//
// 口令 / 归属地排行改由 stats_passwords / stats_locations 承担，明细表上的这两条
// 索引只剩「聚合表缺失时回退到明细统计」这一条路径会用到，代价却很高：
// 120 万条事件下 idx_auth_location 占 22.0MB、idx_auth_password 占 12.0MB，
// 其中 location 是高基数长字符串，索引几乎与数据本身等大。
// 实测删除后控制台查询无回归（聚合路径不读它们）；只有聚合表缺失的异常库回退统计
// 会退化成全表扫描（实测 70 万条登录记录下由 60–70ms 升到 620–830ms），该路径本身只用于兼容旧库。
var schemaRetiredIndexes = []string{
	`DROP INDEX IF EXISTS idx_auth_password`,
	`DROP INDEX IF EXISTS idx_auth_location`,
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

	// sqlUpsertDaily / sqlUpsertIPDaily 聚合累加：每条事件只让一个维度 +1，
	// 两条 UPSERT 的代价与表规模无关（day 为主键，day+src_ip 为联合主键）。
	sqlUpsertDaily = `INSERT INTO stats_daily(day, sessions, auth_attempts, commands, downloads, ip_locks, updated_epoch_ms)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(day) DO UPDATE SET
    sessions         = sessions + excluded.sessions,
    auth_attempts    = auth_attempts + excluded.auth_attempts,
    commands         = commands + excluded.commands,
    downloads        = downloads + excluded.downloads,
    ip_locks         = ip_locks + excluded.ip_locks,
    updated_epoch_ms = excluded.updated_epoch_ms`

	sqlUpsertIPDaily = `INSERT INTO stats_ip_daily(day, src_ip, sessions, auth_attempts, commands, downloads, ip_locks, location, updated_epoch_ms)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(day, src_ip) DO UPDATE SET
    sessions         = sessions + excluded.sessions,
    auth_attempts    = auth_attempts + excluded.auth_attempts,
    commands         = commands + excluded.commands,
    downloads        = downloads + excluded.downloads,
    ip_locks         = ip_locks + excluded.ip_locks,
    location         = COALESCE(stats_ip_daily.location, excluded.location),
    updated_epoch_ms = excluded.updated_epoch_ms`

	// sqlUpsertUsername / sqlUpsertPassword / sqlUpsertLocation 排行累加（user_version 5）：
	// 只有登录尝试事件写入；命中主键后累加，代价与表规模无关。
	sqlUpsertUsername = `INSERT INTO stats_usernames(username, auth_attempts) VALUES(?,?)
ON CONFLICT(username) DO UPDATE SET auth_attempts = auth_attempts + excluded.auth_attempts`

	sqlUpsertPassword = `INSERT INTO stats_passwords(password, auth_attempts) VALUES(?,?)
ON CONFLICT(password) DO UPDATE SET auth_attempts = auth_attempts + excluded.auth_attempts`

	sqlUpsertLocation = `INSERT INTO stats_locations(location, country, auth_attempts) VALUES(?,?,?)
ON CONFLICT(location) DO UPDATE SET
    auth_attempts = auth_attempts + excluded.auth_attempts,
    -- 老数据（country 为空串）首次按新版本写入时补齐国家段，已有值不覆盖
    country = CASE WHEN stats_locations.country = '' THEN excluded.country ELSE stats_locations.country END`
)

// 回填 SQL：把五张明细表的增量用 UNION ALL 归一到同一形状，再按天（或天+IP）汇总；
// 排行表回填只扫 auth_attempts。
// 只在首次升级（缺少对应聚合表）或聚合表被清空时执行一次，单事务提交，崩溃不会留下半成品。
var (
	sqlBackfillDaily = `
INSERT INTO stats_daily(day, sessions, auth_attempts, commands, downloads, ip_locks, updated_epoch_ms)
SELECT day, SUM(sessions), SUM(auth_attempts), SUM(commands), SUM(downloads), SUM(ip_locks), ?
FROM (
    SELECT substr(opened_at,1,10) AS day, 1 AS sessions, 0 AS auth_attempts, 0 AS commands, 0 AS downloads, 0 AS ip_locks FROM sessions
    UNION ALL SELECT substr(ts,1,10), 0, 1, 0, 0, 0 FROM auth_attempts
    UNION ALL SELECT substr(ts,1,10), 0, 0, 1, 0, 0 FROM commands
    UNION ALL SELECT substr(ts,1,10), 0, 0, 0, 1, 0 FROM downloads
    UNION ALL SELECT substr(ts,1,10), 0, 0, 0, 0, 1 FROM ip_locks
)
WHERE day <> ''
GROUP BY day`

	sqlBackfillIPDaily = `
INSERT INTO stats_ip_daily(day, src_ip, sessions, auth_attempts, commands, downloads, ip_locks, location, updated_epoch_ms)
SELECT day, src_ip, SUM(sessions), SUM(auth_attempts), SUM(commands), SUM(downloads), SUM(ip_locks), MAX(location), ?
FROM (
    SELECT substr(opened_at,1,10) AS day, src_ip, 1 AS sessions, 0 AS auth_attempts, 0 AS commands, 0 AS downloads, 0 AS ip_locks, location FROM sessions
    UNION ALL SELECT substr(ts,1,10), src_ip, 0, 1, 0, 0, 0, location FROM auth_attempts
    UNION ALL SELECT substr(ts,1,10), src_ip, 0, 0, 1, 0, 0, location FROM commands
    UNION ALL SELECT substr(ts,1,10), src_ip, 0, 0, 0, 1, 0, location FROM downloads
    UNION ALL SELECT substr(ts,1,10), src_ip, 0, 0, 0, 0, 1, location FROM ip_locks
)
WHERE day <> '' AND src_ip <> ''
GROUP BY day, src_ip`

	// 排行表回溯：只扫 auth_attempts，按去重取值汇总；
	// 归属地用 COALESCE 把 NULL 归入空串键，与写入路径的口径保持一致。
	sqlBackfillUsernames = `
INSERT INTO stats_usernames(username, auth_attempts)
SELECT username, COUNT(*) FROM auth_attempts
WHERE username <> ''
GROUP BY username`

	sqlBackfillPasswords = `
INSERT INTO stats_passwords(password, auth_attempts)
SELECT password, COUNT(*) FROM auth_attempts
WHERE password <> ''
GROUP BY password`

	// country 由 init 的 backfillLocationCountry 用来源 IP 重新解析后回填：
	// 建表时无法从「国家 省份 城市」反推多词国家名。
	sqlBackfillLocations = `
INSERT INTO stats_locations(location, country, auth_attempts)
SELECT COALESCE(location, ''), '', COUNT(*) FROM auth_attempts
GROUP BY COALESCE(location, '')`
)

// stmtKey 预编译语句编号，避免在热路径上按字符串查表。
type stmtKey int

const (
	stmtSessionOpen stmtKey = iota
	stmtSessionClose
	stmtAuthAttempt
	stmtCommand
	stmtDownload
	stmtIPLocked
	stmtDaily
	stmtIPDaily
	stmtUsername
	stmtPassword
	stmtLocation
	stmtCount
)

// Writer 攻击日志写入接口：Store 直接提交（自动提交），Tx 在事务内批量提交。
// attacklog 的写入动作依赖该接口，同一份代码路径既能单条写也能批量写。
type Writer interface {
	RecordSessionOpen(ts string, epochMs int64, sessionID, protocol, ip string, port int, location string) error
	RecordSessionClose(ts, sessionID string, durationMs int64) error
	RecordAuthAttempt(ts string, epochMs int64, sessionID, protocol, ip, username, password string, success bool, location, country string) error
	RecordCommand(ts string, epochMs int64, sessionID, ip, username, cmdline, location string) error
	RecordDownload(ts string, epochMs int64, sessionID, ip, username, url, location string) error
	RecordIPLocked(ts string, epochMs int64, ip, until, location string) error
}

// execer 语句提供者：Store（自动提交）与 Tx（事务内）共用的写入实现抽象。
type execer interface {
	statement(key stmtKey) (*sql.Stmt, error)
}

// CountryResolver 由来源 IP 解析国家段（ip2region 库）。
// 只在 user_version 7 升级回填历史 stats_locations 行时用到：
// 拼接后的归属地无法反推多词国家名，必须回到 IP 重新解析。
type CountryResolver interface {
	CountryOf(ip string) string
}

// Option Open 的可选配置。
type Option func(*Store)

// WithCountryResolver 注入国家段解析器（通常即 geo.Locator）。
// 未注入时 country 列保持空串，Web 端按旧逻辑从 location 首段推断。
func WithCountryResolver(r CountryResolver) Option {
	return func(s *Store) { s.countries = r }
}

// Store 攻击日志持久化存储。
type Store struct {
	db        *sql.DB
	logger    *slog.Logger
	stmts     [stmtCount]*sql.Stmt
	countries CountryResolver
}

// Open 打开（必要时创建）数据库并完成建表与版本迁移。
func Open(path string, logger *slog.Logger, opts ...Option) (*Store, error) {
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
	for _, opt := range opts {
		opt(s)
	}
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
	// 先读升级前的版本：country 回填这类一次性数据迁移只在跨版本时执行，
	// 避免每次启动都重扫明细表。
	version, err := s.readVersion()
	if err != nil {
		return err
	}

	for _, ddl := range schemaTables {
		if _, err := s.db.Exec(ddl); err != nil {
			return fmt.Errorf("初始化表结构失败: %w", err)
		}
	}

	// 旧库迁移：不依赖 user_version，逐表检查 location 是否存在（对新建库为空操作，更健壮）
	for _, table := range locationTables {
		s.ensureColumn(table, "location", "ALTER TABLE "+table+" ADD COLUMN location TEXT")
	}
	// stats_locations.country（user_version 7）：这里失败必须中断启动，
	// 缺列会让每次登录尝试的排行 UPSERT 报错，继续运行等于丢掉全部归属地排行。
	if err := s.ensureLocationCountry(); err != nil {
		return err
	}

	for _, ddl := range schemaIndexes {
		if _, err := s.db.Exec(ddl); err != nil {
			return fmt.Errorf("初始化索引失败: %w", err)
		}
	}

	// 退役索引在索引创建之后清理：老库上它们仍然存在，DROP 是幂等的。
	for _, ddl := range schemaRetiredIndexes {
		if _, err := s.db.Exec(ddl); err != nil {
			return fmt.Errorf("清理退役索引失败: %w", err)
		}
	}
	s.reportFreePages()

	// 崩溃恢复：进程启动即意味着上次的连接已全部消失，把残留的未关闭会话补齐，
	// 否则 Web 控制台的「在线会话」会永久留在在线状态。
	if _, err := s.db.Exec(sqlCloseOrphanSessions); err != nil {
		return fmt.Errorf("清理残留会话失败: %w", err)
	}

	// 预聚合统计表的回填标记曾用 stats_meta 表记录，现由 user_version 取代；
	// 清理过渡期残留表，保证库结构与代码声明一致（全新库为空操作）。
	if _, err := s.db.Exec(`DROP TABLE IF EXISTS stats_meta`); err != nil {
		return fmt.Errorf("清理过渡表 stats_meta 失败: %w", err)
	}

	// 版本迁移：user_version 4 引入按天/按 IP 聚合表，5 引入排行表；
	// 旧库需要从明细回溯历史数据。必须在写入 user_version 之前完成，
	// 中途失败时下次启动会重试。
	rebuilt, err := s.migrateStats()
	if err != nil {
		return err
	}

	// user_version 7：给历史 stats_locations 行补齐国家段。
	// 排行表回填（rebuildRankings）只能写入空串 country，因为 SQLite 侧
	// 无法解析 IP，必须回到 Go 里用 ip2region 重新解析，因此排在它之后；
	// 排行表被清空重建时同样需要重新回填（country 列随行一起被删）。
	if version < 7 || rebuilt {
		if err := s.backfillLocationCountry(); err != nil {
			return err
		}
	}

	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		return fmt.Errorf("写入数据库版本失败: %w", err)
	}
	return nil
}

// reportFreePages 删除退役索引释放的页会留在文件里（SQLite 不会自动缩小文件），
// 空闲页超过 8MB 时提示一次；VACUUM 需要独占写锁且耗时随库体积增长，不在启动路径自动执行。
func (s *Store) reportFreePages() {
	var pages, pageSize int64
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&pages); err != nil {
		return
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return
	}
	if free := pages * pageSize; free > 8<<20 {
		infof(s.logger, fmt.Sprintf("库内空闲页约 %d MB（退役索引释放），可离线执行 VACUUM 回收磁盘", free>>20))
	}
}

// readVersion 读取当前数据库版本（全新库为 0）。
func (s *Store) readVersion() (int, error) {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("读取数据库版本失败: %w", err)
	}
	return v, nil
}

// ensureLocationCountry 给 stats_locations 补 country 列（user_version 7）。
// 与 ensureColumn 不同：这里失败直接返回错误，由 init 中断启动。
func (s *Store) ensureLocationCountry() error {
	exists, err := s.hasColumn("stats_locations", "country")
	if err != nil {
		return fmt.Errorf("检查列 stats_locations.country 失败: %w", err)
	}
	if exists {
		return nil
	}
	if _, err := s.db.Exec(`ALTER TABLE stats_locations ADD COLUMN country TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("迁移列 stats_locations.country 失败: %w", err)
	}
	return nil
}

// backfillLocationCountry 给历史 stats_locations 行补齐国家段（user_version 7）。
//
// 拼接后的 location（「国家 省份 城市」）无法反推多词国家名（South Korea、United
// States），因此按 location 取一条明细记录的来源 IP，用 ip2region 重新解析。
// 每个 location 只取一个 IP（MIN）足够：同一归属地串对应的 IP 国家段必然相同。
//
// 结果集必须先读完并关闭再开事务：写连接池上限为 1，边读边写会死锁。
func (s *Store) backfillLocationCountry() error {
	if s.countries == nil {
		return nil
	}

	pending, err := s.pendingLocations()
	if err != nil || len(pending) == 0 {
		return err
	}

	rows, err := s.db.Query(`SELECT location, MIN(src_ip) FROM auth_attempts
		WHERE location IS NOT NULL AND location <> ''
		GROUP BY location`)
	if err != nil {
		return fmt.Errorf("查询待回填归属地失败: %w", err)
	}
	type fill struct{ location, country string }
	fills := make([]fill, 0, len(pending))
	for rows.Next() {
		var location, ip string
		if err := rows.Scan(&location, &ip); err != nil {
			rows.Close()
			return fmt.Errorf("读取待回填归属地失败: %w", err)
		}
		if !pending[location] {
			continue
		}
		if country := s.countries.CountryOf(ip); country != "" {
			fills = append(fills, fill{location, country})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("读取待回填归属地失败: %w", err)
	}
	rows.Close()
	if len(fills) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("开启国家段回填事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已提交时为 ErrTxDone，可忽略

	start := time.Now()
	for _, f := range fills {
		if _, err := tx.Exec(`UPDATE stats_locations SET country = ? WHERE location = ? AND country = ''`,
			f.country, f.location); err != nil {
			return fmt.Errorf("回填归属地国家段失败: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交国家段回填事务失败: %w", err)
	}
	infof(s.logger, fmt.Sprintf("归属地国家段已回填 %d 行，耗时 %s", len(fills), time.Since(start).Round(time.Millisecond)))
	return nil
}

// pendingLocations 列出 stats_locations 中 country 为空的行（排行表行数与去重
// 归属地数相当，扫描代价与明细表规模无关）。
func (s *Store) pendingLocations() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT location FROM stats_locations WHERE country = ''`)
	if err != nil {
		return nil, fmt.Errorf("查询待回填归属地失败: %w", err)
	}
	defer rows.Close()

	out := make(map[string]bool, 64)
	for rows.Next() {
		var location string
		if err := rows.Scan(&location); err != nil {
			return nil, fmt.Errorf("读取待回填归属地失败: %w", err)
		}
		out[location] = true
	}
	return out, rows.Err()
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
	queries := [stmtCount]string{
		stmtSessionOpen:  sqlInsertSession,
		stmtSessionClose: sqlCloseSession,
		stmtAuthAttempt:  sqlInsertAuth,
		stmtCommand:      sqlInsertCommand,
		stmtDownload:     sqlInsertDown,
		stmtIPLocked:     sqlInsertIpLock,
		stmtDaily:        sqlUpsertDaily,
		stmtIPDaily:      sqlUpsertIPDaily,
		stmtUsername:     sqlUpsertUsername,
		stmtPassword:     sqlUpsertPassword,
		stmtLocation:     sqlUpsertLocation,
	}
	for key, query := range queries {
		stmt, err := s.db.Prepare(query)
		if err != nil {
			return fmt.Errorf("预编译 SQL 失败（%s）: %w", query, err)
		}
		s.stmts[key] = stmt
	}
	return nil
}

// statement 取预编译语句（供 execer 接口使用）。
func (s *Store) statement(key stmtKey) (*sql.Stmt, error) {
	if key < 0 || key >= stmtCount || s.stmts[key] == nil {
		return nil, fmt.Errorf("SQL 语句未预编译: %d", key)
	}
	return s.stmts[key], nil
}

// Healthy 数据库是否可用（Web 控制台依赖数据库，不可用时不启动）。
func (s *Store) Healthy() bool {
	return s != nil && s.db != nil
}

// RecordSessionOpen 记录会话开始。
func (s *Store) RecordSessionOpen(ts string, epochMs int64, sessionID, protocol, ip string, port int, location string) error {
	return recordSessionOpen(s, ts, epochMs, sessionID, protocol, ip, port, location)
}

// RecordSessionClose 更新会话结束时间与时长。
func (s *Store) RecordSessionClose(ts, sessionID string, durationMs int64) error {
	return recordSessionClose(s, ts, sessionID, durationMs)
}

// RecordAuthAttempt 记录一次登录尝试；location 为「国家 省份 城市」，
// country 为国家段（只用于归属地排行表按国家聚合，不落明细表）。
func (s *Store) RecordAuthAttempt(ts string, epochMs int64, sessionID, protocol, ip,
	username, password string, success bool, location, country string) error {
	return recordAuthAttempt(s, ts, epochMs, sessionID, protocol, ip, username, password, success, location, country)
}

// RecordCommand 记录一条命令。
func (s *Store) RecordCommand(ts string, epochMs int64, sessionID, ip, username, cmdline, location string) error {
	return recordCommand(s, ts, epochMs, sessionID, ip, username, cmdline, location)
}

// RecordDownload 记录一次恶意下载。
func (s *Store) RecordDownload(ts string, epochMs int64, sessionID, ip, username, url, location string) error {
	return recordDownload(s, ts, epochMs, sessionID, ip, username, url, location)
}

// RecordIPLocked 记录一次源 IP 锁定；until 文本由调用方按同一时间格式生成。
func (s *Store) RecordIPLocked(ts string, epochMs int64, ip, until, location string) error {
	return recordIPLocked(s, ts, epochMs, ip, until, location)
}

// Tx 批量写入事务：attacklog 每批事件只提交一次，把 N 次 fsync 降为 1 次。
//
// 事务内必须通过 tx.Stmt 复用 Store 的预编译语句：写连接池上限为 1，
// 直接执行 *sql.Stmt 会等待那条已被事务占用的连接而死锁。
type Tx struct {
	store *Store
	tx    *sql.Tx
	stmts [stmtCount]*sql.Stmt
}

// Begin 开启批量写入事务。
func (s *Store) Begin() (*Tx, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("开启写入事务失败: %w", err)
	}
	return &Tx{store: s, tx: tx}, nil
}

// statement 取事务内语句：首次使用时由预编译语句派生并缓存。
func (t *Tx) statement(key stmtKey) (*sql.Stmt, error) {
	if key < 0 || key >= stmtCount {
		return nil, fmt.Errorf("SQL 语句未预编译: %d", key)
	}
	if t.stmts[key] != nil {
		return t.stmts[key], nil
	}
	base, err := t.store.statement(key)
	if err != nil {
		return nil, err
	}
	stmt := t.tx.Stmt(base)
	t.stmts[key] = stmt
	return stmt, nil
}

// RecordSessionOpen 记录会话开始（事务内）。
func (t *Tx) RecordSessionOpen(ts string, epochMs int64, sessionID, protocol, ip string, port int, location string) error {
	return recordSessionOpen(t, ts, epochMs, sessionID, protocol, ip, port, location)
}

// RecordSessionClose 更新会话结束时间与时长（事务内）。
func (t *Tx) RecordSessionClose(ts, sessionID string, durationMs int64) error {
	return recordSessionClose(t, ts, sessionID, durationMs)
}

// RecordAuthAttempt 记录一次登录尝试（事务内）。
func (t *Tx) RecordAuthAttempt(ts string, epochMs int64, sessionID, protocol, ip,
	username, password string, success bool, location, country string) error {
	return recordAuthAttempt(t, ts, epochMs, sessionID, protocol, ip, username, password, success, location, country)
}

// RecordCommand 记录一条命令（事务内）。
func (t *Tx) RecordCommand(ts string, epochMs int64, sessionID, ip, username, cmdline, location string) error {
	return recordCommand(t, ts, epochMs, sessionID, ip, username, cmdline, location)
}

// RecordDownload 记录一次恶意下载（事务内）。
func (t *Tx) RecordDownload(ts string, epochMs int64, sessionID, ip, username, url, location string) error {
	return recordDownload(t, ts, epochMs, sessionID, ip, username, url, location)
}

// RecordIPLocked 记录一次源 IP 锁定（事务内）。
func (t *Tx) RecordIPLocked(ts string, epochMs int64, ip, until, location string) error {
	return recordIPLocked(t, ts, epochMs, ip, until, location)
}

// Commit 提交事务。
func (t *Tx) Commit() error {
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("提交写入事务失败: %w", err)
	}
	return nil
}

// Rollback 回滚事务（已提交时返回 ErrTxDone，调用方可忽略）。
func (t *Tx) Rollback() error {
	return t.tx.Rollback()
}

// statsDelta 一次事件带来的统计增量（只累加一个维度）。
type statsDelta struct {
	sessions, authAttempts, commands, downloads, ipLocks int
}

// statsBump 一次事件要累加的统计目标与增量。
// rank 为 true 时才累加用户名 / 口令 / 归属地排行（只有登录尝试事件需要）。
type statsBump struct {
	ts       string
	epochMs  int64
	ip       string
	location string
	country  string // 国家段：只给归属地排行表用，明细表仍只存拼接后的 location
	username string
	password string
	rank     bool
	delta    statsDelta
}

func recordSessionOpen(e execer, ts string, epochMs int64, sessionID, protocol, ip string, port int, location string) error {
	return recordEvent(e, stmtSessionOpen,
		statsBump{ts: ts, epochMs: epochMs, ip: ip, location: location, delta: statsDelta{sessions: 1}},
		sessionID, protocol, ip, port, ts, epochMs, nullable(location))
}

func recordSessionClose(e execer, ts, sessionID string, durationMs int64) error {
	return execStmt(e, stmtSessionClose, ts, durationMs, sessionID)
}

func recordAuthAttempt(e execer, ts string, epochMs int64, sessionID, protocol, ip,
	username, password string, success bool, location, country string) error {
	return recordEvent(e, stmtAuthAttempt, statsBump{
		ts:       ts,
		epochMs:  epochMs,
		ip:       ip,
		location: location,
		country:  country,
		username: username,
		password: password,
		rank:     true,
		delta:    statsDelta{authAttempts: 1},
	},
		ts, epochMs, nullable(sessionID), nullable(protocol), ip, username, password, boolToInt(success), nullable(location))
}

func recordCommand(e execer, ts string, epochMs int64, sessionID, ip, username, cmdline, location string) error {
	return recordEvent(e, stmtCommand,
		statsBump{ts: ts, epochMs: epochMs, ip: ip, location: location, delta: statsDelta{commands: 1}},
		ts, epochMs, nullable(sessionID), ip, nullable(username), cmdline, nullable(location))
}

func recordDownload(e execer, ts string, epochMs int64, sessionID, ip, username, url, location string) error {
	return recordEvent(e, stmtDownload,
		statsBump{ts: ts, epochMs: epochMs, ip: ip, location: location, delta: statsDelta{downloads: 1}},
		ts, epochMs, nullable(sessionID), ip, nullable(username), url, nullable(location))
}

func recordIPLocked(e execer, ts string, epochMs int64, ip, until, location string) error {
	return recordEvent(e, stmtIPLocked,
		statsBump{ts: ts, epochMs: epochMs, ip: ip, location: location, delta: statsDelta{ipLocks: 1}},
		ts, epochMs, ip, until, nullable(location))
}

// recordEvent 先写明细再累加聚合：明细失败则不累加，保证两者可对账。
func recordEvent(e execer, key stmtKey, b statsBump, args ...any) error {
	if err := execStmt(e, key, args...); err != nil {
		return err
	}
	return bumpStats(e, b)
}

// bumpStats 累加预聚合计数：按天与按天&IP 各一条 UPSERT（命中主键，代价与表规模无关）；
// 登录尝试再累加用户名 / 口令 / 归属地三张累计排行表。
func bumpStats(e execer, b statsBump) error {
	day := dayOf(b.ts)
	if day == "" || b.ip == "" {
		return nil
	}
	daily, err := e.statement(stmtDaily)
	if err != nil {
		return err
	}
	if _, err := daily.Exec(day, b.delta.sessions, b.delta.authAttempts, b.delta.commands, b.delta.downloads, b.delta.ipLocks, b.epochMs); err != nil {
		return fmt.Errorf("累加按天统计失败: %w", err)
	}
	ipDaily, err := e.statement(stmtIPDaily)
	if err != nil {
		return err
	}
	if _, err := ipDaily.Exec(day, b.ip, b.delta.sessions, b.delta.authAttempts, b.delta.commands, b.delta.downloads, b.delta.ipLocks,
		nullable(b.location), b.epochMs); err != nil {
		return fmt.Errorf("累加按 IP 统计失败: %w", err)
	}
	if !b.rank {
		return nil
	}
	return bumpRankings(e, b)
}

// bumpRankings 累加用户名 / 口令 / 归属地排行。
// 归属地空串单独成键（对应 Web 端的「未知」分组），因此不做空值跳过。
func bumpRankings(e execer, b statsBump) error {
	items := []struct {
		stmt  stmtKey
		label string
		value string
	}{
		{stmtUsername, "用户名", b.username},
		{stmtPassword, "口令", b.password},
	}
	for _, item := range items {
		stmt, err := e.statement(item.stmt)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(item.value, 1); err != nil {
			return fmt.Errorf("累加%s排行失败: %w", item.label, err)
		}
	}
	// 归属地额外带国家段（user_version 7），多词国家名无法从 location 反推
	locStmt, err := e.statement(stmtLocation)
	if err != nil {
		return err
	}
	if _, err := locStmt.Exec(b.location, b.country, 1); err != nil {
		return fmt.Errorf("累加归属地排行失败: %w", err)
	}
	return nil
}

// dayOf 从 "yyyy-MM-dd HH:mm:ss.SSS" 取日期部分（与 Web 端统计的 day 口径一致）。
func dayOf(ts string) string {
	if len(ts) < 10 {
		return ""
	}
	return ts[:10]
}

func execStmt(e execer, key stmtKey, args ...any) error {
	stmt, err := e.statement(key)
	if err != nil {
		return err
	}
	if _, err := stmt.Exec(args...); err != nil {
		return fmt.Errorf("写入 SQLite 失败: %w", err)
	}
	return nil
}

// migrateStats 保证预聚合统计表与明细表一致。
//
// 需要从明细回溯的实质条件是「这组聚合表全空而明细表有数据」，按组分开判断：
//   - 总量组（stats_daily / stats_ip_daily，user_version 4 引入）；
//   - 排行组（stats_usernames / stats_passwords / stats_locations，user_version 5 引入）。
//
// 分组判断让 user_version 4 的旧库升级时只回溯新增的排行表，不重复扫明细重建总量；
// 聚合表被误删或手工清空也能自愈。全新空库（明细也为空）不做任何事。
// 回溯在单事务内完成，崩溃不会留下半成品；user_version 由 init 在迁移成功后写入。
//
// 返回值 rebuilt 表示排行表是否被重建（调用方据此判断是否需要回填 country）。
func (s *Store) migrateStats() (rebuilt bool, err error) {
	groups := []struct {
		label    string
		tables   []string
		rankings bool // 排行组：重建后需要回填 country
		rebuild  func() error
	}{
		{"总量统计", []string{"stats_daily", "stats_ip_daily"}, false, s.rebuildStats},
		{"排行统计", []string{"stats_usernames", "stats_passwords", "stats_locations"}, true, s.rebuildRankings},
	}
	for _, g := range groups {
		need, err := s.statsMissing(g.tables)
		if err != nil {
			return false, err
		}
		if !need {
			continue
		}
		infof(s.logger, "预聚合"+g.label+"表需要从明细回溯重建（首次升级或聚合表被清空时发生），请稍候...")
		start := time.Now()
		if err := g.rebuild(); err != nil {
			return false, err
		}
		infof(s.logger, fmt.Sprintf("预聚合%s表已从明细回溯重建，耗时 %s", g.label, time.Since(start).Round(time.Millisecond)))
		if g.rankings {
			rebuilt = true
		}
	}
	return rebuilt, nil
}

// statsMissing 这组聚合表全空但明细表有数据时返回 true（需要从明细回溯）。
func (s *Store) statsMissing(tables []string) (bool, error) {
	empty, err := s.statsEmpty(tables)
	if err != nil || !empty {
		return false, err
	}
	return s.hasAnyEvent()
}

// statsEmpty 给定的一组表是否完全没有数据（EXISTS 短路，不扫全表）。
func (s *Store) statsEmpty(tables []string) (bool, error) {
	for _, table := range tables {
		var exists int
		if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM ` + table + `)`).Scan(&exists); err != nil {
			return false, fmt.Errorf("检查聚合表 %s 失败: %w", table, err)
		}
		if exists == 1 {
			return false, nil
		}
	}
	return true, nil
}

// hasAnyEvent 明细表是否有任意一条记录（EXISTS 短路，不扫全表）。
func (s *Store) hasAnyEvent() (bool, error) {
	for _, table := range locationTables {
		var exists int
		if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM ` + table + `)`).Scan(&exists); err != nil {
			return false, fmt.Errorf("检查明细表 %s 失败: %w", table, err)
		}
		if exists == 1 {
			return true, nil
		}
	}
	return false, nil
}

// rebuildStats 清空并用明细表重建总量聚合表（单事务，崩溃不会留下半成品）。
// 版本号由 init 在迁移成功后写入，这里不涉及 user_version。
func (s *Store) rebuildStats() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("开启统计重建事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已提交时为 ErrTxDone，可忽略

	now := time.Now().UnixMilli()
	for _, stmt := range []string{`DELETE FROM stats_daily`, `DELETE FROM stats_ip_daily`} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("清空聚合统计失败: %w", err)
		}
	}
	if _, err := tx.Exec(sqlBackfillDaily, now); err != nil {
		return fmt.Errorf("重建按天统计失败: %w", err)
	}
	if _, err := tx.Exec(sqlBackfillIPDaily, now); err != nil {
		return fmt.Errorf("重建按 IP 统计失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交统计重建事务失败: %w", err)
	}
	return nil
}

// rebuildRankings 清空并用 auth_attempts 重建用户名 / 口令 / 归属地排行
// （单事务，崩溃不会留下半成品）。
func (s *Store) rebuildRankings() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("开启排行重建事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已提交时为 ErrTxDone，可忽略

	for _, stmt := range []string{
		`DELETE FROM stats_usernames`,
		`DELETE FROM stats_passwords`,
		`DELETE FROM stats_locations`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("清空排行统计失败: %w", err)
		}
	}
	for _, stmt := range []string{sqlBackfillUsernames, sqlBackfillPasswords, sqlBackfillLocations} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("重建排行统计失败: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交排行重建事务失败: %w", err)
	}
	return nil
}

// Close 关闭数据库：先做 WAL checkpoint 收敛日志，再释放连接。
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	for _, stmt := range s.stmts {
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

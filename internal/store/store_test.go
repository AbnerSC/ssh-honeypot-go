package store

import (
	"path/filepath"
	"testing"
)

// openTemp 在临时目录打开一个测试库。
func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "database.db"), nil)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSchemaTablesAndVersion(t *testing.T) {
	s := openTemp(t)

	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("查询表列表失败: %v", err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("扫描表名失败: %v", err)
		}
		got[name] = true
	}
	// store 负责 6 张攻击事件表；sys_users / sys_audit_log 由 web 包建表
	for _, want := range []string{"sessions", "auth_attempts", "commands", "downloads", "ip_locks"} {
		if !got[want] {
			t.Errorf("缺少表 %s，实际表: %v", want, got)
		}
	}

	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("读取 user_version 失败: %v", err)
	}
	if version != schemaVersion {
		t.Errorf("user_version = %d, want %d", version, schemaVersion)
	}

	// WAL 模式必须生效（Web 只读连接与写入并发的前提）
	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("读取 journal_mode 失败: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestIndexes(t *testing.T) {
	s := openTemp(t)

	want := []string{
		"idx_sessions_src_ip", "idx_sessions_opened", "idx_sessions_protocol",
		"idx_auth_src_ip", "idx_auth_username", "idx_auth_ts", "idx_auth_password", "idx_auth_location",
		"idx_commands_session", "idx_commands_src_ip", "idx_commands_ts",
		"idx_downloads_src_ip", "idx_downloads_ts",
		"idx_ip_locks_src_ip", "idx_ip_locks_ts",
	}
	got := map[string]bool{}
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'`)
	if err != nil {
		t.Fatalf("查询索引失败: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("扫描索引名失败: %v", err)
		}
		got[name] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("缺少索引 %s", name)
		}
	}
}

func TestRecordAllEvents(t *testing.T) {
	s := openTemp(t)
	const ts = "2026-10-25 12:00:00.123"
	const epoch = int64(1761364800123)

	if err := s.RecordSessionOpen(ts, epoch, "s1-abc", "ssh", "203.0.113.7", 51234, "中国 广东省 深圳市"); err != nil {
		t.Fatalf("RecordSessionOpen: %v", err)
	}
	if err := s.RecordAuthAttempt(ts, epoch, "s1-abc", "ssh", "203.0.113.7", "root", "123456", true, "中国 广东省 深圳市"); err != nil {
		t.Fatalf("RecordAuthAttempt: %v", err)
	}
	if err := s.RecordCommand(ts, epoch, "s1-abc", "203.0.113.7", "root", "uname -a", "中国 广东省 深圳市"); err != nil {
		t.Fatalf("RecordCommand: %v", err)
	}
	if err := s.RecordDownload(ts, epoch, "s1-abc", "203.0.113.7", "root", "http://evil/x.sh", "中国 广东省 深圳市"); err != nil {
		t.Fatalf("RecordDownload: %v", err)
	}
	if err := s.RecordIPLocked(ts, epoch, "203.0.113.7", "2026-10-25 13:00:00.000", "中国 广东省 深圳市"); err != nil {
		t.Fatalf("RecordIPLocked: %v", err)
	}
	if err := s.RecordSessionClose("2026-10-25 12:00:05.000", "s1-abc", 4877); err != nil {
		t.Fatalf("RecordSessionClose: %v", err)
	}

	var protocol, location, closedAt string
	var duration int64
	if err := s.db.QueryRow(
		`SELECT protocol, location, closed_at, duration_ms FROM sessions WHERE session_id = ?`, "s1-abc",
	).Scan(&protocol, &location, &closedAt, &duration); err != nil {
		t.Fatalf("查询 sessions 失败: %v", err)
	}
	if protocol != "ssh" || location != "中国 广东省 深圳市" {
		t.Errorf("sessions 字段不符: protocol=%q location=%q", protocol, location)
	}
	if closedAt != "2026-10-25 12:00:05.000" || duration != 4877 {
		t.Errorf("会话关闭字段不符: closed_at=%q duration=%d", closedAt, duration)
	}

	var username, password string
	var success int
	if err := s.db.QueryRow(
		`SELECT username, password, success FROM auth_attempts WHERE session_id = ?`, "s1-abc",
	).Scan(&username, &password, &success); err != nil {
		t.Fatalf("查询 auth_attempts 失败: %v", err)
	}
	if username != "root" || password != "123456" || success != 1 {
		t.Errorf("auth_attempts 字段不符: %q %q %d", username, password, success)
	}

	var cmdline string
	if err := s.db.QueryRow(`SELECT command FROM commands WHERE src_ip = ?`, "203.0.113.7").Scan(&cmdline); err != nil {
		t.Fatalf("查询 commands 失败: %v", err)
	}
	if cmdline != "uname -a" {
		t.Errorf("commands 字段不符: %q", cmdline)
	}

	var url, until string
	if err := s.db.QueryRow(`SELECT url FROM downloads WHERE src_ip = ?`, "203.0.113.7").Scan(&url); err != nil {
		t.Fatalf("查询 downloads 失败: %v", err)
	}
	if url != "http://evil/x.sh" {
		t.Errorf("downloads.url = %q", url)
	}
	if err := s.db.QueryRow(`SELECT locked_until FROM ip_locks WHERE src_ip = ?`, "203.0.113.7").Scan(&until); err != nil {
		t.Fatalf("查询 ip_locks 失败: %v", err)
	}
	if until != "2026-10-25 13:00:00.000" {
		t.Errorf("ip_locks.locked_until = %q", until)
	}
}

// TestEmptyLocationWritesNull 空归属地必须写 NULL（Web 统计按 NULL 归入「未知」）。
func TestEmptyLocationWritesNull(t *testing.T) {
	s := openTemp(t)
	if err := s.RecordAuthAttempt("2026-10-25 12:00:00.000", 1, "s1", "ssh", "10.0.0.1", "root", "x", false, ""); err != nil {
		t.Fatalf("RecordAuthAttempt: %v", err)
	}
	var isNull int
	if err := s.db.QueryRow(`SELECT location IS NULL FROM auth_attempts`).Scan(&isNull); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if isNull != 1 {
		t.Error("空 location 应写入 NULL")
	}
}

// TestOpenIdempotent 重复打开同一文件不应破坏结构或丢失数据。
func TestOpenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.db")

	first, err := Open(path, nil)
	if err != nil {
		t.Fatalf("首次打开失败: %v", err)
	}
	if err := first.RecordCommand("2026-10-25 12:00:00.000", 1, "s1", "1.2.3.4", "root", "id", ""); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	second, err := Open(path, nil)
	if err != nil {
		t.Fatalf("再次打开失败: %v", err)
	}
	defer second.Close()

	var count int
	if err := second.db.QueryRow(`SELECT COUNT(*) FROM commands`).Scan(&count); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if count != 1 {
		t.Errorf("重开后数据丢失: count=%d", count)
	}
}

// TestMigrateLegacyV1 旧版（无 location 列、user_version=0）数据库应自动补列。
func TestMigrateLegacyV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	legacy, err := Open(path, nil)
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	// 模拟 Java 1.0 的旧结构与旧版本号
	for _, stmt := range []string{
		`PRAGMA user_version=0`,
		`DROP TABLE IF EXISTS auth_attempts`,
		`CREATE TABLE auth_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ts_epoch_ms INTEGER NOT NULL,
			session_id TEXT, protocol TEXT, src_ip TEXT NOT NULL, username TEXT NOT NULL,
			password TEXT NOT NULL, success INTEGER NOT NULL)`,
	} {
		if _, err := legacy.db.Exec(stmt); err != nil {
			t.Fatalf("构造旧库失败（%s）: %v", stmt, err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	migrated, err := Open(path, nil)
	if err != nil {
		t.Fatalf("迁移打开失败: %v", err)
	}
	defer migrated.Close()

	var version int
	if err := migrated.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("读取版本失败: %v", err)
	}
	if version != schemaVersion {
		t.Errorf("迁移后 user_version = %d, want %d", version, schemaVersion)
	}
	// location 列必须已补上且可写入
	if err := migrated.RecordAuthAttempt("2026-10-25 12:00:00.000", 1, "s1", "ssh", "1.2.3.4", "root", "x", false, "中国 北京"); err != nil {
		t.Fatalf("迁移后写入失败: %v", err)
	}
	var location string
	if err := migrated.db.QueryRow(`SELECT location FROM auth_attempts`).Scan(&location); err != nil {
		t.Fatalf("查询迁移列失败: %v", err)
	}
	if location != "中国 北京" {
		t.Errorf("location = %q", location)
	}
}

// TestCloseOrphanSessionsOnOpen 进程重启后必须补齐残留的未关闭会话，
// 否则 Web 端「在线会话」会永久显示在线。
func TestCloseOrphanSessionsOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.db")

	first, err := Open(path, nil)
	if err != nil {
		t.Fatalf("首次打开失败: %v", err)
	}
	// 模拟崩溃：只写 session_open，不写 session_close
	if err := first.RecordSessionOpen("2026-10-25 12:00:00.000", 1761364800000, "s1-crash", "ssh", "1.2.3.4", 51234, ""); err != nil {
		t.Fatalf("写入会话失败: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	second, err := Open(path, nil)
	if err != nil {
		t.Fatalf("再次打开失败: %v", err)
	}
	defer second.Close()

	var open int
	if err := second.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE closed_at IS NULL`).Scan(&open); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if open != 0 {
		t.Fatalf("重启后仍存在 %d 个未关闭会话", open)
	}
	var closedAt string
	var duration int64
	if err := second.db.QueryRow(`SELECT closed_at, duration_ms FROM sessions WHERE session_id = ?`, "s1-crash").
		Scan(&closedAt, &duration); err != nil {
		t.Fatalf("查询会话失败: %v", err)
	}
	if closedAt == "" || duration < 0 {
		t.Fatalf("关闭字段未补齐: closed_at=%q duration=%d", closedAt, duration)
	}
}

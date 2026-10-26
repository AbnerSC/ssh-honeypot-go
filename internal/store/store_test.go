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
		"idx_auth_src_ip", "idx_auth_username", "idx_auth_ts",
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
	// 退役索引（user_version 6）不得再建：口令 / 归属地排行已由聚合表承担
	for _, name := range []string{"idx_auth_password", "idx_auth_location"} {
		if got[name] {
			t.Errorf("退役索引 %s 不应存在", name)
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

// TestStatsAggregation 每条事件必须同步累加到按天与按 IP 预聚合表。
func TestStatsAggregation(t *testing.T) {
	s := openTemp(t)
	const ts = "2026-10-25 12:00:00.123"
	const epoch = int64(1761364800123)
	const ip = "203.0.113.7"

	steps := []struct {
		name string
		fn   func() error
	}{
		{"RecordSessionOpen", func() error {
			return s.RecordSessionOpen(ts, epoch, "s1-abc", "ssh", ip, 51234, "美国 加利福尼亚州")
		}},
		{"RecordAuthAttempt 1", func() error {
			return s.RecordAuthAttempt(ts, epoch, "s1-abc", "ssh", ip, "root", "123456", false, "美国 加利福尼亚州")
		}},
		{"RecordAuthAttempt 2", func() error {
			return s.RecordAuthAttempt(ts, epoch, "s1-abc", "ssh", "198.51.100.9", "admin", "admin", false, "")
		}},
		{"RecordCommand", func() error {
			return s.RecordCommand(ts, epoch, "s1-abc", ip, "root", "uname -a", "美国 加利福尼亚州")
		}},
		{"RecordDownload", func() error {
			return s.RecordDownload(ts, epoch, "s1-abc", ip, "root", "http://evil/x.sh", "")
		}},
		{"RecordIPLocked", func() error {
			return s.RecordIPLocked(ts, epoch, ip, "2026-10-25 13:00:00.000", "")
		}},
	}
	for _, step := range steps {
		if err := step.fn(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
	}

	var sessions, auth, commands, downloads, locks int64
	if err := s.db.QueryRow(`SELECT sessions, auth_attempts, commands, downloads, ip_locks
		FROM stats_daily WHERE day = ?`, "2026-10-25").
		Scan(&sessions, &auth, &commands, &downloads, &locks); err != nil {
		t.Fatalf("查询按天统计失败: %v", err)
	}
	if sessions != 1 || auth != 2 || commands != 1 || downloads != 1 || locks != 1 {
		t.Errorf("按天统计不符: sessions=%d auth=%d commands=%d downloads=%d locks=%d",
			sessions, auth, commands, downloads, locks)
	}

	var ipAuth, ipCommands int64
	if err := s.db.QueryRow(`SELECT auth_attempts, commands FROM stats_ip_daily
		WHERE day = ? AND src_ip = ?`, "2026-10-25", ip).Scan(&ipAuth, &ipCommands); err != nil {
		t.Fatalf("查询按 IP 统计失败: %v", err)
	}
	if ipAuth != 1 || ipCommands != 1 {
		t.Errorf("按 IP 统计不符: auth=%d commands=%d", ipAuth, ipCommands)
	}

	// 会话结束不影响统计（只更新明细）
	if err := s.RecordSessionClose("2026-10-25 12:00:05.000", "s1-abc", 4877); err != nil {
		t.Fatalf("RecordSessionClose: %v", err)
	}
	if err := s.db.QueryRow(`SELECT sessions FROM stats_daily WHERE day = ?`, "2026-10-25").Scan(&sessions); err != nil {
		t.Fatalf("查询按天统计失败: %v", err)
	}
	if sessions != 1 {
		t.Errorf("会话结束后统计被重复累加: sessions=%d", sessions)
	}
}

// TestStatsBackfillFromDetail 旧库（明细有数据、聚合表为空）首次打开必须回溯重建。
func TestStatsBackfillFromDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	first, err := Open(path, nil)
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	// 模拟旧库：直接写明细表，不经过 RecordXxx（不累加聚合），版本号也退回 3
	for _, stmt := range []string{
		`DELETE FROM stats_daily`,
		`DELETE FROM stats_ip_daily`,
		`PRAGMA user_version=3`,
		`INSERT INTO sessions(session_id, protocol, src_ip, src_port, opened_at, opened_epoch_ms, location)
		 VALUES('s-java-1','ssh','198.51.100.9',1234,'2026-10-24 01:02:03.000',1761267723000,'美国')`,
		`INSERT INTO auth_attempts(ts, ts_epoch_ms, src_ip, username, password, success, location)
		 VALUES('2026-10-24 01:02:04.000',1761267724000,'198.51.100.9','root','x',0,'美国')`,
		`INSERT INTO commands(ts, ts_epoch_ms, src_ip, username, command, location)
		 VALUES('2026-10-24 01:02:05.000',1761267725000,'198.51.100.9','root','id','美国')`,
	} {
		if _, err := first.db.Exec(stmt); err != nil {
			t.Fatalf("构造旧数据失败（%s）: %v", stmt, err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	second, err := Open(path, nil)
	if err != nil {
		t.Fatalf("重开失败: %v", err)
	}
	defer second.Close()

	var sessions, auth, commands int64
	if err := second.db.QueryRow(`SELECT sessions, auth_attempts, commands FROM stats_daily WHERE day = ?`,
		"2026-10-24").Scan(&sessions, &auth, &commands); err != nil {
		t.Fatalf("查询回溯结果失败: %v", err)
	}
	if sessions != 1 || auth != 1 || commands != 1 {
		t.Errorf("回溯统计不符: sessions=%d auth=%d commands=%d", sessions, auth, commands)
	}

	var ipSessions int64
	var location string
	if err := second.db.QueryRow(`SELECT sessions, location FROM stats_ip_daily WHERE day = ? AND src_ip = ?`,
		"2026-10-24", "198.51.100.9").Scan(&ipSessions, &location); err != nil {
		t.Fatalf("查询按 IP 回溯结果失败: %v", err)
	}
	if ipSessions != 1 || location != "美国" {
		t.Errorf("按 IP 回溯不符: sessions=%d location=%q", ipSessions, location)
	}

	// 迁移完成后版本号必须已提升，避免每次重启都重扫明细
	var version int
	if err := second.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("读取版本失败: %v", err)
	}
	if version != schemaVersion {
		t.Errorf("迁移后 user_version = %d, want %d", version, schemaVersion)
	}
}

// TestRankingAggregation 登录尝试必须同步累加到用户名 / 口令 / 归属地排行表。
func TestRankingAggregation(t *testing.T) {
	s := openTemp(t)
	const ts = "2026-10-25 12:00:00.123"
	const epoch = int64(1761364800123)

	for i := 0; i < 3; i++ {
		if err := s.RecordAuthAttempt(ts, epoch, "s1", "ssh", "203.0.113.7", "root", "123456", false, "美国 加利福尼亚州"); err != nil {
			t.Fatalf("RecordAuthAttempt: %v", err)
		}
	}
	// 空归属地单独成键（Web 端归入「未知」），不能与其它地区混在一起
	if err := s.RecordAuthAttempt(ts, epoch, "s1", "ssh", "198.51.100.9", "admin", "admin", false, ""); err != nil {
		t.Fatalf("RecordAuthAttempt: %v", err)
	}
	// 非登录事件不写入排行
	if err := s.RecordCommand(ts, epoch, "s1", "203.0.113.7", "root", "id", "美国 加利福尼亚州"); err != nil {
		t.Fatalf("RecordCommand: %v", err)
	}

	cases := []struct {
		query string
		want  int64
		name  string
	}{
		{`SELECT auth_attempts FROM stats_usernames WHERE username = 'root'`, 3, "用户名 root"},
		{`SELECT auth_attempts FROM stats_usernames WHERE username = 'admin'`, 1, "用户名 admin"},
		{`SELECT auth_attempts FROM stats_passwords WHERE password = '123456'`, 3, "口令 123456"},
		{`SELECT auth_attempts FROM stats_locations WHERE location = '美国 加利福尼亚州'`, 3, "归属地"},
		{`SELECT auth_attempts FROM stats_locations WHERE location = ''`, 1, "未知归属地"},
	}
	for _, c := range cases {
		var got int64
		if err := s.db.QueryRow(c.query).Scan(&got); err != nil {
			t.Fatalf("查询%s排行失败: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestRankingBackfillFromDetail user_version 4 的旧库（排行表为空、明细有数据）必须回溯重建。
func TestRankingBackfillFromDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	first, err := Open(path, nil)
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	// 模拟旧库：明细由旧版直接写入，排行表为空，版本号退回 4
	for _, stmt := range []string{
		`DELETE FROM stats_usernames`,
		`DELETE FROM stats_passwords`,
		`DELETE FROM stats_locations`,
		`PRAGMA user_version=4`,
		`INSERT INTO auth_attempts(ts, ts_epoch_ms, src_ip, username, password, success, location)
		 VALUES('2026-10-24 01:02:04.000',1761267724000,'198.51.100.9','root','x',0,'美国')`,
		`INSERT INTO auth_attempts(ts, ts_epoch_ms, src_ip, username, password, success, location)
		 VALUES('2026-10-24 01:02:05.000',1761267725000,'198.51.100.9','root','y',0,NULL)`,
	} {
		if _, err := first.db.Exec(stmt); err != nil {
			t.Fatalf("构造旧数据失败（%s）: %v", stmt, err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	second, err := Open(path, nil)
	if err != nil {
		t.Fatalf("重开失败: %v", err)
	}
	defer second.Close()

	cases := []struct {
		query string
		want  int64
		name  string
	}{
		{`SELECT auth_attempts FROM stats_usernames WHERE username = 'root'`, 2, "用户名 root"},
		{`SELECT auth_attempts FROM stats_passwords WHERE password = 'x'`, 1, "口令 x"},
		{`SELECT auth_attempts FROM stats_locations WHERE location = '美国'`, 1, "归属地 美国"},
		{`SELECT auth_attempts FROM stats_locations WHERE location = ''`, 1, "未知归属地"},
	}
	for _, c := range cases {
		var got int64
		if err := second.db.QueryRow(c.query).Scan(&got); err != nil {
			t.Fatalf("查询%s回溯结果失败: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestTxBatchWrites 事务批量写入必须生效，且统计与明细在同一事务内可见。
func TestTxBatchWrites(t *testing.T) {
	s := openTemp(t)
	const ts = "2026-10-25 12:00:00.123"

	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := tx.RecordAuthAttempt(ts, 1761364800123, "s1", "ssh", "203.0.113.7", "root", "x", false, "美国"); err != nil {
			t.Fatalf("事务内写入失败: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var detail, aggregated int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_attempts`).Scan(&detail); err != nil {
		t.Fatalf("统计明细失败: %v", err)
	}
	if err := s.db.QueryRow(`SELECT auth_attempts FROM stats_daily WHERE day = ?`, "2026-10-25").Scan(&aggregated); err != nil {
		t.Fatalf("统计聚合失败: %v", err)
	}
	if detail != 3 || aggregated != 3 {
		t.Errorf("批量写入不符: detail=%d aggregated=%d", detail, aggregated)
	}
}

// TestRetiredIndexesDroppedFromLegacyDB 旧库（user_version=5）上的退役索引
// 必须在启动迁移时被删除，且明细数据不受影响。
func TestRetiredIndexesDroppedFromLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.db")

	first, err := Open(path, nil)
	if err != nil {
		t.Fatalf("首次打开失败: %v", err)
	}
	// 模拟 v5 库：退役索引仍在、版本号退回 5
	for _, stmt := range []string{
		`CREATE INDEX idx_auth_password ON auth_attempts(password)`,
		`CREATE INDEX idx_auth_location ON auth_attempts(location)`,
		`PRAGMA user_version=5`,
		`INSERT INTO auth_attempts(ts, ts_epoch_ms, src_ip, username, password, success, location)
		 VALUES('2026-10-25 12:00:00.000',1761364800000,'203.0.113.7','root','123456',0,'中国 北京')`,
	} {
		if _, err := first.db.Exec(stmt); err != nil {
			t.Fatalf("构造旧库失败（%s）: %v", stmt, err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	second, err := Open(path, nil)
	if err != nil {
		t.Fatalf("迁移打开失败: %v", err)
	}
	defer second.Close()

	for _, name := range []string{"idx_auth_password", "idx_auth_location"} {
		var n int
		if err := second.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name = ?`, name).
			Scan(&n); err != nil {
			t.Fatalf("查询索引 %s 失败: %v", name, err)
		}
		if n != 0 {
			t.Errorf("迁移后退役索引 %s 仍存在", name)
		}
	}

	var version, rows int
	if err := second.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("读取版本失败: %v", err)
	}
	if version != schemaVersion {
		t.Errorf("迁移后 user_version = %d, want %d", version, schemaVersion)
	}
	if err := second.db.QueryRow(`SELECT COUNT(*) FROM auth_attempts`).Scan(&rows); err != nil {
		t.Fatalf("统计明细失败: %v", err)
	}
	if rows != 1 {
		t.Errorf("迁移后明细行数 = %d, want 1", rows)
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

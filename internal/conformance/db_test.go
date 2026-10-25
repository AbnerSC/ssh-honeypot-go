package conformance

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

const (
	ddlSessions = `CREATE TABLE sessions (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL UNIQUE,
		src_ip     TEXT NOT NULL,
		opened_at  TEXT NOT NULL
	)`
	ddlAuth = `CREATE TABLE auth_attempts (
		id     INTEGER PRIMARY KEY AUTOINCREMENT,
		ts     TEXT NOT NULL,
		src_ip TEXT NOT NULL
	)`
	idxAuthSrcIP = `CREATE INDEX idx_auth_src_ip ON auth_attempts(src_ip)`
)

// newDB 建一个临时 SQLite 库，执行给定 DDL 并写入 user_version，返回文件路径。
func newDB(t *testing.T, version int, ddl ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "database.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("打开临时库失败: %v", err)
	}
	defer db.Close()
	for _, s := range ddl {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("执行 DDL 失败: %v\n%s", err, s)
		}
	}
	if _, err := db.Exec("PRAGMA user_version=" + strconv.Itoa(version)); err != nil {
		t.Fatalf("写入 user_version 失败: %v", err)
	}
	return path
}

func mustLoad(t *testing.T, path string) *Schema {
	t.Helper()
	s, err := LoadSchema(path)
	if err != nil {
		t.Fatalf("读取结构失败: %v", err)
	}
	return s
}

func TestDiffIdenticalSchema(t *testing.T) {
	javaPath := newDB(t, 3, ddlSessions, ddlAuth, idxAuthSrcIP)
	goPath := newDB(t, 3, ddlSessions, ddlAuth, idxAuthSrcIP)

	java, goSchema := mustLoad(t, javaPath), mustLoad(t, goPath)
	if diffs := Diff(java, goSchema); len(diffs) != 0 {
		t.Fatalf("结构相同的两份库不应产生差异，实际: %v", diffs)
	}
	if java.UserVersion != 3 || goSchema.UserVersion != 3 {
		t.Fatalf("user_version 读取错误: java=%d go=%d", java.UserVersion, goSchema.UserVersion)
	}
	if len(java.Tables) != 2 {
		t.Fatalf("应读到 2 张业务表，实际 %d: %v", len(java.Tables), java.Tables)
	}
	// sqlite_sequence 属于内部表，必须被跳过
	if _, ok := java.Tables["sqlite_sequence"]; ok {
		t.Fatal("sqlite_sequence 不应出现在业务表清单中")
	}
}

func TestDiffDetectsColumnChanges(t *testing.T) {
	javaPath := newDB(t, 3, ddlSessions)
	// Go 版多一列 location、opened_at 类型变为 INTEGER
	goPath := newDB(t, 3, `CREATE TABLE sessions (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL UNIQUE,
		src_ip     TEXT NOT NULL,
		opened_at  INTEGER NOT NULL,
		location   TEXT
	)`)

	diffs := Diff(mustLoad(t, javaPath), mustLoad(t, goPath))
	joined := strings.Join(diffs, "\n")
	for _, want := range []string{
		"列 location：仅 Go 版存在",
		"列 opened_at 类型不同：java=TEXT go=INTEGER",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少预期差异 %q，实际差异:\n%s", want, joined)
		}
	}
}

func TestDiffDetectsIndexAndTableChanges(t *testing.T) {
	javaPath := newDB(t, 3, ddlSessions, ddlAuth, idxAuthSrcIP)
	goPath := newDB(t, 3, ddlSessions, `CREATE TABLE auth_attempts (
		id     INTEGER PRIMARY KEY AUTOINCREMENT,
		ts     TEXT NOT NULL,
		src_ip TEXT NOT NULL
	)`, `CREATE INDEX idx_auth_src_ip ON auth_attempts(src_ip, ts)`)

	diffs := Diff(mustLoad(t, javaPath), mustLoad(t, goPath))
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "索引 idx_auth_src_ip 列不同：java=(src_ip) go=(src_ip, ts)") {
		t.Errorf("未检出索引列差异，实际:\n%s", joined)
	}

	// 仅 Java 版存在的表
	javaPath2 := newDB(t, 3, ddlSessions, ddlAuth)
	goPath2 := newDB(t, 3, ddlSessions)
	joined = strings.Join(Diff(mustLoad(t, javaPath2), mustLoad(t, goPath2)), "\n")
	if !strings.Contains(joined, "表 auth_attempts：仅 Java 版存在") {
		t.Errorf("未检出缺表，实际:\n%s", joined)
	}
}

// TestDiffAllowsGoVersionBump Go 版允许比 Java 版版本号更高（迁移由 Go 版自行完成）。
func TestDiffAllowsGoVersionBump(t *testing.T) {
	javaPath := newDB(t, 3, ddlSessions)
	goPath := newDB(t, 4, ddlSessions)

	if diffs := Diff(mustLoad(t, javaPath), mustLoad(t, goPath)); len(diffs) != 0 {
		t.Fatalf("Go 版版本号更高不应判为差异，实际: %v", diffs)
	}
}

// TestDiffDetectsVersionDowngrade Go 版版本号低于 Java 版说明无法接续。
func TestDiffDetectsVersionDowngrade(t *testing.T) {
	javaPath := newDB(t, 4, ddlSessions)
	goPath := newDB(t, 3, ddlSessions)

	diffs := Diff(mustLoad(t, javaPath), mustLoad(t, goPath))
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "user_version：java=4 go=3") {
		t.Fatalf("未检出降级，实际:\n%s", joined)
	}
}

func TestDiffIgnoresGoExtensionTables(t *testing.T) {
	javaPath := newDB(t, 3, ddlSessions, ddlAuth)
	// Go 版多建预聚合统计表与同名索引，不应判为结构差异（按扩展表跳过，版本号也允许更高）
	goPath := newDB(t, 4, ddlSessions, ddlAuth,
		`CREATE TABLE stats_daily (day TEXT PRIMARY KEY, sessions INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE stats_ip_daily (day TEXT NOT NULL, src_ip TEXT NOT NULL,
			auth_attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, src_ip))`,
		`CREATE INDEX idx_stats_ip_daily_ip ON stats_ip_daily(src_ip, auth_attempts)`)

	if diffs := Diff(mustLoad(t, javaPath), mustLoad(t, goPath)); len(diffs) != 0 {
		t.Fatalf("扩展表不应产生差异，实际: %v", diffs)
	}
}

func TestLoadSchemaMissingFile(t *testing.T) {
	if _, err := LoadSchema(filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Fatal("文件不存在时应报错（mode=ro 不建库）")
	}
}

func TestRowSummary(t *testing.T) {
	javaPath := newDB(t, 3, ddlSessions, ddlAuth)
	goPath := newDB(t, 3, ddlSessions)

	java, goSchema := mustLoad(t, javaPath), mustLoad(t, goPath)
	lines := RowSummary(java, goSchema)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "auth_attempts") || !strings.Contains(joined, "go=-") {
		t.Fatalf("行数摘要应包含仅 Java 存在的表并标记 go=-，实际:\n%s", joined)
	}
	if !strings.Contains(joined, "sessions") {
		t.Fatalf("行数摘要缺少 sessions，实际:\n%s", joined)
	}
}

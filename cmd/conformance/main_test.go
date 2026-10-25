package main

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// makeDB 建一个临时库：基线为 sessions 表 + user_version=3。
func makeDB(t *testing.T, extraDDL ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "database.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("打开临时库失败: %v", err)
	}
	defer db.Close()
	ddls := append([]string{`CREATE TABLE sessions (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL UNIQUE,
		src_ip     TEXT NOT NULL
	)`}, extraDDL...)
	for _, ddl := range ddls {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("执行 DDL 失败: %v\n%s", err, ddl)
		}
	}
	if _, err := db.Exec("PRAGMA user_version=3"); err != nil {
		t.Fatalf("写入 user_version 失败: %v", err)
	}
	return path
}

func TestRunUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 2 {
		t.Fatalf("无参数应返回 2，实际 %d", code)
	}
	if !strings.Contains(errOut.String(), "db-diff") {
		t.Fatalf("用法说明应包含子命令，实际:\n%s", errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("help 应返回 0，实际 %d", code)
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"nope"}, &out, &errOut); code != 2 {
		t.Fatalf("未知子命令应返回 2，实际 %d", code)
	}
}

func TestRunDBDiffIdentical(t *testing.T) {
	javaPath := makeDB(t, `CREATE INDEX idx_sessions_src_ip ON sessions(src_ip)`)
	goPath := makeDB(t, `CREATE INDEX idx_sessions_src_ip ON sessions(src_ip)`)

	var out, errOut bytes.Buffer
	code := run([]string{"db-diff", "-java", javaPath, "-go", goPath}, &out, &errOut)
	if code != 0 {
		t.Fatalf("结构一致应返回 0，实际 %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "结构一致") || !strings.Contains(out.String(), "user_version=3") {
		t.Fatalf("输出缺少结论或版本号:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "sessions") {
		t.Fatalf("输出缺少行数摘要:\n%s", out.String())
	}
}

func TestRunDBDiffDifferent(t *testing.T) {
	javaPath := makeDB(t)
	goPath := makeDB(t, `ALTER TABLE sessions ADD COLUMN location TEXT`)

	var out, errOut bytes.Buffer
	code := run([]string{"db-diff", "-java", javaPath, "-go", goPath}, &out, &errOut)
	if code != 1 {
		t.Fatalf("结构不一致应返回 1，实际 %d\nstdout:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "列 location：仅 Go 版存在") {
		t.Fatalf("输出未列出列差异:\n%s", out.String())
	}
}

func TestRunDBDiffMissingArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"db-diff", "-java", "x"}, &out, &errOut); code != 2 {
		t.Fatalf("缺参数应返回 2，实际 %d", code)
	}
	if code := run([]string{"db-diff", "-java", filepath.Join(t.TempDir(), "nope.db"), "-go", "x"}, &out, &errOut); code != 2 {
		t.Fatalf("库不存在应返回 2，实际 %d", code)
	}
}

// fakeConsole 任意路径都返回同构包络，登录后置 Cookie。
func fakeConsole() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "s1", Path: "/"})
		_, _ = w.Write([]byte(`{"ok":true,"user":{"id":1,"username":"admin"}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"data":{"total":1,"items":[]}}`))
	})
	return mux
}

func TestRunAPIDiff(t *testing.T) {
	javaSrv := httptest.NewServer(fakeConsole())
	defer javaSrv.Close()
	goSrv := httptest.NewServer(fakeConsole())
	defer goSrv.Close()

	var out, errOut bytes.Buffer
	code := run([]string{"api-diff", "-java", javaSrv.URL, "-go", goSrv.URL, "-pass", "admin123"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("契约一致应返回 0，实际 %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "接口契约一致") {
		t.Fatalf("输出缺少结论:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "跳过写接口 5 条") {
		t.Fatalf("输出应提示跳过的写接口:\n%s", out.String())
	}
	if strings.Contains(out.String(), "DIFF") {
		t.Fatalf("同构响应不应出现 DIFF:\n%s", out.String())
	}
}

func TestRunAPIDiffDifferences(t *testing.T) {
	javaSrv := httptest.NewServer(fakeConsole())
	defer javaSrv.Close()

	other := http.NewServeMux()
	other.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"user":{"id":1,"username":"admin"}}`))
	})
	other.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"data":{"total":"1"}}`))
	})
	goSrv := httptest.NewServer(other)
	defer goSrv.Close()

	var out, errOut bytes.Buffer
	code := run([]string{"api-diff", "-java", javaSrv.URL, "-go", goSrv.URL, "-pass", "admin123"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("存在差异应返回 1，实际 %d\nstdout:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "DIFF") || !strings.Contains(out.String(), "data.total") {
		t.Fatalf("输出未列出差异:\n%s", out.String())
	}
}

func TestRunAPIDiffLoginFailure(t *testing.T) {
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error":"用户名或密码错误"}`))
	})
	javaSrv := httptest.NewServer(fakeConsole())
	defer javaSrv.Close()
	goSrv := httptest.NewServer(bad)
	defer goSrv.Close()

	var out, errOut bytes.Buffer
	code := run([]string{"api-diff", "-java", javaSrv.URL, "-go", goSrv.URL, "-pass", "admin123"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("登录失败应返回 2，实际 %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "登录失败") {
		t.Fatalf("错误输出应说明登录失败:\n%s", errOut.String())
	}
}

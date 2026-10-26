package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/config"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/store"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/web"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// prepareDB 按生产顺序建好 12 张表：攻击日志表与预聚合表来自 store，系统用户/审计表来自 Web 控制台。
func prepareDB(t *testing.T, dbPath string) {
	t.Helper()
	logger := quietLogger()
	st, err := store.Open(dbPath, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志表失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关闭攻击日志存储失败: %v", err)
	}
	srv, err := web.New(web.Options{
		Addr:                  "127.0.0.1:0",
		DBPath:                dbPath,
		SessionTimeoutMinutes: 30,
		Logger:                logger,
	})
	if err != nil {
		t.Fatalf("初始化系统表失败: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("关闭 Web 服务失败: %v", err)
	}
}

func TestRunCheckDBSchemaOK(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "database.db")
	prepareDB(t, dbPath)

	cfg := config.Default()
	cfg.Log.DB = dbPath

	var out bytes.Buffer
	if code := runCheckDB(cfg, &out); code != 0 {
		t.Fatalf("自检应通过, 退出码=%d 输出:\n%s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{
		"schema OK (user_version=7)", "sessions", "stats_daily",
		"stats_usernames", "stats_passwords", "stats_locations",
		"sys_users", "sys_audit_log",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("输出缺少 %q:\n%s", want, text)
		}
	}
}

func TestRunCheckDBMissingFile(t *testing.T) {
	cfg := config.Default()
	cfg.Log.DB = filepath.Join(t.TempDir(), "not-exist.db")

	var out bytes.Buffer
	if code := runCheckDB(cfg, &out); code == 0 {
		t.Fatalf("数据库不存在时不应通过:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "数据库不可用") {
		t.Fatalf("输出不符合预期:\n%s", out.String())
	}
}

func TestRunCheckDBMissingTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("创建空数据库文件失败: %v", err)
	}

	cfg := config.Default()
	cfg.Log.DB = dbPath

	var out bytes.Buffer
	if code := runCheckDB(cfg, &out); code == 0 {
		t.Fatalf("缺表时不应通过:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "schema FAIL") || !strings.Contains(out.String(), "sessions") {
		t.Fatalf("输出不符合预期:\n%s", out.String())
	}
}

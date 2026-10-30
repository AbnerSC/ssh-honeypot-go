package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempConfig 在临时目录写入 YAML 内容并返回路径。
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写入临时配置失败: %v", err)
	}
	return path
}

// clearAIEnv 清空全部 AI_* 环境变量，避免宿主机环境影响用例。
func clearAIEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"AI_ENABLED", "AI_BASE_URL", "AI_API_KEY", "AI_MODEL_NAME", "AI_ENABLE_THINKING",
		"AI_TIMEOUT_SECONDS", "AI_MAX_OUTPUT_CHARS", "AI_MAX_CONCURRENT",
		"AI_FAILURE_THRESHOLD", "AI_COOLDOWN_SECONDS",
	} {
		t.Setenv(name, "")
	}
}

func TestDefaultMatchesJava(t *testing.T) {
	cfg := Default()

	if cfg.SSH != (Service{Enabled: true, Port: 2222}) {
		t.Errorf("ssh 默认值不符: %+v", cfg.SSH)
	}
	if cfg.Telnet != (Service{Enabled: true, Port: 2323}) {
		t.Errorf("telnet 默认值不符: %+v", cfg.Telnet)
	}
	if cfg.MySQL != (Service{Enabled: true, Port: 3306}) {
		t.Errorf("mysql 默认值不符: %+v", cfg.MySQL)
	}
	if cfg.PostgreSQL != (Service{Enabled: true, Port: 5432}) {
		t.Errorf("postgresql 默认值不符: %+v", cfg.PostgreSQL)
	}
	if cfg.Redis != (Service{Enabled: true, Port: 6379}) {
		t.Errorf("redis 默认值不符: %+v", cfg.Redis)
	}
	if cfg.Log.File != filepath.Join("logs", "honeypot.jsonl") {
		t.Errorf("log.file 默认值不符: %s", cfg.Log.File)
	}
	if cfg.Log.DB != filepath.Join("logs", "database.db") {
		t.Errorf("log.db 默认值不符: %s", cfg.Log.DB)
	}
	if cfg.Web.Enabled != true || cfg.Web.Port != 8080 || cfg.Web.SessionTimeoutMinutes != 30 {
		t.Errorf("web 默认值不符: %+v", cfg.Web)
	}
	if len(cfg.Web.TrustedProxies) != 0 {
		t.Errorf("默认不应信任任何转发代理: %v", cfg.Web.TrustedProxies)
	}
	if cfg.Auth.MaxFailures != 3 || cfg.Auth.WindowMinutes != 5 || cfg.Auth.LockMinutes != 30 {
		t.Errorf("auth 默认值不符: %+v", cfg.Auth)
	}
	if cfg.AI.Enabled || cfg.AI.TimeoutSeconds != 20 || cfg.AI.MaxOutputChars != 8192 ||
		cfg.AI.MaxConcurrent != 1 || cfg.AI.FailureThreshold != 3 || cfg.AI.CooldownSeconds != 300 {
		t.Errorf("ai 默认值不符: %+v", cfg.AI)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	clearAIEnv(t)
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"), nil)
	if err != nil {
		t.Fatalf("配置文件缺失不应报错: %v", err)
	}
	if cfg.SSH.Port != 2222 || cfg.Web.Port != 8080 {
		t.Errorf("缺失配置文件时应使用默认值: %+v", cfg)
	}
}

func TestLoadPartialKeepsDefaults(t *testing.T) {
	clearAIEnv(t)
	path := writeTempConfig(t, `
hostname: ubuntu
ssh:
  port: 2022
log:
  db: db/database.db
`)
	cfg, err := Load(path, nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if cfg.Hostname != "ubuntu" {
		t.Errorf("hostname = %q, want ubuntu", cfg.Hostname)
	}
	if cfg.SSH.Port != 2022 {
		t.Errorf("ssh.port = %d, want 2022", cfg.SSH.Port)
	}
	if !cfg.SSH.Enabled {
		t.Error("未配置 ssh.enabled 时应保留默认 true")
	}
	if cfg.Log.DB != "db/database.db" {
		t.Errorf("log.db = %q", cfg.Log.DB)
	}
	if cfg.Log.File != filepath.Join("logs", "honeypot.jsonl") {
		t.Errorf("未配置的 log.file 应保留默认值, got %q", cfg.Log.File)
	}
	if cfg.Telnet.Port != 2323 {
		t.Errorf("未出现的 telnet 段应保留默认值, got %+v", cfg.Telnet)
	}
}

func TestCredentialsBothForms(t *testing.T) {
	clearAIEnv(t)
	path := writeTempConfig(t, `
auth:
  credentials:
    root: "123456"
    admin: ["admin123", "admin"]
    numeric: 123456
`)
	cfg, err := Load(path, nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	got := cfg.Auth.Passwords()
	if len(got) != 3 {
		t.Fatalf("密码本条目数 = %d, want 3 (%v)", len(got), got)
	}
	if len(got["root"]) != 1 || got["root"][0] != "123456" {
		t.Errorf("单密码写法解析错误: %v", got["root"])
	}
	if len(got["admin"]) != 2 || got["admin"][0] != "admin123" || got["admin"][1] != "admin" {
		t.Errorf("列表写法解析错误: %v", got["admin"])
	}
	if len(got["numeric"]) != 1 || got["numeric"][0] != "123456" {
		t.Errorf("数字标量应转成字符串: %v", got["numeric"])
	}
}

func TestEmptyCredentialsFallsBackToBuiltin(t *testing.T) {
	clearAIEnv(t)
	path := writeTempConfig(t, `
auth:
  credentials: {}
`)
	cfg, err := Load(path, nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	got := cfg.Auth.Passwords()
	if len(got) != 5 || got["root"][0] != "123456" {
		t.Errorf("空密码本应回退内置弱口令, got %v", got)
	}
}

func TestAIEnvOverrides(t *testing.T) {
	clearAIEnv(t)
	t.Setenv("AI_ENABLED", "yes")
	t.Setenv("AI_BASE_URL", "http://127.0.0.1:8000")
	t.Setenv("AI_API_KEY", "secret")
	t.Setenv("AI_MODEL_NAME", "qwen3-2b")
	t.Setenv("AI_ENABLE_THINKING", "ON")
	t.Setenv("AI_TIMEOUT_SECONDS", "45")
	t.Setenv("AI_MAX_OUTPUT_CHARS", "4096")
	t.Setenv("AI_MAX_CONCURRENT", "4")
	t.Setenv("AI_FAILURE_THRESHOLD", "5")
	t.Setenv("AI_COOLDOWN_SECONDS", "60")

	cfg, err := Load(writeTempConfig(t, "ai:\n  enabled: false\n"), nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if !cfg.AI.Enabled || !cfg.AI.EnableThinking {
		t.Errorf("布尔覆盖失败: %+v", cfg.AI)
	}
	if cfg.AI.BaseURL != "http://127.0.0.1:8000" || cfg.AI.APIKey != "secret" || cfg.AI.ModelName != "qwen3-2b" {
		t.Errorf("字符串覆盖失败: %+v", cfg.AI)
	}
	if cfg.AI.TimeoutSeconds != 45 || cfg.AI.MaxOutputChars != 4096 || cfg.AI.MaxConcurrent != 4 ||
		cfg.AI.FailureThreshold != 5 || cfg.AI.CooldownSeconds != 60 {
		t.Errorf("整数覆盖失败: %+v", cfg.AI)
	}
}

func TestAIEnvInvalidValuesKeepConfig(t *testing.T) {
	clearAIEnv(t)
	t.Setenv("AI_ENABLED", "maybe")
	t.Setenv("AI_TIMEOUT_SECONDS", "abc")

	cfg, err := Load(writeTempConfig(t, "ai:\n  enabled: true\n  timeout_seconds: 33\n"), nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if !cfg.AI.Enabled {
		t.Error("非法布尔值应保留配置文件取值")
	}
	if cfg.AI.TimeoutSeconds != 33 {
		t.Errorf("非法整数应保留配置文件取值, got %d", cfg.AI.TimeoutSeconds)
	}
}

func TestEmptyAIEnvIgnored(t *testing.T) {
	clearAIEnv(t)
	t.Setenv("AI_MODEL_NAME", "   ")

	cfg, err := Load(writeTempConfig(t, "ai:\n  model_name: from-file\n"), nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if cfg.AI.ModelName != "from-file" {
		t.Errorf("空白环境变量不应覆盖配置文件, got %q", cfg.AI.ModelName)
	}
}

func TestResolveHostname(t *testing.T) {
	// 非容器环境（Windows / 本地开发）直接走配置值
	cfg := Default()
	if inContainer() {
		t.Skip("容器内主机名优先，跳过配置优先级断言")
	}
	if got := cfg.ResolveHostname(); got != DefaultHostname {
		t.Errorf("空 hostname 应回退 %q, got %q", DefaultHostname, got)
	}
	cfg.Hostname = "  web-prod-01  "
	if got := cfg.ResolveHostname(); got != "web-prod-01" {
		t.Errorf("应使用配置 hostname 并去除空白, got %q", got)
	}
}

func TestLooksLikeContainerID(t *testing.T) {
	cases := map[string]bool{
		"3f4a1b2c9d8e":                        true,
		"3f4a1b2c9d8e7f60a1b2c3d4e5f60718293": true,
		"ubuntu":                              false,
		"3f4a1b2c9d8":                         false, // 11 位
		"3f4a1b2c9d8g":                        false, // 含非十六进制
	}
	for name, want := range cases {
		if got := looksLikeContainerID(name); got != want {
			t.Errorf("looksLikeContainerID(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNormalizeAuth(t *testing.T) {
	clearAIEnv(t)
	cfg, err := Load(writeTempConfig(t, `
auth:
  maxFailures: 0
  windowMinutes: -1
  lockMinutes: 0
  credentials:
    root: "1"
`), nil)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if cfg.Auth.MaxFailures != 3 || cfg.Auth.WindowMinutes != 5 || cfg.Auth.LockMinutes != 30 {
		t.Errorf("非法认证参数应回退默认值, got %+v", cfg.Auth)
	}
}

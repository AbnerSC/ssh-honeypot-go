// Package config 加载蜜罐 YAML 配置。
//
// 语义与 Java 版 org.open.scdm.honeypot.config.HoneypotConfig 保持一致：
//   - 配置文件缺失时回退内置默认值（仅提示，不中断启动）
//   - 文件中未出现的键保留默认值（先构造默认结构体再反序列化）
//   - credentials 兼容「单密码字符串」与「密码列表」两种写法
//   - ai 段支持 AI_* 环境变量覆盖（存在且非空才生效）
//   - web.trustedProxies 支持 WEB_TRUSTED_PROXIES 环境变量覆盖（逗号分隔）
//   - 伪装主机名优先级：Docker 容器主机名 > 配置文件 hostname > 默认 svr01
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigFile 默认配置文件路径。
	DefaultConfigFile = "config.yaml"
	// DefaultHostname 未配置 Docker hostname 且配置文件未指定 hostname 时的兜底值。
	DefaultHostname = "svr01"
)

// Service 单个协议监听配置。
type Service struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// Log 日志与数据文件配置。
type Log struct {
	// File 攻击日志（JSONL）路径。
	File string `yaml:"file"`
	// DB SQLite 数据库文件，与 JSONL 双写同一份数据。
	DB string `yaml:"db"`
}

// Web 控制台配置。
type Web struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
	// SessionTimeoutMinutes 管理端登录会话滑动过期时间（分钟）。
	SessionTimeoutMinutes int `yaml:"sessionTimeoutMinutes"`
	// TrustedProxies 受信反向代理网段（CIDR 或裸 IP）列表。
	//
	// 仅在直连地址命中列表时才采信 X-Forwarded-For 等转发头；
	// 为空（默认）表示不信任任何转发头，来源 IP 恒为 TCP 对端地址。
	// 部署在 Nginx/HAProxy 之后时，必须显式填写代理地址，否则登录锁定
	// 与审计会把所有请求记为代理 IP（安全但失真）。
	TrustedProxies []string `yaml:"trustedProxies"`
}

// Service 将 Web 配置视为通用监听配置，便于与其余协议统一处理。
func (w Web) Service() Service {
	return Service{Enabled: w.Enabled, Port: w.Port}
}

// Credentials 密码本：用户名 -> 允许的密码列表。
// YAML 中既支持 `root: "123456"` 也支持 `root: ["123456", "toor"]`。
type Credentials map[string][]string

// UnmarshalYAML 兼容单值与列表两种写法，与 Java 版 setCredentials 行为一致。
func (c *Credentials) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("credentials 必须是「用户名: 密码」映射，实际为 %s", kindName(value.Kind))
	}
	out := make(Credentials, len(value.Content)/2)
	for i := 0; i+1 < len(value.Content); i += 2 {
		name := value.Content[i].Value
		node := value.Content[i+1]
		var pwds []string
		if node.Kind == yaml.SequenceNode {
			pwds = make([]string, 0, len(node.Content))
			for _, item := range node.Content {
				pwds = append(pwds, item.Value)
			}
		} else {
			pwds = []string{node.Value}
		}
		out[name] = pwds
	}
	*c = out
	return nil
}

func kindName(k yaml.Kind) string {
	switch k {
	case yaml.MappingNode:
		return "映射"
	case yaml.SequenceNode:
		return "列表"
	case yaml.ScalarNode:
		return "标量"
	case yaml.DocumentNode:
		return "文档"
	case yaml.AliasNode:
		return "别名"
	default:
		return "未知"
	}
}

// Auth 登录认证配置：密码本 + 源 IP 失败锁定策略。
type Auth struct {
	MaxFailures   int         `yaml:"maxFailures"`
	WindowMinutes int         `yaml:"windowMinutes"`
	LockMinutes   int         `yaml:"lockMinutes"`
	PasswordBook  Credentials `yaml:"credentials"`
}

// Passwords 返回生效的密码本：未配置或配置为空时使用内置常见弱口令。
func (a *Auth) Passwords() map[string][]string {
	if len(a.PasswordBook) == 0 {
		return defaultPasswords()
	}
	out := make(map[string][]string, len(a.PasswordBook))
	for user, pwds := range a.PasswordBook {
		out[user] = pwds
	}
	return out
}

// defaultPasswords 内置弱口令，与 Java 版 Auth.defaultCredentials 逐项一致。
func defaultPasswords() map[string][]string {
	return map[string][]string{
		"root":   {"123456"},
		"admin":  {"admin123"},
		"ubuntu": {"ubuntu"},
		"pi":     {"raspberry"},
		"test":   {"test123"},
	}
}

// AI 大模型命令仿真配置，字段名与 config.yaml 的 snake_case 键一一对应。
type AI struct {
	Enabled        bool   `yaml:"enabled"`
	BaseURL        string `yaml:"base_url"`
	APIKey         string `yaml:"api_key"`
	ModelName      string `yaml:"model_name"`
	EnableThinking bool   `yaml:"enable_thinking"`
	// TimeoutSeconds 单次请求超时（秒），超时立即降级本地兜底。
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// MaxOutputChars 单条输出最大字符数，超长截断。
	MaxOutputChars int `yaml:"max_output_chars"`
	// MaxConcurrent 全局并发请求上限，超出的命令立即降级不排队。
	MaxConcurrent int `yaml:"max_concurrent"`
	// FailureThreshold 连续失败达到该次数后触发熔断。
	FailureThreshold int `yaml:"failure_threshold"`
	// CooldownSeconds 熔断时长（秒）。
	CooldownSeconds int `yaml:"cooldown_seconds"`
}

// Config 蜜罐完整配置。
type Config struct {
	Hostname   string  `yaml:"hostname"`
	SSH        Service `yaml:"ssh"`
	Telnet     Service `yaml:"telnet"`
	MySQL      Service `yaml:"mysql"`
	PostgreSQL Service `yaml:"postgresql"`
	Redis      Service `yaml:"redis"`
	Log        Log     `yaml:"log"`
	Web        Web     `yaml:"web"`
	Auth       Auth    `yaml:"auth"`
	AI         AI      `yaml:"ai"`
}

// Default 返回与 Java 版完全一致的内置默认配置。
func Default() *Config {
	return &Config{
		Hostname:   "",
		SSH:        Service{Enabled: true, Port: 2222},
		Telnet:     Service{Enabled: true, Port: 2323},
		MySQL:      Service{Enabled: true, Port: 3306},
		PostgreSQL: Service{Enabled: true, Port: 5432},
		Redis:      Service{Enabled: true, Port: 6379},
		Log: Log{
			File: filepath.Join("logs", "honeypot.jsonl"),
			DB:   filepath.Join("logs", "database.db"),
		},
		Web: Web{Enabled: true, Port: 8080, SessionTimeoutMinutes: 30},
		Auth: Auth{
			MaxFailures:   3,
			WindowMinutes: 5,
			LockMinutes:   30,
			PasswordBook:  defaultPasswords(),
		},
		AI: AI{
			Enabled:          false,
			BaseURL:          "",
			APIKey:           "",
			ModelName:        "",
			EnableThinking:   false,
			TimeoutSeconds:   20,
			MaxOutputChars:   8192,
			MaxConcurrent:    1,
			FailureThreshold: 3,
			CooldownSeconds:  300,
		},
	}
}

// Load 从 path 加载配置并应用 AI_* 环境变量覆盖。
// 配置文件不存在时使用默认值；logger 为 nil 时静默（供 -health 等无日志场景）。
func Load(path string, logger *slog.Logger) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		infof(logger, "未找到配置文件 %s，使用默认配置。", absPath(path))
	case err != nil:
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	case len(data) == 0:
		// 空文件等价于「未配置任何键」，保持默认值
	default:
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
	}

	cfg.normalizeAuth()
	cfg.AI.applyEnvOverrides(logger)
	cfg.Web.applyEnvOverrides(logger)
	return cfg, nil
}

// normalizeAuth 对误配的认证参数做防御性兜底，避免锁定策略失效。
func (c *Config) normalizeAuth() {
	if c.Auth.MaxFailures <= 0 {
		c.Auth.MaxFailures = 3
	}
	if c.Auth.WindowMinutes <= 0 {
		c.Auth.WindowMinutes = 5
	}
	if c.Auth.LockMinutes <= 0 {
		c.Auth.LockMinutes = 30
	}
}

// ResolveHostname 解析生效的伪装主机名：
// Docker 容器主机名（docker run --hostname / compose hostname）> 配置值 > svr01。
// Docker 未显式配置 hostname 时容器主机名为随机容器 ID，该情况视为未配置并继续向下兜底。
func (c *Config) ResolveHostname() string {
	if inContainer() {
		if h, err := os.Hostname(); err == nil {
			h = strings.TrimSpace(h)
			if h != "" && !looksLikeContainerID(h) {
				return h
			}
		}
	}
	if h := strings.TrimSpace(c.Hostname); h != "" {
		return h
	}
	return DefaultHostname
}

// inContainer 判断是否运行在容器内（/.dockerenv / container 环境变量 / cgroup 特征）。
func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("container"))) {
	case "docker", "containerd", "podman":
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			return true
		}
	}
	return false
}

// looksLikeContainerID 容器 ID 为纯小写十六进制串（短 ID 12 位 / 长 ID 64 位）。
func looksLikeContainerID(name string) bool {
	if len(name) < 12 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// applyEnvOverrides 按 AI_* 环境变量覆盖配置，优先级：环境变量（非空）> config.yaml > 默认值。
// 变量名与 config.yaml ai 段键一一对应（大写 + AI_ 前缀）；api_key 的值不回显日志。
func (a *AI) applyEnvOverrides(logger *slog.Logger) {
	var applied []string
	if v := envValue("AI_ENABLED"); v != "" {
		a.Enabled = parseBool(logger, "AI_ENABLED", v, a.Enabled)
		applied = append(applied, "AI_ENABLED="+strconv.FormatBool(a.Enabled))
	}
	if v := envValue("AI_BASE_URL"); v != "" {
		a.BaseURL = v
		applied = append(applied, "AI_BASE_URL="+v)
	}
	if v := envValue("AI_API_KEY"); v != "" {
		a.APIKey = v
		applied = append(applied, "AI_API_KEY=***")
	}
	if v := envValue("AI_MODEL_NAME"); v != "" {
		a.ModelName = v
		applied = append(applied, "AI_MODEL_NAME="+v)
	}
	if v := envValue("AI_ENABLE_THINKING"); v != "" {
		a.EnableThinking = parseBool(logger, "AI_ENABLE_THINKING", v, a.EnableThinking)
		applied = append(applied, "AI_ENABLE_THINKING="+strconv.FormatBool(a.EnableThinking))
	}
	if v := envValue("AI_TIMEOUT_SECONDS"); v != "" {
		a.TimeoutSeconds = parseInt(logger, "AI_TIMEOUT_SECONDS", v, a.TimeoutSeconds)
		applied = append(applied, "AI_TIMEOUT_SECONDS="+strconv.Itoa(a.TimeoutSeconds))
	}
	if v := envValue("AI_MAX_OUTPUT_CHARS"); v != "" {
		a.MaxOutputChars = parseInt(logger, "AI_MAX_OUTPUT_CHARS", v, a.MaxOutputChars)
		applied = append(applied, "AI_MAX_OUTPUT_CHARS="+strconv.Itoa(a.MaxOutputChars))
	}
	if v := envValue("AI_MAX_CONCURRENT"); v != "" {
		a.MaxConcurrent = parseInt(logger, "AI_MAX_CONCURRENT", v, a.MaxConcurrent)
		applied = append(applied, "AI_MAX_CONCURRENT="+strconv.Itoa(a.MaxConcurrent))
	}
	if v := envValue("AI_FAILURE_THRESHOLD"); v != "" {
		a.FailureThreshold = parseInt(logger, "AI_FAILURE_THRESHOLD", v, a.FailureThreshold)
		applied = append(applied, "AI_FAILURE_THRESHOLD="+strconv.Itoa(a.FailureThreshold))
	}
	if v := envValue("AI_COOLDOWN_SECONDS"); v != "" {
		a.CooldownSeconds = parseInt(logger, "AI_COOLDOWN_SECONDS", v, a.CooldownSeconds)
		applied = append(applied, "AI_COOLDOWN_SECONDS="+strconv.Itoa(a.CooldownSeconds))
	}
	if len(applied) > 0 {
		infof(logger, "AI 配置已按环境变量覆盖: %s", strings.Join(applied, ", "))
	}
}

// applyEnvOverrides 按 WEB_TRUSTED_PROXIES 环境变量覆盖受信代理网段，
// 优先级：环境变量（非空）> config.yaml > 默认值。
// 值为逗号分隔的 CIDR 或裸 IP 列表（如 "172.19.0.1,172.18.0.0/16"），
// 便于 Docker/compose 部署免挂载配置文件；非法条目告警并忽略，全部非法时保留原配置。
func (w *Web) applyEnvOverrides(logger *slog.Logger) {
	v := envValue("WEB_TRUSTED_PROXIES")
	if v == "" {
		return
	}
	var parsed, rejected []string
	for _, part := range strings.Split(v, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			parsed = append(parsed, s)
			continue
		}
		if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
			parsed = append(parsed, ip.String())
			continue
		}
		rejected = append(rejected, s)
	}
	if len(rejected) > 0 {
		warnf(logger, "环境变量 WEB_TRUSTED_PROXIES 含非法网段条目已忽略: %s", strings.Join(rejected, ", "))
	}
	if len(parsed) == 0 {
		warnf(logger, "环境变量 WEB_TRUSTED_PROXIES=%s 无合法条目，保留配置文件取值。", v)
		return
	}
	w.TrustedProxies = parsed
	infof(logger, "Web 配置已按环境变量覆盖: WEB_TRUSTED_PROXIES=%s", strings.Join(parsed, ", "))
}

// envValue 取环境变量：未设置或空白视为未设置（避免 compose 传空值覆盖配置文件）。
func envValue(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

// parseBool 宽容布尔解析（true/false/1/0/yes/no/on/off，忽略大小写），非法值告警并保留原配置。
func parseBool(logger *slog.Logger, name, value string, fallback bool) bool {
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		warnf(logger, "环境变量 %s=%s 不是合法布尔值，已忽略。", name, value)
		return fallback
	}
}

// parseInt 整数解析，非法值告警并保留原配置。
func parseInt(logger *slog.Logger, name, value string, fallback int) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		warnf(logger, "环境变量 %s=%s 不是合法整数，已忽略。", name, value)
		return fallback
	}
	return n
}

func infof(logger *slog.Logger, format string, args ...any) {
	if logger != nil {
		logger.Info(fmt.Sprintf(format, args...))
	}
}

func warnf(logger *slog.Logger, format string, args ...any) {
	if logger != nil {
		logger.Warn(fmt.Sprintf(format, args...))
	}
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

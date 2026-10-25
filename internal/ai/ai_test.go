package ai

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testConfig 构造一份默认可用配置，mutate 用于按用例微调。
func testConfig(baseURL string, mutate func(*Config)) Config {
	cfg := Config{
		Enabled:          true,
		BaseURL:          baseURL,
		APIKey:           "",
		ModelName:        "qwen3-30b",
		EnableThinking:   false,
		TimeoutSeconds:   5,
		MaxOutputChars:   1024,
		MaxConcurrent:    1,
		FailureThreshold: 3,
		CooldownSeconds:  300,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func newTestClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	c := New(testConfig(ts.URL, nil), quietLogger())
	if c == nil {
		t.Fatal("客户端构造失败")
	}
	return c
}

// ============================ 构造与归一化 ============================

func TestNewRequiresConfig(t *testing.T) {
	logger := quietLogger()
	if New(Config{Enabled: false, BaseURL: "http://x", ModelName: "m"}, logger) != nil {
		t.Fatal("未启用时应返回 nil")
	}
	if New(Config{Enabled: true, ModelName: "m"}, logger) != nil {
		t.Fatal("缺少 base_url 时应返回 nil")
	}
	if New(Config{Enabled: true, BaseURL: "http://x"}, logger) != nil {
		t.Fatal("缺少 model_name 时应返回 nil")
	}

	cases := map[string]string{
		"http://example.com":     "http://example.com/v1/chat/completions",
		"http://example.com/":    "http://example.com/v1/chat/completions",
		"http://example.com/v1":  "http://example.com/v1/chat/completions",
		"http://example.com/v1/": "http://example.com/v1/chat/completions",
	}
	for base, want := range cases {
		c := New(Config{Enabled: true, BaseURL: base, ModelName: "m"}, logger)
		if c == nil {
			t.Fatalf("%q 应构造成功", base)
		}
		if got := c.Endpoint(); got != want {
			t.Fatalf("base_url=%q endpoint=%q, 期望 %q", base, got, want)
		}
		c.Close()
	}

	// 误配下限钳制：输出上限 >=256、超时 >=3s、并发 >=1
	c := New(Config{Enabled: true, BaseURL: "http://example.com", ModelName: "m",
		MaxOutputChars: 0, TimeoutSeconds: 0, MaxConcurrent: 0}, logger)
	if c == nil {
		t.Fatal("应构造成功")
	}
	if c.maxOutputChars != minMaxOutputChars {
		t.Fatalf("输出上限未钳制: %d", c.maxOutputChars)
	}
	if c.http.Timeout != time.Duration(minRequestTimeout)*time.Second {
		t.Fatalf("请求超时未钳制: %v", c.http.Timeout)
	}
	if cap(c.permits) < 1 {
		t.Fatalf("并发上限未钳制: %d", cap(c.permits))
	}
	c.Close()

	// nil 客户端全程安全降级
	var nilClient *Client
	if _, ok := nilClient.GenerateShellOutput("h", "u", "/", nil, "ls"); ok {
		t.Fatal("nil 客户端应降级")
	}
	nilClient.Close()
}

// ============================ 正常调用 ============================

func TestGenerateShellOutputSuccess(t *testing.T) {
	var (
		mu      sync.Mutex
		gotBody chatRequest
		gotAuth string
		gotCT   string
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		_ = json.Unmarshal(raw, &gotBody)
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// 思考段 + 代码围栏 + 控制字符：全部需被净化
		io.WriteString(w, `{"choices":[{"message":{"content":"<think>hmm</think>\u0060\u0060\u0060\nhello\tworld\u0001\n\u0060\u0060\u0060"}}]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts)
	defer c.Close()

	out, ok := c.GenerateShellOutput("svr01", "root", "/root", []string{"ls", "pwd"}, "./check.sh --all")
	if !ok {
		t.Fatal("正常响应应返回 ok=true")
	}
	if out != "hello\tworld" {
		t.Fatalf("净化结果异常: %q", out)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotCT != "application/json" {
		t.Fatalf("Content-Type=%q", gotCT)
	}
	if gotAuth != "" {
		t.Fatalf("api_key 为空时不应携带 Authorization: %q", gotAuth)
	}
	if gotBody.Model != "qwen3-30b" || gotBody.Temperature != 1 || gotBody.MaxTokens != maxTokens {
		t.Fatalf("请求参数不符: %+v", gotBody)
	}
	if v, exists := gotBody.ChatTemplateKwargs["enable_thinking"]; !exists || v != false {
		t.Fatalf("chat_template_kwargs 不符: %+v", gotBody.ChatTemplateKwargs)
	}
	if len(gotBody.Messages) != 2 {
		t.Fatalf("messages 数量不符: %d", len(gotBody.Messages))
	}
	sys := gotBody.Messages[0]
	if sys.Role != "system" ||
		!strings.Contains(sys.Content, "You are a real bash shell") ||
		!strings.Contains(sys.Content, "Host: svr01. Current user: root. Working directory: /root.") ||
		!strings.Contains(sys.Content, "Recently executed commands: ls; pwd.") ||
		!strings.Contains(sys.Content, "Ubuntu 22.04.3 LTS") {
		t.Fatalf("system prompt 不符: %q", sys.Content)
	}
	if gotBody.Messages[1].Role != "user" || gotBody.Messages[1].Content != "./check.sh --all" {
		t.Fatalf("user message 不符: %+v", gotBody.Messages[1])
	}
}

func TestGenerateShellOutputAPIKeyAndThinking(t *testing.T) {
	var (
		mu      sync.Mutex
		gotAuth string
		gotBody chatRequest
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		_ = json.Unmarshal(raw, &gotBody)
		mu.Unlock()
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer ts.Close()

	c := New(testConfig(ts.URL, func(cfg *Config) {
		cfg.APIKey = "  secret-key  "
		cfg.EnableThinking = true
	}), quietLogger())
	if c == nil {
		t.Fatal("客户端构造失败")
	}
	defer c.Close()

	if _, ok := c.GenerateShellOutput("h", "u", "/", nil, "ls"); !ok {
		t.Fatal("应返回 ok=true")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer secret-key" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if v, _ := gotBody.ChatTemplateKwargs["enable_thinking"].(bool); !v {
		t.Fatalf("enable_thinking 未透传: %+v", gotBody.ChatTemplateKwargs)
	}
	// 无历史命令时不应出现 Recently executed 段
	if strings.Contains(gotBody.Messages[0].Content, "Recently executed commands") {
		t.Fatal("无历史命令时不应输出 Recently executed 段")
	}
}

func TestEmptyContentIsSuccess(t *testing.T) {
	for _, body := range []string{
		`{"choices":[{"message":{"content":null}}]}`,
		`{"choices":[{"message":{"content":""}}]}`,
	} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}))
		c := newTestClient(t, ts)
		out, ok := c.GenerateShellOutput("h", "u", "/", nil, "sync")
		c.Close()
		ts.Close()
		if !ok || out != "" {
			t.Fatalf("body=%s -> ok=%v out=%q（命令成功无输出属正常）", body, ok, out)
		}
	}
}

// ============================ 降级路径 ============================

func TestFailurePathsDegrade(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantMsg string
	}{
		{"非 2xx", http.StatusInternalServerError, `{}`, "AI 服务 HTTP 500"},
		{"非法 JSON", http.StatusOK, `not-json`, "AI 响应解析失败"},
		{"缺少 choices", http.StatusOK, `{}`, "AI 响应解析失败"},
		{"choices 为空", http.StatusOK, `{"choices":[]}`, "AI 响应解析失败"},
		{"缺少 message", http.StatusOK, `{"choices":[{}]}`, "AI 响应解析失败"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer ts.Close()

			c := New(testConfig(ts.URL, func(cfg *Config) { cfg.FailureThreshold = 100 }), quietLogger())
			defer c.Close()

			out, ok := c.GenerateShellOutput("h", "u", "/", nil, "nmap 10.0.0.1")
			if ok || out != "" {
				t.Fatalf("失败路径应降级: ok=%v out=%q", ok, out)
			}
			if got := c.failures.Load(); got != 1 {
				t.Fatalf("连续失败计数=%d, 期望 1", got)
			}
			if c.circuitOpen() {
				t.Fatal("未达阈值不应熔断")
			}
		})
	}
}

func TestTimeoutDegrades(t *testing.T) {
	var calls int
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, `{"choices":[{"message":{"content":"late"}}]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts)
	defer c.Close()
	c.http.Timeout = 30 * time.Millisecond // 缩短超时以免拖慢测试

	if out, ok := c.GenerateShellOutput("h", "u", "/", nil, "slowcmd"); ok || out != "" {
		t.Fatalf("超时应降级: ok=%v out=%q", ok, out)
	}
	if c.failures.Load() != 1 {
		t.Fatalf("超时应计入失败: %d", c.failures.Load())
	}
}

func TestCircuitBreaker(t *testing.T) {
	var (
		mu    sync.Mutex
		calls int
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{}`)
	}))
	defer ts.Close()

	c := New(testConfig(ts.URL, func(cfg *Config) {
		cfg.FailureThreshold = 2
		cfg.CooldownSeconds = 60
	}), quietLogger())
	defer c.Close()

	for i := 0; i < 2; i++ {
		if _, ok := c.GenerateShellOutput("h", "u", "/", nil, "cmd"); ok {
			t.Fatalf("第 %d 次调用应失败", i+1)
		}
	}
	if !c.circuitOpen() {
		t.Fatal("连续失败达阈值后应熔断")
	}
	// 熔断期间直接降级，不再发起请求
	if _, ok := c.GenerateShellOutput("h", "u", "/", nil, "cmd"); ok {
		t.Fatal("熔断期间应降级")
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 2 {
		t.Fatalf("熔断期间不应发起请求，实际请求 %d 次", got)
	}

	// 冷却到期后自动半开，放行下一次请求
	c.openUntil.Store(time.Now().Add(-time.Second).UnixMilli())
	if _, ok := c.GenerateShellOutput("h", "u", "/", nil, "cmd"); ok {
		t.Fatal("服务仍失败时应降级")
	}
	mu.Lock()
	got = calls
	mu.Unlock()
	if got != 3 {
		t.Fatalf("冷却到期后应重新发起请求，实际请求 %d 次", got)
	}
}

func TestConcurrencyImmediateDegrade(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		io.WriteString(w, `{"choices":[{"message":{"content":"done"}}]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts)
	defer c.Close()

	done := make(chan struct {
		out string
		ok  bool
	}, 1)
	go func() {
		out, ok := c.GenerateShellOutput("h", "u", "/", nil, "first")
		done <- struct {
			out string
			ok  bool
		}{out, ok}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("首个请求未到达服务端")
	}

	// 并发额度已占满：第二个请求必须立即降级，不排队等待
	start := time.Now()
	out, ok := c.GenerateShellOutput("h", "u", "/", nil, "second")
	if ok || out != "" {
		t.Fatalf("并发打满应降级: ok=%v out=%q", ok, out)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("并发打满应立即可返回，实际耗时 %v", elapsed)
	}

	close(release)
	select {
	case res := <-done:
		if !res.ok || res.out != "done" {
			t.Fatalf("首个请求结果异常: %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("首个请求未返回")
	}
}

// ============================ 输出净化 ============================

func TestSanitize(t *testing.T) {
	c := New(testConfig("http://example.com", func(cfg *Config) { cfg.MaxOutputChars = 300 }), quietLogger())
	if c == nil {
		t.Fatal("客户端构造失败")
	}
	defer c.Close()

	cases := []struct{ name, in, want string }{
		{"剥离思考段", "<think>先想想</think>total 4", "total 4"},
		{"孤立闭标签", "a</think>b", "ab"},
		{"剥代码围栏", "```\nline1\nline2\n```", "line1\nline2"},
		{"仅围栏标记", "```", ""},
		{"正文反引号保留", "path is `backtick` ok", "path is `backtick` ok"},
		{"过滤控制字符", "\x01a\n\tb\x02", "a\n\tb"}, // 保留 \n \t，其余控制字符剔除
		{"短文本原样", "hello\nworld", "hello\nworld"},
	}
	for _, tc := range cases {
		if got := c.sanitize(tc.in); got != tc.want {
			t.Fatalf("%s: sanitize(%q)=%q, 期望 %q", tc.name, tc.in, got, tc.want)
		}
	}

	// 按字符数（rune）截断，不会切坏多字节字符
	long := strings.Repeat("é", 400)
	got := c.sanitize(long)
	if len([]rune(got)) != 300 {
		t.Fatalf("截断长度=%d, 期望 300", len([]rune(got)))
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Fatal("截断不应产生替换字符")
	}
}

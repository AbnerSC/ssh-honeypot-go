package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/store"
)

// 测试脚手架

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "database.db")

	// 真实部署中攻击日志存储先于 Web 启动建表（sessions/auth_attempts/...），
	// 这里显式还原该前提，Web 侧只负责 sys_users / sys_audit_log。
	st, err := store.Open(dbPath, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志表失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv, err := New(Options{
		Addr:                  "127.0.0.1:0",
		DBPath:                dbPath,
		SessionTimeoutMinutes: 30,
		Logger:                logger,
	})
	if err != nil {
		t.Fatalf("创建 Web 服务失败: %v", err)
	}
	ts := httptest.NewServer(srv.httpServer.Handler)
	t.Cleanup(func() {
		ts.Close()
		_ = srv.Close()
	})
	return srv, ts
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("创建 Cookie Jar 失败: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func newNoRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// apiResponse 响应包络。
type apiResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error"`
	Data  json.RawMessage `json:"data"`
	User  json.RawMessage `json:"user"`
}

// call 发起一次 API 调用并解析包络。
func call(t *testing.T, client *http.Client, method, url string, payload any) (*http.Response, apiResponse) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("序列化请求体失败: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求 %s %s 失败: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var parsed apiResponse
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

// loginAdmin 以默认管理员登录。
func loginAdmin(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp, body := call(t, client, http.MethodPost, baseURL+"/api/login",
		map[string]any{"username": "admin", "password": "admin123"})
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("默认管理员登录失败: status=%d error=%s", resp.StatusCode, body.Error)
	}
}

// waitAuditCount 等待满足条件的审计记录达到期望条数（审计为异步落库）。
func waitAuditCount(t *testing.T, srv *Server, where string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := srv.readDB.QueryRow("SELECT COUNT(*) FROM sys_audit_log WHERE " + where).Scan(&n); err != nil {
			t.Fatalf("统计审计记录失败: %v", err)
		}
		if n >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待审计记录超时: %s 期望至少 %d 条", where, want)
}

// 登录与 API 契约

func TestLoginAndConsoleAPIs(t *testing.T) {
	srv, ts := newTestServer(t)
	client := newClient(t)
	loginAdmin(t, client, ts.URL)

	// /api/me：返回登录用户（不含口令哈希），默认管理员带强制改密标记
	resp, body := call(t, client, http.MethodGet, ts.URL+"/api/me", nil)
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("/api/me 失败: status=%d error=%s", resp.StatusCode, body.Error)
	}
	var me User
	if err := json.Unmarshal(body.User, &me); err != nil {
		t.Fatalf("解析 /api/me 失败: %v", err)
	}
	if me.Username != "admin" || me.Role != RoleAdmin || !me.MustChange || !me.Enabled {
		t.Fatalf("默认管理员信息不符合预期: %+v", me)
	}

	// 自助改密：清除强制改密标记
	resp, body = call(t, client, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": "admin123", "newPassword": "newpass123"})
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("修改密码失败: status=%d error=%s", resp.StatusCode, body.Error)
	}
	_, body = call(t, client, http.MethodGet, ts.URL+"/api/me", nil)
	if err := json.Unmarshal(body.User, &me); err != nil {
		t.Fatalf("解析 /api/me 失败: %v", err)
	}
	if me.MustChange {
		t.Fatal("改密后 mustChange 应为 false")
	}

	// 总览统计：字段齐全
	resp, body = call(t, client, http.MethodGet, ts.URL+"/api/stats/overview", nil)
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("总览统计失败: %s", body.Error)
	}
	var overview map[string]any
	if err := json.Unmarshal(body.Data, &overview); err != nil {
		t.Fatalf("解析总览统计失败: %v", err)
	}
	for _, key := range []string{"totalSessions", "totalAuth", "totalCommands", "totalDownloads",
		"uniqueIps", "todaySessions", "todayAuth", "todayCommands", "todayDownloads", "activeLocks"} {
		if _, ok := overview[key]; !ok {
			t.Fatalf("总览统计缺少字段 %s", key)
		}
	}

	// 明细分页：空库返回空数组而非 null
	resp, body = call(t, client, http.MethodGet, ts.URL+"/api/sessions?page=1&size=20", nil)
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("会话查询失败: %s", body.Error)
	}
	var page struct {
		Total int64            `json:"total"`
		Page  int              `json:"page"`
		Size  int              `json:"size"`
		Rows  []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(body.Data, &page); err != nil {
		t.Fatalf("解析会话分页失败: %v", err)
	}
	if page.Total != 0 || page.Page != 1 || page.Size != 20 || page.Rows == nil {
		t.Fatalf("会话分页结果不符合预期: %+v", page)
	}

	// 用户列表
	resp, body = call(t, client, http.MethodGet, ts.URL+"/api/users", nil)
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("用户列表失败: %s", body.Error)
	}
	var users []User
	if err := json.Unmarshal(body.Data, &users); err != nil {
		t.Fatalf("解析用户列表失败: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("用户列表不符合预期: %+v", users)
	}

	// 新增用户：201 + data.id
	resp, body = call(t, client, http.MethodPost, ts.URL+"/api/users",
		map[string]any{"username": "viewer1", "password": "viewer123", "role": RoleViewer, "mustChange": false})
	if resp.StatusCode != http.StatusCreated || !body.OK {
		t.Fatalf("新增用户失败: status=%d error=%s", resp.StatusCode, body.Error)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body.Data, &created); err != nil || created.ID <= 1 {
		t.Fatalf("新增用户返回 ID 异常: %s (%v)", string(body.Data), err)
	}

	// 用户名重复 / 非法用户名 / 短密码 / 非法角色
	cases := []map[string]any{
		{"username": "viewer1", "password": "viewer123", "role": RoleViewer},
		{"username": "bad name", "password": "viewer123", "role": RoleViewer},
		{"username": "okname", "password": "short", "role": RoleViewer},
		{"username": "okname2", "password": "viewer123", "role": "superuser"},
	}
	for _, payload := range cases {
		resp, body = call(t, client, http.MethodPost, ts.URL+"/api/users", payload)
		if resp.StatusCode != http.StatusBadRequest || body.Error == "" {
			t.Fatalf("非法用户参数未被拒绝: %+v status=%d", payload, resp.StatusCode)
		}
	}

	// 管理员自保护：不能禁用/删除当前账号
	resp, _ = call(t, client, http.MethodPut, ts.URL+"/api/users/1/status", map[string]any{"enabled": false})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("禁用当前登录账号应返回 400，实际 %d", resp.StatusCode)
	}
	resp, _ = call(t, client, http.MethodDelete, ts.URL+"/api/users/1", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("删除当前登录账号应返回 400，实际 %d", resp.StatusCode)
	}

	// 审计：登录 / 改密 / 新增用户均已落库，且路径描述与脱敏生效
	waitAuditCount(t, srv, "path = '/api/password'", 1)
	waitAuditCount(t, srv, "path = '/api/users' AND method = 'POST'", 1)
	waitAuditCount(t, srv, "path = '/api/login' AND username = 'admin'", 1)

	var (
		desc    string
		reqBody string
	)
	err := srv.readDB.QueryRow(`SELECT path_desc, req_body FROM sys_audit_log
		WHERE path = '/api/password' ORDER BY id DESC LIMIT 1`).Scan(&desc, &reqBody)
	if err != nil {
		t.Fatalf("查询审计记录失败: %v", err)
	}
	if desc != "修改登录密码" {
		t.Fatalf("路径描述不符合预期: %q", desc)
	}
	if strings.Contains(reqBody, "admin123") || strings.Contains(reqBody, "newpass123") {
		t.Fatalf("审计请求体未脱敏: %s", reqBody)
	}
	if !strings.Contains(reqBody, `"oldPassword":"***"`) || !strings.Contains(reqBody, `"newPassword":"***"`) {
		t.Fatalf("审计请求体脱敏结果不符合预期: %s", reqBody)
	}

	// 数字路径段归一后仍能命中中文描述
	waitAuditCount(t, srv, "path LIKE '/api/users/%/status'", 1)
	if err := srv.readDB.QueryRow(`SELECT path_desc FROM sys_audit_log
		WHERE path LIKE '/api/users/%/status' ORDER BY id DESC LIMIT 1`).Scan(&desc); err != nil {
		t.Fatalf("查询审计记录失败: %v", err)
	}
	if desc != "启用/禁用用户" {
		t.Fatalf("数字路径段归一失败: %q", desc)
	}
}

func TestAuditAndUserAdminPermission(t *testing.T) {
	_, ts := newTestServer(t)
	admin := newClient(t)
	loginAdmin(t, admin, ts.URL)

	resp, body := call(t, admin, http.MethodPost, ts.URL+"/api/users",
		map[string]any{"username": "viewer1", "password": "viewer123", "role": RoleViewer, "mustChange": false})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("新增 viewer 失败: %s", body.Error)
	}

	viewer := newClient(t)
	resp, body = call(t, viewer, http.MethodPost, ts.URL+"/api/login",
		map[string]any{"username": "viewer1", "password": "viewer123"})
	if resp.StatusCode != http.StatusOK || !body.OK {
		t.Fatalf("viewer 登录失败: status=%d error=%s", resp.StatusCode, body.Error)
	}

	for _, path := range []string{"/api/users", "/api/audit-logs", "/api/audit-logs/trend"} {
		resp, body = call(t, viewer, http.MethodGet, ts.URL+path, nil)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body.Error, "仅管理员") {
			t.Fatalf("viewer 访问 %s 应返回 403，实际 %d (%s)", path, resp.StatusCode, body.Error)
		}
	}

	// viewer 仍可访问攻击日志统计与明细
	resp, _ = call(t, viewer, http.MethodGet, ts.URL+"/api/stats/overview", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer 访问统计应放行，实际 %d", resp.StatusCode)
	}
}

// 鉴权与限额

func TestUnauthorizedAccess(t *testing.T) {
	_, ts := newTestServer(t)

	// API 未登录 → 401 JSON
	resp, body := call(t, newClient(t), http.MethodGet, ts.URL+"/api/stats/overview", nil)
	if resp.StatusCode != http.StatusUnauthorized || body.OK || body.Error == "" {
		t.Fatalf("未登录访问 API 应返回 401 JSON，实际 %d (%s)", resp.StatusCode, body.Error)
	}

	// 页面未登录 → 302 跳转登录页
	client := newNoRedirectClient(t)
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("请求首页失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login.html" {
		t.Fatalf("未登录访问首页应跳转登录页，实际 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 登录页与静态资源放行
	for _, path := range []string{"/login.html", "/css/style.css", "/js/api.js", "/img/logo.svg", "/favicon.ico"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("静态资源 %s 应匿名可访问，实际 %d", path, resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
			t.Fatalf("静态资源 %s 缺少 no-cache: %q", path, cc)
		}
	}

	// vendor 目录不对外暴露（需先登录以越过鉴权）
	authed := newClient(t)
	loginAdmin(t, authed, ts.URL)
	resp, err = authed.Get(ts.URL + "/vendor/echarts.min.js")
	if err != nil {
		t.Fatalf("请求 vendor 失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("vendor 目录应禁止直接访问，实际 %d", resp.StatusCode)
	}
}

func TestBodyTooLarge(t *testing.T) {
	_, ts := newTestServer(t)
	huge := `{"username":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	resp, err := newClient(t).Post(ts.URL+"/api/login", "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("提交超大请求体失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求体应返回 413，实际 %d", resp.StatusCode)
	}
}

func TestLoginFailureLocksIP(t *testing.T) {
	_, ts := newTestServer(t)
	client := newClient(t)

	for i := 0; i < loginMaxAttempts; i++ {
		resp, body := call(t, client, http.MethodPost, ts.URL+"/api/login",
			map[string]any{"username": "admin", "password": "wrong-password"})
		if resp.StatusCode != http.StatusUnauthorized || body.Error != "用户名或密码错误" {
			t.Fatalf("第 %d 次失败登录响应不符合预期: %d (%s)", i+1, resp.StatusCode, body.Error)
		}
	}

	// 第 6 次即使口令正确也应被锁定
	resp, body := call(t, client, http.MethodPost, ts.URL+"/api/login",
		map[string]any{"username": "admin", "password": "admin123"})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body.Error, "已锁定") {
		t.Fatalf("连续失败应锁定来源 IP，实际 %d (%s)", resp.StatusCode, body.Error)
	}
}

func TestShouldChangePasswordRequiresOldPassword(t *testing.T) {
	_, ts := newTestServer(t)
	client := newClient(t)
	loginAdmin(t, client, ts.URL)

	// 原密码错误
	resp, body := call(t, client, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": "bad", "newPassword": "newpass123"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "原密码错误" {
		t.Fatalf("原密码错误应返回 400，实际 %d (%s)", resp.StatusCode, body.Error)
	}
	// 新密码过短
	resp, body = call(t, client, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": "admin123", "newPassword": "short"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "密码长度至少 8 位" {
		t.Fatalf("新密码过短应返回 400，实际 %d (%s)", resp.StatusCode, body.Error)
	}
}

// 静态资源与 ECharts

func TestEChartsEndpoint(t *testing.T) {
	_, ts := newTestServer(t)
	client := newClient(t)
	loginAdmin(t, client, ts.URL)

	resp, err := client.Get(ts.URL + "/api/vendor/echarts.js")
	if err != nil {
		t.Fatalf("请求 ECharts 失败: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ECharts 应返回 200，实际 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/javascript") {
		t.Fatalf("ECharts Content-Type 不符合预期: %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Fatalf("ECharts Cache-Control 不符合预期: %q", cc)
	}
	if len(data) < 100_000 {
		t.Fatalf("ECharts 资源长度异常: %d", len(data))
	}

	// 登录后首页可访问
	resp2, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("请求首页失败: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("登录后首页应返回 200，实际 %d", resp2.StatusCode)
	}
}

// 纯函数单测

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "公网直连不信任转发头",
			remoteAddr: "203.0.113.9:52100",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "203.0.113.9",
		},
		{
			name:       "内网代理取链路首个公网 IP",
			remoteAddr: "172.18.0.1:52100",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1, 8.8.8.8, 10.0.0.2"},
			want:       "8.8.8.8",
		},
		{
			name:       "链路全内网时取首个内网 IP",
			remoteAddr: "127.0.0.1:52100",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.5, 10.0.0.2"},
			want:       "192.168.1.5",
		},
		{
			name:       "IPv4-mapped 直连地址归一后再判断",
			remoteAddr: "[::ffff:172.18.0.1]:52100",
			headers:    map[string]string{"X-Real-IP": "10.1.1.1"},
			want:       "10.1.1.1",
		},
		{
			name:       "转发头带端口时剥离",
			remoteAddr: "10.0.0.1:52100",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7:4433"},
			want:       "203.0.113.7",
		},
		{
			name:       "无转发头退回直连地址",
			remoteAddr: "10.0.0.1:52100",
			want:       "10.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := ClientIP(req); got != tc.want {
				t.Fatalf("ClientIP = %q, 期望 %q", got, tc.want)
			}
		})
	}
}

func TestPasswordHashing(t *testing.T) {
	stored := hashPassword("s3cret-pass")
	if !strings.HasPrefix(stored, "pbkdf2-sha256$210000$") {
		t.Fatalf("哈希格式不符合预期: %s", stored)
	}
	if !verifyPassword("s3cret-pass", stored) {
		t.Fatal("正确口令应校验通过")
	}
	if verifyPassword("wrong-pass", stored) {
		t.Fatal("错误口令不应校验通过")
	}
	// 盐不同则哈希不同，但都能校验
	if hashPassword("s3cret-pass") == stored {
		t.Fatal("相同口令的两次哈希不应相同（盐随机）")
	}
	// 非法存储格式
	for _, bad := range []string{"", "plain", "pbkdf2-sha256$1$", "pbkdf2-sha256$x$$",
		"pbkdf2-sha256$1$AAAA$", "argon2$1$AAAA$BBBB"} {
		if verifyPassword("s3cret-pass", bad) {
			t.Fatalf("非法哈希格式不应通过: %q", bad)
		}
	}
}

func TestPathDescMapping(t *testing.T) {
	cases := map[string]string{
		"POST /api/login":            "用户登录",
		"GET /api/stats/overview":    "攻击总览统计",
		"PUT /api/users/7/status":    "启用/禁用用户",
		"PUT /api/users/12/password": "重置用户密码",
		"DELETE /api/users/9":        "删除用户",
		"GET /api/unknown":           "",
	}
	for key, want := range cases {
		parts := strings.SplitN(key, " ", 2)
		if got := pathDesc(parts[0], parts[1]); got != want {
			t.Fatalf("pathDesc(%q) = %q, 期望 %q", key, got, want)
		}
	}
}

func TestMaskBodyAndResponse(t *testing.T) {
	masked := maskBody(`{"username":"admin","password":"p1","newPassword":"p2","nested":{"password":"p3"}}`)
	if strings.Contains(masked, `"p1"`) || strings.Contains(masked, `"p2"`) {
		t.Fatalf("敏感字段未脱敏: %s", masked)
	}
	if !strings.Contains(masked, `"password":"***"`) || !strings.Contains(masked, `"newPassword":"***"`) {
		t.Fatalf("脱敏结果不符合预期: %s", masked)
	}
	if !strings.Contains(masked, `"p3"`) {
		t.Fatalf("嵌套字段不应被改写: %s", masked)
	}
	if got := maskBody("not-json"); got != "not-json" {
		t.Fatalf("非法 JSON 应原样返回: %s", got)
	}
	if got := maskBody("  "); got != "" {
		t.Fatalf("空白请求体应返回空串: %q", got)
	}

	resp := maskResponse(`{"ok":true,"data":{"total":3,"page":1,"size":20,"rows":[{"a":1},{"a":2}]}}`)
	if strings.Contains(resp, `"rows":[`) {
		t.Fatalf("响应摘要不应包含完整 rows: %s", resp)
	}
	if !strings.Contains(resp, `"rowsCount":2`) {
		t.Fatalf("响应摘要应包含 rowsCount: %s", resp)
	}

	long := strings.Repeat("x", 2100)
	if got := truncate(long); len([]rune(got)) != 2000+len([]rune("…(truncated)")) {
		t.Fatalf("截断长度异常: %d", len([]rune(got)))
	}
	if got := truncate("short"); got != "short" {
		t.Fatalf("短文本不应截断: %s", got)
	}
}

func TestParseBodyTolerance(t *testing.T) {
	parse := func(raw []byte) (map[string]any, error) {
		r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		if raw != nil {
			r = r.WithContext(context.WithValue(r.Context(), bodyKey{}, raw))
		}
		return parseBody(r)
	}

	// 空体与 null 均视为空对象
	for _, raw := range [][]byte{nil, []byte("  \n\t"), []byte("null")} {
		got, err := parse(raw)
		if err != nil {
			t.Fatalf("空请求体不应报错: %q -> %v", string(raw), err)
		}
		if len(got) != 0 {
			t.Fatalf("空请求体应解析为空对象: %q -> %v", string(raw), got)
		}
	}

	// 容忍 UTF-8 BOM（Java 版 Gson 同样容忍）
	got, err := parse(append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"username":"admin"}`)...))
	if err != nil {
		t.Fatalf("带 BOM 的 JSON 不应报错: %v", err)
	}
	if got["username"] != "admin" {
		t.Fatalf("带 BOM 的 JSON 解析结果异常: %v", got)
	}

	// 非法 JSON 返回错误
	if _, err := parse([]byte(`{"username":`)); err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
}

func TestSessionStoreSlidingExpiry(t *testing.T) {
	store := newSessionStore(40 * time.Millisecond)
	defer store.Close()

	sess := store.Create(1, "admin", RoleAdmin)
	if store.Get(sess.ID) == nil {
		t.Fatal("新建会话应可读取")
	}
	// Get 会续期，等待超过原始有效期后仍应有效
	time.Sleep(30 * time.Millisecond)
	if store.Get(sess.ID) == nil {
		t.Fatal("会话应在读取时滑动续期")
	}
	time.Sleep(80 * time.Millisecond)
	if store.Get(sess.ID) != nil {
		t.Fatal("超过滑动有效期后会话应失效")
	}

	id := store.Create(2, "viewer", RoleViewer).ID
	store.Destroy(id)
	if store.Get(id) != nil {
		t.Fatal("销毁后会话应失效")
	}
}

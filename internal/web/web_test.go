package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-honeypot-go/internal/store"
)

// 测试口令：全部满足「12 位 + 大写/小写/数字/符号四类中至少三类」的强度策略。
const (
	testNewPassword     = "Admin@45678901"
	testViewerPassword  = "Viewer@123456"
	testViewerPassword2 = "Viewer@456789"
)

// testDefaultAdminPasswordValue 测试用固定初始口令（同样满足强度策略）：
// TestMain 把它注入生产环境的随机生成环节，使用例不依赖随机值
// （随机生成本身由 users_password_test.go 单独校验）。
const testDefaultAdminPasswordValue = "Kp7#mQx2vLn8$Rt4"

func TestMain(m *testing.M) {
	testDefaultAdminPassword = testDefaultAdminPasswordValue
	os.Exit(m.Run())
}

// 测试脚手架

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith 允许单个用例定制 Options（如受信代理白名单）。
func newTestServerWith(t *testing.T, mutate func(*Options)) (*Server, *httptest.Server) {
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

	opts := Options{
		Addr:                  "127.0.0.1:0",
		DBPath:                dbPath,
		SessionTimeoutMinutes: 30,
		Logger:                logger,
	}
	if mutate != nil {
		mutate(&opts)
	}
	srv, err := New(opts)
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
	return callWithHeader(t, client, method, url, payload, nil)
}

// callWithHeader 同 call，额外设置请求头（用于伪造 X-Forwarded-For 等场景）。
func callWithHeader(t *testing.T, client *http.Client, method, url string, payload any,
	headers map[string]string) (*http.Response, apiResponse) {
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
	for k, v := range headers {
		req.Header.Set(k, v)
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

// loginAdmin 以默认管理员登录（口令为 bootstrap 注入的固定测试值）。
func loginAdmin(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	if defaultAdminPassword != testDefaultAdminPasswordValue {
		t.Fatalf("默认管理员初始口令未被正确注入: %q", defaultAdminPassword)
	}
	resp, body := call(t, client, http.MethodPost, baseURL+"/api/login",
		map[string]any{"username": "admin", "password": defaultAdminPassword})
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
		map[string]any{"oldPassword": defaultAdminPassword, "newPassword": testNewPassword})
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
		map[string]any{"username": "viewer1", "password": testViewerPassword, "role": RoleViewer, "mustChange": false})
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
		{"username": "viewer1", "password": testViewerPassword, "role": RoleViewer},
		{"username": "bad name", "password": testViewerPassword, "role": RoleViewer},
		{"username": "okname", "password": "short", "role": RoleViewer},
		{"username": "okname2", "password": testViewerPassword, "role": "superuser"},
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
	if strings.Contains(reqBody, defaultAdminPassword) || strings.Contains(reqBody, testNewPassword) {
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
	// 默认管理员首次登录强制改密（服务端拦截其它 API），先完成改密
	resp, body := call(t, admin, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": defaultAdminPassword, "newPassword": testNewPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("管理员改密失败: %d (%s)", resp.StatusCode, body.Error)
	}

	resp, body = call(t, admin, http.MethodPost, ts.URL+"/api/users",
		map[string]any{"username": "viewer1", "password": testViewerPassword, "role": RoleViewer, "mustChange": false})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("新增 viewer 失败: %s", body.Error)
	}

	viewer := newClient(t)
	resp, body = call(t, viewer, http.MethodPost, ts.URL+"/api/login",
		map[string]any{"username": "viewer1", "password": testViewerPassword})
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
		map[string]any{"username": "admin", "password": defaultAdminPassword})
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
		map[string]any{"oldPassword": "bad", "newPassword": testNewPassword})
	if resp.StatusCode != http.StatusBadRequest || body.Error != "原密码错误" {
		t.Fatalf("原密码错误应返回 400，实际 %d (%s)", resp.StatusCode, body.Error)
	}
	// 新密码过短
	resp, body = call(t, client, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": defaultAdminPassword, "newPassword": "short"})
	if resp.StatusCode != http.StatusBadRequest || body.Error != fmt.Sprintf("密码长度至少 %d 位", passwordMinLength) {
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

// TestClientIPResolver 来源 IP 解析的安全模型：
// 转发头只能由受信代理写入，未配置白名单时任何转发头都不得采信，
// 否则攻击者可伪造 X-Forwarded-For 绕过登录锁定或伪造审计来源。
func TestClientIPResolver(t *testing.T) {
	untrusted, err := NewClientIPResolver(nil)
	if err != nil {
		t.Fatalf("构造默认解析器失败: %v", err)
	}
	trusted, err := NewClientIPResolver([]string{"10.0.0.0/8", "::1"})
	if err != nil {
		t.Fatalf("构造受信代理解析器失败: %v", err)
	}

	cases := []struct {
		name       string
		resolver   *ClientIPResolver
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "默认不信任转发头",
			resolver:   untrusted,
			remoteAddr: "172.18.0.1:52100",
			headers:    map[string]string{"X-Forwarded-For": "8.8.8.8"},
			want:       "172.18.0.1",
		},
		{
			name:       "受信代理才读链路首个 IP",
			resolver:   trusted,
			remoteAddr: "10.1.2.3:52100",
			headers:    map[string]string{"X-Forwarded-For": "8.8.8.8, 10.0.0.2"},
			want:       "8.8.8.8",
		},
		{
			name:       "非受信直连地址忽略转发头",
			resolver:   trusted,
			remoteAddr: "203.0.113.9:52100",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "203.0.113.9",
		},
		{
			name:       "转发头带端口时剥离",
			resolver:   trusted,
			remoteAddr: "10.0.0.1:52100",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7:4433"},
			want:       "203.0.113.7",
		},
		{
			name:       "IPv4-mapped 直连地址归一",
			resolver:   untrusted,
			remoteAddr: "[::ffff:172.18.0.1]:52100",
			headers:    map[string]string{"X-Real-IP": "10.1.1.1"},
			want:       "172.18.0.1",
		},
		{
			name:       "无转发头退回直连地址",
			resolver:   trusted,
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
			if got := tc.resolver.Resolve(req); got != tc.want {
				t.Fatalf("Resolve = %q, 期望 %q", got, tc.want)
			}
			// 兼容入口 ClientIP 恒不信任转发头
			if got := ClientIP(req); got != normalizeIP(stripPort(tc.remoteAddr)) {
				t.Fatalf("ClientIP = %q, 期望直连地址", got)
			}
		})
	}

	// 非法受信代理配置必须在启动时报错，而不是静默失效
	if _, err := NewClientIPResolver([]string{"not-an-ip", "10.0.0.0/33"}); err == nil {
		t.Fatal("非法受信代理配置应报错")
	}
}

// TestMustChangeForcedByServer 默认口令登录后必须强制改密：
// mustChange 仅前端拦截时，攻击者直接调 API 即可获取控制台数据。
func TestMustChangeForcedByServer(t *testing.T) {
	_, ts := newTestServer(t)
	client := newClient(t)
	loginAdmin(t, client, ts.URL)

	resp, body := call(t, client, http.MethodGet, ts.URL+"/api/users", nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body.Error, "修改密码") {
		t.Fatalf("未改密时应拒绝控制台 API，实际 %d (%s)", resp.StatusCode, body.Error)
	}
	resp, _ = call(t, client, http.MethodGet, ts.URL+"/api/stats/overview", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("未改密时不应可读攻击统计，实际 %d", resp.StatusCode)
	}

	// 自身信息、改密、静态资源仍放行
	resp, _ = call(t, client, http.MethodGet, ts.URL+"/api/me", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/me 应放行，实际 %d", resp.StatusCode)
	}
	resp, _ = call(t, client, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": defaultAdminPassword, "newPassword": testNewPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改密应放行，实际 %d", resp.StatusCode)
	}

	resp, body = call(t, client, http.MethodGet, ts.URL+"/api/users", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改密后应可访问控制台 API，实际 %d (%s)", resp.StatusCode, body.Error)
	}
}

// TestSessionRevokedOnAccountChange 账号被禁用/重置口令/删除后，
// 旧会话必须立即失效（权限撤销不能等会话自然过期）。
func TestSessionRevokedOnAccountChange(t *testing.T) {
	_, ts := newTestServer(t)

	admin := newClient(t)
	loginAdmin(t, admin, ts.URL)
	if resp, body := call(t, admin, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": defaultAdminPassword, "newPassword": testNewPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("管理员改密失败: %d (%s)", resp.StatusCode, body.Error)
	}

	resp, body := call(t, admin, http.MethodPost, ts.URL+"/api/users", map[string]any{
		"username": "viewer2", "password": testViewerPassword, "role": RoleViewer, "mustChange": false,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建 viewer2 失败: %s", body.Error)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body.Data, &created); err != nil || created.ID == 0 {
		t.Fatalf("解析用户 ID 失败: %v (%s)", err, body.Data)
	}

	loginViewer := func(client *http.Client) {
		t.Helper()
		resp, body := call(t, client, http.MethodPost, ts.URL+"/api/login",
			map[string]any{"username": "viewer2", "password": testViewerPassword})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("viewer2 登录失败: %d (%s)", resp.StatusCode, body.Error)
		}
	}
	assertRevoked := func(client *http.Client, stage string) {
		t.Helper()
		resp, _ := call(t, client, http.MethodGet, ts.URL+"/api/stats/overview", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s后旧会话应失效（401），实际 %d", stage, resp.StatusCode)
		}
	}

	viewer := newClient(t)
	loginViewer(viewer)
	if resp, _ := call(t, viewer, http.MethodGet, ts.URL+"/api/stats/overview", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer2 会话应可用，实际 %d", resp.StatusCode)
	}

	// 禁用 → 旧会话 401
	if resp, body := call(t, admin, http.MethodPut,
		fmt.Sprintf("%s/api/users/%d/status", ts.URL, created.ID),
		map[string]any{"enabled": false}); resp.StatusCode != http.StatusOK {
		t.Fatalf("禁用用户失败: %d (%s)", resp.StatusCode, body.Error)
	}
	assertRevoked(viewer, "禁用")

	// 重新启用后重新登录 → 重置口令 → 旧会话 401
	if resp, body := call(t, admin, http.MethodPut,
		fmt.Sprintf("%s/api/users/%d/status", ts.URL, created.ID),
		map[string]any{"enabled": true}); resp.StatusCode != http.StatusOK {
		t.Fatalf("启用用户失败: %d (%s)", resp.StatusCode, body.Error)
	}
	loginViewer(viewer)
	if resp, body := call(t, admin, http.MethodPut,
		fmt.Sprintf("%s/api/users/%d/password", ts.URL, created.ID),
		map[string]any{"password": testViewerPassword2, "mustChange": false}); resp.StatusCode != http.StatusOK {
		t.Fatalf("重置密码失败: %d (%s)", resp.StatusCode, body.Error)
	}
	assertRevoked(viewer, "重置密码")

	// 新口令登录 → 删除用户 → 旧会话 401
	resp, body = call(t, viewer, http.MethodPost, ts.URL+"/api/login",
		map[string]any{"username": "viewer2", "password": testViewerPassword2})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("新口令登录失败: %d (%s)", resp.StatusCode, body.Error)
	}
	if resp, body := call(t, admin, http.MethodDelete,
		fmt.Sprintf("%s/api/users/%d", ts.URL, created.ID), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("删除用户失败: %d (%s)", resp.StatusCode, body.Error)
	}
	assertRevoked(viewer, "删除")
}

// TestChangePasswordRevokesOtherSessions 自助改密后其它终端会话必须失效，当前会话保留。
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	_, ts := newTestServer(t)
	admin := newClient(t)
	loginAdmin(t, admin, ts.URL)
	if resp, body := call(t, admin, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": defaultAdminPassword, "newPassword": testNewPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("管理员改密失败: %d (%s)", resp.StatusCode, body.Error)
	}
	if resp, body := call(t, admin, http.MethodPost, ts.URL+"/api/users", map[string]any{
		"username": "viewer3", "password": testViewerPassword, "role": RoleViewer, "mustChange": false,
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建 viewer3 失败: %s", body.Error)
	}

	first, second := newClient(t), newClient(t)
	for i, client := range []*http.Client{first, second} {
		resp, body := call(t, client, http.MethodPost, ts.URL+"/api/login",
			map[string]any{"username": "viewer3", "password": testViewerPassword})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 个终端登录失败: %d (%s)", i+1, resp.StatusCode, body.Error)
		}
	}

	if resp, body := call(t, first, http.MethodPut, ts.URL+"/api/password",
		map[string]any{"oldPassword": testViewerPassword, "newPassword": testViewerPassword2}); resp.StatusCode != http.StatusOK {
		t.Fatalf("改密失败: %d (%s)", resp.StatusCode, body.Error)
	}
	if resp, _ := call(t, first, http.MethodGet, ts.URL+"/api/stats/overview", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("当前终端会话应保留，实际 %d", resp.StatusCode)
	}
	if resp, _ := call(t, second, http.MethodGet, ts.URL+"/api/stats/overview", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("其它终端旧会话应失效，实际 %d", resp.StatusCode)
	}
}

// TestForwardedForIgnoredByDefault 伪造 X-Forwarded-For 不得绕过登录锁定。
func TestForwardedForIgnoredByDefault(t *testing.T) {
	srv, ts := newTestServer(t)
	client := newClient(t)

	for i := 0; i < loginMaxAttempts; i++ {
		resp, _ := callWithHeader(t, client, http.MethodPost, ts.URL+"/api/login",
			map[string]any{"username": "admin", "password": "wrong-password"},
			map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1)})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败登录状态码异常: %d", i+1, resp.StatusCode)
		}
	}

	// 换一个伪造来源 IP 并给出正确口令：仍应命中锁定
	resp, body := callWithHeader(t, client, http.MethodPost, ts.URL+"/api/login",
		map[string]any{"username": "admin", "password": defaultAdminPassword},
		map[string]string{"X-Forwarded-For": "203.0.113.200"})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body.Error, "已锁定") {
		t.Fatalf("伪造转发头绕过了登录锁定，实际 %d (%s)", resp.StatusCode, body.Error)
	}

	// 审计记录的来源必须是真实直连地址（127.0.0.1），而不是伪造值
	waitAuditCount(t, srv, "path = '/api/login'", loginMaxAttempts)
	var srcIP string
	if err := srv.readDB.QueryRow(`SELECT src_ip FROM sys_audit_log WHERE path = '/api/login' ORDER BY id DESC LIMIT 1`).Scan(&srcIP); err != nil {
		t.Fatalf("读取审计来源失败: %v", err)
	}
	if srcIP != "127.0.0.1" {
		t.Fatalf("审计来源被转发头伪造: %q", srcIP)
	}
}

// TestTrustedProxyResolvesForwardedFor 配置受信代理后，转发头才用于来源解析与审计。
func TestTrustedProxyResolvesForwardedFor(t *testing.T) {
	srv, ts := newTestServerWith(t, func(o *Options) {
		o.TrustedProxies = []string{"127.0.0.1"}
	})
	client := newClient(t)

	resp, body := callWithHeader(t, client, http.MethodPost, ts.URL+"/api/login",
		map[string]any{"username": "admin", "password": defaultAdminPassword},
		map[string]string{"X-Forwarded-For": "45.33.32.156"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("受信代理下登录失败: %d (%s)", resp.StatusCode, body.Error)
	}

	waitAuditCount(t, srv, "path = '/api/login'", 1)
	var srcIP string
	if err := srv.readDB.QueryRow(`SELECT src_ip FROM sys_audit_log WHERE path = '/api/login' ORDER BY id DESC LIMIT 1`).Scan(&srcIP); err != nil {
		t.Fatalf("读取审计来源失败: %v", err)
	}
	if srcIP != "45.33.32.156" {
		t.Fatalf("受信代理下应记录真实客户端 IP，实际 %q", srcIP)
	}
}

// TestEscapeLike 过滤值中的 % / _ 必须按字面量处理，不得被当作模式通配符。
func TestEscapeLike(t *testing.T) {
	cases := map[string]string{
		"abc":  "abc",
		"100%": `100\%`,
		"a_b":  `a\_b`,
		`a\b`:  `a\\b`,
		"%_\\": `\%\_\\`,
	}
	for in, want := range cases {
		if got := escapeLike(in); got != want {
			t.Errorf("escapeLike(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAuditAnonymousQuota 未认证请求审计按 IP 限额，避免登录接口被刷爆磁盘。
func TestAuditAnonymousQuota(t *testing.T) {
	repo := &AuditRepo{}
	for i := 0; i < auditAnonPerIP; i++ {
		if !repo.allowAnonymous("198.51.100.7") {
			t.Fatalf("第 %d 条未认证审计不应被限流", i+1)
		}
	}
	if repo.allowAnonymous("198.51.100.7") {
		t.Fatalf("超出 %d 条/分钟应丢弃", auditAnonPerIP)
	}
	if !repo.allowAnonymous("203.0.113.8") {
		t.Fatal("其它来源 IP 不应受影响")
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

// TestLogRepoAggregateAndFallback 预聚合表可用时走聚合统计；表缺失时回退明细统计。
func TestLogRepoAggregateAndFallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "database.db")

	st, err := store.Open(dbPath, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志表失败: %v", err)
	}
	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")
	epoch := now.UnixMilli()
	const ip = "203.0.113.7"
	// 多词国家名：location 拼接后只能取到首词，聚合名必须来自 country 列
	for _, fn := range []func() error{
		func() error { return st.RecordSessionOpen(ts, epoch, "s1-agg", "ssh", ip, 1234, "South Korea Seoul") },
		func() error {
			return st.RecordAuthAttempt(ts, epoch, "s1-agg", "ssh", ip, "root", "x", false, "South Korea Seoul", "South Korea")
		},
		func() error { return st.RecordCommand(ts, epoch, "s1-agg", ip, "root", "id", "South Korea Seoul") },
	} {
		if err := fn(); err != nil {
			t.Fatalf("写入事件失败: %v", err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	readDB, err := openReadDB(dbPath)
	if err != nil {
		t.Fatalf("打开只读库失败: %v", err)
	}
	defer readDB.Close()

	repo := newLogRepo(readDB)
	if !repo.agg {
		t.Fatal("store 已建预聚合表，LogRepo 应启用聚合路径")
	}
	overview, err := repo.Overview()
	if err != nil {
		t.Fatalf("总览统计失败: %v", err)
	}
	want := map[string]int64{
		"totalSessions": 1, "totalAuth": 1, "totalCommands": 1,
		"uniqueIps": 1, "todaySessions": 1, "todayAuth": 1,
	}
	for key, expected := range want {
		if got := toInt64(overview[key]); got != expected {
			t.Errorf("聚合总览 %s = %d, want %d", key, got, expected)
		}
	}

	trend, err := repo.Trend(7)
	if err != nil {
		t.Fatalf("趋势统计失败: %v", err)
	}
	if len(trend) != 1 || toInt64(trend[0]["sessions"]) != 1 || toInt64(trend[0]["auth"]) != 1 {
		t.Errorf("聚合趋势不符: %v", trend)
	}

	topIPs, err := repo.TopIPs(5)
	if err != nil {
		t.Fatalf("IP 排行失败: %v", err)
	}
	if len(topIPs) != 1 || topIPs[0]["name"] != ip || toInt64(topIPs[0]["value"]) != 1 {
		t.Errorf("聚合 IP 排行不符: %v", topIPs)
	}

	topLocations, err := repo.TopLocations(5)
	if err != nil {
		t.Fatalf("地区排行失败: %v", err)
	}
	if len(topLocations) != 1 || topLocations[0]["name"] != "South Korea" || toInt64(topLocations[0]["value"]) != 1 {
		t.Errorf("地区排行应按国家聚合为 South Korea，实际: %v", topLocations)
	}

	// 回退路径：聚合表缺失时仍能统计明细（防御性兜底）
	writeDB, err := openWriteDB(dbPath)
	if err != nil {
		t.Fatalf("打开写库失败: %v", err)
	}
	defer writeDB.Close()
	for _, ddl := range []string{`DROP TABLE stats_daily`, `DROP TABLE stats_ip_daily`} {
		if _, err := writeDB.Exec(ddl); err != nil {
			t.Fatalf("删除聚合表失败（%s）: %v", ddl, err)
		}
	}

	fallback := newLogRepo(readDB)
	if fallback.agg {
		t.Fatal("聚合表已删除，应回退明细统计")
	}
	overview, err = fallback.Overview()
	if err != nil {
		t.Fatalf("回退总览统计失败: %v", err)
	}
	if got := toInt64(overview["totalSessions"]); got != 1 {
		t.Errorf("回退总览 totalSessions = %d, want 1", got)
	}
	if got := toInt64(overview["todayCommands"]); got != 1 {
		t.Errorf("回退总览 todayCommands = %d, want 1", got)
	}
}

// TestTopLocationsWithoutCountryColumn 聚合表存在但缺 country 列（升级前的 v6 库）时，
// 只能让地区排行退化为按 location 首段推断，其余统计仍走聚合表。
func TestTopLocationsWithoutCountryColumn(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "database.db")

	st, err := store.Open(dbPath, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志表失败: %v", err)
	}
	now := time.Now()
	if err := st.RecordAuthAttempt(now.Format("2006-01-02 15:04:05.000"), now.UnixMilli(),
		"s1", "ssh", "203.0.113.7", "root", "x", false, "South Korea Seoul", "South Korea"); err != nil {
		t.Fatalf("写入事件失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	// 退化成 v6 结构：stats_locations 没有 country 列
	w, err := openWriteDB(dbPath)
	if err != nil {
		t.Fatalf("打开写库失败: %v", err)
	}
	for _, ddl := range []string{
		`DROP TABLE stats_locations`,
		`CREATE TABLE stats_locations (location TEXT NOT NULL PRIMARY KEY, auth_attempts INTEGER NOT NULL DEFAULT 0)`,
		`INSERT INTO stats_locations(location, auth_attempts) VALUES('South Korea Seoul', 1)`,
	} {
		if _, err := w.Exec(ddl); err != nil {
			t.Fatalf("构造 v6 库失败（%s）: %v", ddl, err)
		}
	}
	_ = w.Close()

	db, err := openReadDB(dbPath)
	if err != nil {
		t.Fatalf("打开只读库失败: %v", err)
	}
	defer db.Close()

	repo := newLogRepo(db)
	if !repo.agg || repo.locCountry {
		t.Fatalf("聚合路径应仍启用但缺 country 列: agg=%t locCountry=%t", repo.agg, repo.locCountry)
	}
	// 其余统计不受影响，仍读聚合表
	if _, err := repo.Overview(); err != nil {
		t.Fatalf("总览统计失败: %v", err)
	}
	// 缺 country 列时只能按空格取首段（升级前的既有行为），升级到 v7 后应变为 South Korea
	top, err := repo.TopLocations(5)
	if err != nil {
		t.Fatalf("地区排行失败: %v", err)
	}
	if len(top) != 1 || top[0]["name"] != "South" {
		t.Errorf("缺 country 列时应退化为首段推断，实际: %v", top)
	}
}

// TestRecoverMiddlewareIsolatesPanic 单个处理器 panic 必须只影响本次请求：
// 返回 500 而不是终止整个进程（否则控制台与同进程的蜜罐会一起下线）。
func TestRecoverMiddlewareIsolatesPanic(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic 后状态码=%d，期望 500", rec.Code)
	}

	// 已写出响应的处理器 panic 时不得重复写状态码（保持原有响应与状态）
	h2 := srv.recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		panic("boom")
	}))
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/boom2", nil))
	if rec2.Code != http.StatusTeapot {
		t.Fatalf("已写出响应后不应被改写，状态码=%d", rec2.Code)
	}
}

// TestCheckPasswordPolicy 口令强度：长度≥ 12，且大写字母、小写字母、数字、
// 特殊符号四类中至少包含三类。
func TestCheckPasswordPolicy(t *testing.T) {
	const (
		errTooShort = "密码长度至少 12 位"
		errTooWeak  = "密码需包含大写字母、小写字母、数字、特殊符号中的至少三种"
	)
	cases := []struct{ name, pwd, want string }{
		{"空口令", "", errTooShort},
		{"11 位但四类全含", "Abcdef@1234", errTooShort},
		{"12 位但仅小写", "abcdefghijkl", errTooWeak},
		{"12 位但仅大小写", "Abcdefghijkl", errTooWeak},
		{"16 位但仅数字", "1234567890123456", errTooWeak},
		{"12 位三类（大写/小写/数字）", "Abcdefgh1234", ""},
		{"12 位三类（小写/数字/符号）", "abcdefgh123!", ""},
		{"四类全含", "Abcdef@12345", ""},
		{"非 ASCII 字符计入符号类", "密码Abcdef1234", ""},
		{"测试注入的初始口令", testDefaultAdminPasswordValue, ""},
		{"默认管理员实际口令", defaultAdminPassword, ""},
	}
	for _, c := range cases {
		if got := checkPassword(c.pwd); got != c.want {
			t.Errorf("%s: checkPassword = %q, 期望 %q", c.name, got, c.want)
		}
	}
}

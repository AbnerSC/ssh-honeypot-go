package conformance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newStack 起一个 httptest 服务并返回带 Cookie Jar 的客户端。
func newStack(t *testing.T, name string, h http.Handler) (*Stack, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s, err := NewStack(name, srv.URL)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}
	return s, srv
}

func TestNewStackRejectsBadURL(t *testing.T) {
	for _, bad := range []string{"", "127.0.0.1:8080", "http://"} {
		if _, err := NewStack("x", bad); err == nil {
			t.Errorf("地址 %q 应被拒绝", bad)
		}
	}
}

func TestShape(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "对象嵌套与数组采样",
			raw:  `{"ok":true,"data":{"total":1,"items":[{"id":1,"name":"a","ok":false}]}}`,
			want: map[string]string{
				"ok":                "bool",
				"data.total":        "number",
				"data.items[].id":   "number",
				"data.items[].name": "string",
				"data.items[].ok":   "bool",
			},
		},
		{
			name: "空数组与空对象",
			raw:  `{"data":{"items":[],"extra":{}}}`,
			want: map[string]string{
				"data.items[]": "array<unknown>",
				"data.extra":   "object",
			},
		},
		{
			name: "null 字段",
			raw:  `{"data":{"closedAt":null}}`,
			want: map[string]string{"data.closedAt": "null"},
		},
	}
	for _, c := range cases {
		got, err := Shape([]byte(c.raw))
		if err != nil {
			t.Fatalf("%s: 解析失败: %v", c.name, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("%s: 路径数量不符 got=%v want=%v", c.name, got, c.want)
		}
		for path, typ := range c.want {
			if got[path] != typ {
				t.Errorf("%s: 路径 %s 类型为 %q，期望 %q", c.name, path, got[path], typ)
			}
		}
	}
}

func TestShapeRejectsNonJSON(t *testing.T) {
	if _, err := Shape([]byte(`<html>502 Bad Gateway</html>`)); err == nil {
		t.Fatal("非 JSON 响应应报错")
	}
}

func TestDiffShapes(t *testing.T) {
	base := map[string]string{"ok": "bool", "data.total": "number"}

	if diffs := DiffShapes(base, map[string]string{"ok": "bool", "data.total": "number"}); len(diffs) != 0 {
		t.Fatalf("相同形状不应有差异: %v", diffs)
	}

	// 空数组与有元素数组视为兼容（不同库数据量本就不同）
	wild := map[string]string{"ok": "bool", "data.total": "number", "data.items[]": "array<unknown>"}
	full := map[string]string{"ok": "bool", "data.total": "number", "data.items[].id": "number"}
	if diffs := DiffShapes(wild, full); len(diffs) != 0 {
		t.Fatalf("空数组应与有元素数组兼容: %v", diffs)
	}

	extra := map[string]string{"ok": "bool", "data.total": "number", "data.rows": "number"}
	diffs := DiffShapes(base, extra)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "字段 data.rows：仅 Go 返回") {
		t.Fatalf("应检出多余字段，实际: %v", diffs)
	}

	typeDiff := map[string]string{"ok": "bool", "data.total": "string"}
	diffs = DiffShapes(base, typeDiff)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "类型不同：java=number go=string") {
		t.Fatalf("应检出类型差异，实际: %v", diffs)
	}
}

// fakeConsole 模拟一侧控制台：登录成功后必须带 Cookie 才能读取接口。
func fakeConsole(loginOK bool, overview string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if !loginOK {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"error":"用户名或密码错误"}`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "s1", Path: "/", HttpOnly: true})
		_, _ = w.Write([]byte(`{"ok":true,"user":{"id":1,"username":"admin","role":"admin","mustChange":false}}`))
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("JSESSIONID"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"error":"未登录或会话已过期"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"user":{"id":1,"username":"admin","role":"admin","mustChange":false}}`))
	})
	mux.HandleFunc("/api/stats/overview", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(overview))
	})
	return mux
}

func TestLoginAndAnonymousCompare(t *testing.T) {
	java, _ := newStack(t, "java", fakeConsole(true, `{"ok":true,"data":{"sessions":1}}`))
	goStack, _ := newStack(t, "go", fakeConsole(true, `{"ok":true,"data":{"sessions":2}}`))

	// 未登录态：两侧都是 401 同构包络
	diffs, err := CompareAnonymous(java, goStack)
	if err != nil {
		t.Fatalf("未登录态比对失败: %v", err)
	}
	if len(diffs) != 0 {
		t.Fatalf("未登录态应一致，实际: %v", diffs)
	}

	if err := java.Login("admin", "admin123"); err != nil {
		t.Fatalf("java 登录失败: %v", err)
	}
	if err := goStack.Login("admin", "admin123"); err != nil {
		t.Fatalf("go 登录失败: %v", err)
	}

	// 登录后同结构、不同取值：不算差异
	ep := Endpoint{Method: http.MethodGet, Path: "/api/stats/overview"}
	diffs, err = CompareEndpoint(java, goStack, ep)
	if err != nil {
		t.Fatalf("比对失败: %v", err)
	}
	if len(diffs) != 0 {
		t.Fatalf("取值不同但结构一致，不应有差异，实际: %v", diffs)
	}
}

func TestLoginFailure(t *testing.T) {
	bad, _ := newStack(t, "bad", fakeConsole(false, `{}`))
	if err := bad.Login("admin", "wrong"); err == nil {
		t.Fatal("登录失败应返回错误")
	} else if !strings.Contains(err.Error(), "登录失败") {
		t.Fatalf("错误信息应包含登录失败提示，实际: %v", err)
	}
}

func TestCompareEndpointDetectsDifferences(t *testing.T) {
	java, _ := newStack(t, "java", fakeConsole(true, `{"ok":true,"data":{"sessions":1,"ips":3}}`))
	goStack, _ := newStack(t, "go", fakeConsole(true, `{"ok":true,"data":{"sessions":"2"}}`))

	if err := java.Login("admin", "admin123"); err != nil {
		t.Fatalf("java 登录失败: %v", err)
	}
	if err := goStack.Login("admin", "admin123"); err != nil {
		t.Fatalf("go 登录失败: %v", err)
	}

	ep := Endpoint{Method: http.MethodGet, Path: "/api/stats/overview"}
	diffs, err := CompareEndpoint(java, goStack, ep)
	if err != nil {
		t.Fatalf("比对失败: %v", err)
	}
	joined := strings.Join(diffs, "\n")
	for _, want := range []string{
		"字段 data.sessions 类型不同：java=number go=string",
		"字段 data.ips：仅 Java 返回（number）",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少预期差异 %q，实际:\n%s", want, joined)
		}
	}
}

func TestCompareEndpointDetectsStatusDifference(t *testing.T) {
	jh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	gh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	java, _ := newStack(t, "java", jh)
	goStack, _ := newStack(t, "go", gh)

	diffs, err := CompareEndpoint(java, goStack, Endpoint{Method: http.MethodGet, Path: "/api/me"})
	if err != nil {
		t.Fatalf("比对失败: %v", err)
	}
	if len(diffs) != 1 || !strings.Contains(diffs[0], "状态码不同：java=200 go=500") {
		t.Fatalf("应检出状态码差异，实际: %v", diffs)
	}
}

func TestReadEndpointsCoverContract(t *testing.T) {
	// 只读接口清单必须包含会话生命周期与全部 GET（16 GET + logout）
	if len(ReadEndpoints) != 17 {
		t.Fatalf("只读接口应为 17 条（16 GET + logout），实际 %d", len(ReadEndpoints))
	}
	// 写接口 5 条：合计 22 条 + 登录（由 Login 单独调用）= 计划附录 A 的 23 条
	if len(MutatingEndpoints) != 5 {
		t.Fatalf("写接口应为 5 条，实际 %d", len(MutatingEndpoints))
	}
}

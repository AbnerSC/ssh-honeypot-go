package conformance

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Endpoint 一条待比对的 HTTP 接口。
type Endpoint struct {
	Method string
	Path   string // 含查询串，如 /api/stats/trend?days=14
	Body   string // 请求体 JSON 原文，GET 为空
	Desc   string // 中文说明，输出用
}

// ReadEndpoints 只读接口（含会话生命周期）：可安全反复调用，双栈响应结构必须一致。
// 覆盖计划附录 A 中除写接口外的 18 条（16 个 GET + login/logout）。
var ReadEndpoints = []Endpoint{
	{Method: http.MethodGet, Path: "/api/me", Desc: "当前登录用户"},
	{Method: http.MethodGet, Path: "/api/stats/overview", Desc: "总览指标"},
	{Method: http.MethodGet, Path: "/api/stats/trend?days=14", Desc: "趋势"},
	{Method: http.MethodGet, Path: "/api/stats/protocol", Desc: "协议分布"},
	{Method: http.MethodGet, Path: "/api/stats/top-ips?limit=10", Desc: "Top IP"},
	{Method: http.MethodGet, Path: "/api/stats/top-locations?limit=10", Desc: "Top 归属地"},
	{Method: http.MethodGet, Path: "/api/stats/top-usernames?limit=10", Desc: "Top 用户名"},
	{Method: http.MethodGet, Path: "/api/stats/top-passwords?limit=10", Desc: "Top 口令"},
	{Method: http.MethodGet, Path: "/api/sessions?page=1&size=10", Desc: "会话明细"},
	{Method: http.MethodGet, Path: "/api/auth-attempts?page=1&size=10", Desc: "登录尝试"},
	{Method: http.MethodGet, Path: "/api/commands?page=1&size=10", Desc: "命令明细"},
	{Method: http.MethodGet, Path: "/api/downloads?page=1&size=10", Desc: "恶意下载"},
	{Method: http.MethodGet, Path: "/api/ip-locks?page=1&size=10", Desc: "IP 锁定"},
	{Method: http.MethodGet, Path: "/api/audit-logs?page=1&size=10", Desc: "审计日志"},
	{Method: http.MethodGet, Path: "/api/audit-logs/trend?days=14", Desc: "审计趋势"},
	{Method: http.MethodGet, Path: "/api/users", Desc: "系统用户清单"},
	{Method: http.MethodPost, Path: "/api/logout", Desc: "登出"},
}

// MutatingEndpoints 写接口（改密、增删用户）：会改变线上状态且需要真实用户 ID，
// 默认不参与比对；仅当显式开启「升级演练」时才手工执行。
var MutatingEndpoints = []Endpoint{
	{Method: http.MethodPut, Path: "/api/password", Desc: "修改自己的口令"},
	{Method: http.MethodPost, Path: "/api/users", Desc: "创建用户"},
	{Method: http.MethodPut, Path: "/api/users/{id}/status", Desc: "启用/禁用用户"},
	{Method: http.MethodPut, Path: "/api/users/{id}/password", Desc: "重置用户口令"},
	{Method: http.MethodDelete, Path: "/api/users/{id}", Desc: "删除用户"},
}

// Stack 一侧（Java 或 Go）的控制台客户端，自带 Cookie Jar 以保持会话。
type Stack struct {
	Name   string
	Base   string
	client *http.Client
}

// NewStack 创建客户端；base 形如 http://127.0.0.1:8080。
// 自建环境常用自签名证书的 nginx 反代，故跳过证书校验（仅本机/内网对比用途）。
func NewStack(name, base string) (*Stack, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%s 地址无效：%q（需形如 http://127.0.0.1:8080）", name, base)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 %s Cookie Jar 失败: %w", name, err)
	}
	return &Stack{
		Name: name,
		Base: strings.TrimRight(base, "/"),
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 内网自签名证书
			},
		},
	}, nil
}

// Do 发起一次请求，返回状态码与原始响应体（上限 4MB）。
func (s *Stack) Do(method, path, body string) (int, []byte, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.Base+path, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s %s 构造请求失败: %w", s.Name, method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s %s 请求失败: %w", s.Name, method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s %s %s 读取响应失败: %w", s.Name, method, path, err)
	}
	return resp.StatusCode, raw, nil
}

// Login 登录并保存会话 Cookie；双侧账号须预先存在且不需要强制改密。
func (s *Stack) Login(user, pass string) error {
	payload, err := json.Marshal(map[string]string{"username": user, "password": pass})
	if err != nil {
		return err
	}
	status, raw, err := s.Do(http.MethodPost, "/api/login", string(payload))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("%s 登录失败：HTTP %d %s", s.Name, status, snippet(raw))
	}
	var env struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s 登录响应不是 JSON：%s", s.Name, snippet(raw))
	}
	if !env.OK {
		return fmt.Errorf("%s 登录失败：%s", s.Name, snippet(raw))
	}
	return nil
}

// Shape 把响应体拍平成「路径 -> 类型」，用于结构比对。
// 数组按元素采样并加 [] 后缀；空数组记为 array<unknown>，比较时视作通配。
func Shape(raw []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("响应不是合法 JSON：%s", snippet(raw))
	}
	out := map[string]string{}
	flattenShape("", v, out)
	return out, nil
}

func flattenShape(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[prefix] = "object"
			return
		}
		for k, vv := range t {
			flattenShape(joinPath(prefix, k), vv, out)
		}
	case []any:
		if len(t) == 0 {
			out[prefix+"[]"] = "array<unknown>"
			return
		}
		for _, item := range t {
			flattenShape(prefix+"[]", item, out)
		}
	default:
		out[prefix] = valueType(v)
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func valueType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "bool"
	default:
		return "unknown"
	}
}

// DiffShapes 比对两份形状，返回人类可读的差异清单。
func DiffShapes(java, goShape map[string]string) []string {
	var diffs []string
	for _, path := range unionKeys(java, goShape) {
		jt, jok := java[path]
		gt, gok := goShape[path]
		switch {
		case !gok:
			if coveredBySparse(jt, goShape, path) {
				continue
			}
			diffs = append(diffs, fmt.Sprintf("字段 %s：仅 Java 返回（%s）", path, jt))
		case !jok:
			if coveredBySparse(gt, java, path) {
				continue
			}
			diffs = append(diffs, fmt.Sprintf("字段 %s：仅 Go 返回（%s）", path, gt))
		case !compatibleTypes(jt, gt):
			diffs = append(diffs, fmt.Sprintf("字段 %s 类型不同：java=%s go=%s", path, jt, gt))
		}
	}
	sort.Strings(diffs)
	return diffs
}

// coveredBySparse 判断缺失路径能否用「一侧为空数组/空对象」的采样缺口解释：
//
//   - 本侧在该路径上记的是空数组/空对象（array<unknown> / object），而对侧在同一前缀下有采样字段；
//   - 对侧在更浅一层已记为空数组/空对象，因此自然不会有更深的采样字段。
//
// 一侧数据库为空（如全新库）时数组无元素可采样，形状必然对不上，不应算作契约差异。
func coveredBySparse(ownType string, other map[string]string, path string) bool {
	if isSparse(ownType) {
		for p := range other {
			if strings.HasPrefix(p, path+".") {
				return true
			}
		}
	}
	for p, typ := range other {
		if isSparse(typ) && strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}

// isSparse 空数组/空对象在形状里只留下类型标记，属于采样缺口。
func isSparse(typ string) bool {
	return typ == "array<unknown>" || typ == "object"
}

// compatibleTypes 空数组/空对象会让采样类型缺失，这类差异不算契约差异。
func compatibleTypes(a, b string) bool {
	if a == b {
		return true
	}
	wildcard := func(s string) bool {
		return s == "array<unknown>" || s == "object" || s == "null"
	}
	return wildcard(a) || wildcard(b)
}

// CompareEndpoint 请求双侧的同一接口并比对状态码与响应结构。
func CompareEndpoint(java, goStack *Stack, ep Endpoint) ([]string, error) {
	label := fmt.Sprintf("%s %s", ep.Method, ep.Path)

	js, jraw, err := java.Do(ep.Method, ep.Path, ep.Body)
	if err != nil {
		return nil, err
	}
	gs, graw, err := goStack.Do(ep.Method, ep.Path, ep.Body)
	if err != nil {
		return nil, err
	}

	var diffs []string
	if js != gs {
		diffs = append(diffs, fmt.Sprintf("%s 状态码不同：java=%d go=%d", label, js, gs))
	}
	jshape, err := Shape(jraw)
	if err != nil {
		return nil, fmt.Errorf("%s 的 Java 侧响应异常：%w", label, err)
	}
	gshape, err := Shape(graw)
	if err != nil {
		return nil, fmt.Errorf("%s 的 Go 侧响应异常：%w", label, err)
	}
	for _, d := range DiffShapes(jshape, gshape) {
		diffs = append(diffs, label+" "+d)
	}
	return diffs, nil
}

// CompareAnonymous 比对未登录态：双侧都必须拒绝并返回同构的 401 包络。
func CompareAnonymous(java, goStack *Stack) ([]string, error) {
	return CompareEndpoint(java, goStack, Endpoint{Method: http.MethodGet, Path: "/api/me", Desc: "未登录态"})
}

// snippet 截断响应体，避免把整页 HTML 刷到终端。
func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		return "(空响应)"
	}
	return s
}

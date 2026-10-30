package web

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// forwardedHeaders 常见代理附加头，按优先级排列。
var forwardedHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP",
}

// ClientIPResolver 按「受信反向代理」白名单解析请求来源 IP。
//
// 安全模型：转发头只能由受信代理写入，客户端可任意伪造，因此仅在直连地址
// 命中 trustedProxies（CIDR）时才读取转发头；白名单为空（默认）时任何转发头
// 都不被采信，ClientIP 恒等于 TCP 连接的对端地址。这样即使蜜罐部署在
// Docker/内网环境中（直连地址看起来是私网网关），攻击者也无法通过伪造
// X-Forwarded-For 绕过登录锁定或伪造审计来源。
type ClientIPResolver struct {
	trusted []*net.IPNet
}

// NewClientIPResolver 编译受信代理网段；非法条目直接报错（配置期失败优于运行期静默）。
// 支持裸 IP（自动补全 /32 或 /128）与 CIDR 两种写法。
func NewClientIPResolver(cidrs []string) (*ClientIPResolver, error) {
	r := &ClientIPResolver{}
	for _, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(strings.Trim(s, "[]"))
			if ip == nil {
				return nil, fmt.Errorf("非法的受信代理地址: %q", raw)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			s = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("非法的受信代理网段 %q: %w", raw, err)
		}
		r.trusted = append(r.trusted, ipnet)
	}
	return r, nil
}

// Resolve 解析来源 IP：直连地址不在受信代理网段时直接返回直连地址。
func (r *ClientIPResolver) Resolve(req *http.Request) string {
	direct := normalizeIP(stripPort(req.RemoteAddr))
	if r == nil || !r.isTrusted(direct) {
		return direct
	}
	for _, header := range forwardedHeaders {
		if ip := firstMeaningful(req.Header.Get(header)); ip != "" {
			return ip
		}
	}
	return direct
}

// isTrusted 判断直连地址是否命中受信代理网段。
func (r *ClientIPResolver) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range r.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ClientIP 兼容入口：不信任任何转发头，等价于未配置受信代理。
// 生产路径请使用 Server 持有的 ClientIPResolver。
func ClientIP(r *http.Request) string {
	return normalizeIP(stripPort(r.RemoteAddr))
}

// normalizeIP 把 IPv4-mapped IPv6（如 ::ffff:172.20.0.1）还原为 IPv4，
// 并去掉可能残留的方括号；无法解析的地址原样返回。
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	ip = strings.Trim(ip, "[]")
	if !strings.Contains(ip, ":") {
		return ip
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ip
}

// stripPort 去掉 IPv4 / 带方括号 IPv6 携带的端口；纯 IPv6 字面量原样返回。
func stripPort(s string) string {
	s = strings.TrimSpace(s)
	if host, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(s, "[]")
}

// firstMeaningful 从 X-Forwarded-For 类链路中取首个合法 IP；优先公网，全内网时取首个内网段。
func firstMeaningful(headerValue string) string {
	if strings.TrimSpace(headerValue) == "" {
		return ""
	}
	firstPrivate := ""
	for _, part := range strings.Split(headerValue, ",") {
		ip := normalizeIP(stripPort(part))
		if !isLegalIP(ip) {
			continue
		}
		if !isPrivateOrLoopback(ip) {
			return ip
		}
		if firstPrivate == "" {
			firstPrivate = ip
		}
	}
	return firstPrivate
}

// isLegalIP 校验合法 IP（IPv4 点分十进制 / IPv6 冒号十六进制）。
func isLegalIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isPrivateOrLoopback 识别私网 / 环回 / 链路本地 / 未指定地址。
func isPrivateOrLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
		return true
	}
	// 0.0.0.0/8 与 Java 版 a == 0 判定保持一致
	if v4 := parsed.To4(); v4 != nil && v4[0] == 0 {
		return true
	}
	return false
}

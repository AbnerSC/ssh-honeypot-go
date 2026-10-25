package web

import (
	"net"
	"net/http"
	"strings"
)

// forwardedHeaders 常见代理附加头，按优先级排列。
var forwardedHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP",
}

// ClientIP 解析请求来源的真实客户端 IP（代理感知）。
//
// 仅当直连地址为私网/环回（判定存在本机前置代理）时才信任转发头，
// 避免公网直连请求伪造 X-Forwarded-For 干扰审计与登录锁定；
// 多级代理时取转发链首个公网 IP（链上全为内网时取首个内网 IP）。
func ClientIP(r *http.Request) string {
	direct := normalizeIP(stripPort(r.RemoteAddr))
	if !isPrivateOrLoopback(direct) {
		return direct // 公网直连，不信任任何转发头
	}
	for _, header := range forwardedHeaders {
		if ip := firstMeaningful(r.Header.Get(header)); ip != "" {
			return ip
		}
	}
	return direct // 无转发头时退回直连地址
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

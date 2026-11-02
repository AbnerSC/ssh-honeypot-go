package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"ssh-honeypot-go/internal/config"
)

// healthDialTimeout 单端口探测超时：健康检查总耗时必须远小于容器探针 timeout。
const healthDialTimeout = 2 * time.Second

// healthTarget 一个待探测的监听地址。
type healthTarget struct {
	name string
	addr string
}

// runHealth 探测主监听端口并返回退出码（0 健康 / 1 异常），供镜像 HEALTHCHECK 使用。
//
// 优先探测 Web（与存量 compose 的 `curl -f http://127.0.0.1:8080` 等价），
// 未启用时依次回退 SSH / Telnet / MySQL / PostgreSQL / Redis；
// 全部协议都未启用时恒为健康。
func runHealth(cfg *config.Config) int {
	target, ok := primaryHealthTarget(cfg)
	if !ok {
		return 0
	}
	conn, err := net.DialTimeout("tcp", target.addr, healthDialTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "健康检查失败: %s (%s) 不可达: %v\n", target.name, target.addr, err)
		return 1
	}
	_ = conn.Close()
	return 0
}

// primaryHealthTarget 按 Web → SSH → Telnet → MySQL → PostgreSQL → Redis 顺序取第一个启用的监听。
func primaryHealthTarget(cfg *config.Config) (healthTarget, bool) {
	candidates := []struct {
		name    string
		service config.Service
	}{
		{"Web", cfg.Web.Service()},
		{"SSH", cfg.SSH},
		{"Telnet", cfg.Telnet},
		{"MySQL", cfg.MySQL},
		{"PostgreSQL", cfg.PostgreSQL},
		{"Redis", cfg.Redis},
	}
	for _, c := range candidates {
		if c.service.Enabled && c.service.Port > 0 {
			return healthTarget{
				name: c.name,
				addr: net.JoinHostPort("127.0.0.1", fmt.Sprint(c.service.Port)),
			}, true
		}
	}
	return healthTarget{}, false
}

// summarizeServices 生成启动摘要中的协议端口描述，关闭的协议显示「关闭」。
func summarizeServices(cfg *config.Config) string {
	part := func(s config.Service) string {
		if s.Enabled {
			return fmt.Sprint(s.Port)
		}
		return "关闭"
	}
	web := "关闭"
	if cfg.Web.Enabled {
		web = fmt.Sprint(cfg.Web.Port)
	}
	return strings.Join([]string{
		"SSH=" + part(cfg.SSH),
		"Telnet=" + part(cfg.Telnet),
		"MySQL=" + part(cfg.MySQL),
		"PostgreSQL=" + part(cfg.PostgreSQL),
		"Redis=" + part(cfg.Redis),
		"Web=" + web,
	}, ", ")
}

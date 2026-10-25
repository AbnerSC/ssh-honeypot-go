// Package auth 凭证守卫：基于内存密码本校验登录凭证，并对连续失败的源 IP 实施临时锁定。
//
// 规则与 Java 版 org.open.scdm.honeypot.auth.CredentialGuard 一致：
//   - 只有密码本中的「用户名/密码」组合才允许登录成功，不再全部放行
//   - 每个账号可配置多个密码，命中任意一个即视为登录成功
//   - 同一源 IP 在可配置时间窗口（默认 5 分钟）内连续登录失败达到阈值（默认 3 次）后锁定
//   - 两次失败间隔超过窗口则失败计数重置，不再累计；登录成功会清零该 IP 的失败计数
//   - 失败计数与锁定状态全部缓存在内存中，进程重启后清空
package auth

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/attacklog"
)

// sweepInterval 过期条目清扫周期，防止只失败一次就消失的 IP 残留导致 Map 无限增长。
const sweepInterval = time.Minute

// Guard 凭证守卫。
type Guard struct {
	mu          sync.Mutex
	credentials map[string][]string
	maxFailures int
	window      time.Duration
	lockFor     time.Duration
	events      *attacklog.Logger
	logger      *slog.Logger

	// failCounts IP -> 连续失败次数
	failCounts map[string]int
	// lastFailAt IP -> 最近一次失败时间戳（毫秒），用于判断窗口是否过期
	lastFailAt map[string]int64
	// lockedUntil IP -> 锁定截止时间戳（毫秒）
	lockedUntil map[string]int64
	lastSweepAt int64
}

// New 构造凭证守卫。maxFailures/windowMinutes/lockMinutes 小于 1 时按 1 处理。
//
// events 可为 nil（例如单元测试）；此时锁定事件不落盘，仅输出日志。
func New(credentials map[string][]string, maxFailures, windowMinutes, lockMinutes int,
	events *attacklog.Logger, logger *slog.Logger) *Guard {

	normalized := make(map[string][]string, len(credentials))
	passwords := 0
	for user, pwds := range credentials {
		cp := make([]string, len(pwds))
		copy(cp, pwds)
		normalized[user] = cp
		passwords += len(cp)
	}

	g := &Guard{
		credentials: normalized,
		maxFailures: maxInt(1, maxFailures),
		window:      time.Duration(maxInt(1, windowMinutes)) * time.Minute,
		lockFor:     time.Duration(maxInt(1, lockMinutes)) * time.Minute,
		events:      events,
		logger:      logger,
		failCounts:  make(map[string]int),
		lastFailAt:  make(map[string]int64),
		lockedUntil: make(map[string]int64),
		lastSweepAt: time.Now().UnixMilli(),
	}

	infof(logger, fmt.Sprintf("密码本已加载，共 %d 个账号、%d 条密码；%d 分钟内连续失败 %d 次锁定 %d 分钟",
		len(normalized), passwords, maxInt(1, windowMinutes), g.maxFailures, maxInt(1, lockMinutes)))
	return g
}

// MaxFailures 连续失败阈值（Telnet 侧用作单连接允许的最大尝试次数）。
func (g *Guard) MaxFailures() int {
	if g == nil {
		return 1
	}
	return g.maxFailures
}

// IsLocked 该 IP 是否处于锁定状态（锁定过期自动解除）。
func (g *Guard) IsLocked(ip string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.isLockedLocked(ip, time.Now().UnixMilli())
}

// Authenticate 校验登录凭证并维护失败计数。
//
// 已锁定的 IP 直接拒绝；窗口外的失败会重置计数，窗口内累计失败达到阈值后立即锁定
// 并记录 ip_locked 事件。
func (g *Guard) Authenticate(ip, username, password string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UnixMilli()
	g.sweepExpiredLocked(now)
	if g.isLockedLocked(ip, now) {
		return false
	}

	ok := false
	for _, pwd := range g.credentials[username] {
		if pwd == password {
			ok = true
			break
		}
	}
	if ok {
		delete(g.failCounts, ip)
		delete(g.lastFailAt, ip)
		return true
	}
	g.countFailureLocked(ip, now)
	return false
}

// RecordFailure 记录一次认证失败并按窗口累计，达到阈值即锁定源 IP。
//
// 供 SSH 公钥认证等无密码校验路径复用，防止攻击者换认证方式绕过失败锁定策略。
func (g *Guard) RecordFailure(ip string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UnixMilli()
	g.sweepExpiredLocked(now)
	if g.isLockedLocked(ip, now) {
		return
	}
	g.countFailureLocked(ip, now)
}

// isLockedLocked 判断锁定状态并清理已过期的锁定条目（调用方需持锁）。
func (g *Guard) isLockedLocked(ip string, now int64) bool {
	until, ok := g.lockedUntil[ip]
	if !ok {
		return false
	}
	if now >= until {
		delete(g.lockedUntil, ip)
		delete(g.failCounts, ip)
		delete(g.lastFailAt, ip)
		return false
	}
	return true
}

// countFailureLocked 窗口内累计失败计数并触发锁定（调用方需已确认未锁定）。
func (g *Guard) countFailureLocked(ip string, now int64) {
	// 距上次失败已超过窗口，则视为新的一轮，重置计数
	if prev, ok := g.lastFailAt[ip]; ok && now-prev > g.window.Milliseconds() {
		delete(g.failCounts, ip)
	}
	g.failCounts[ip]++
	n := g.failCounts[ip]
	g.lastFailAt[ip] = now

	if n < g.maxFailures {
		return
	}
	until := now + g.lockFor.Milliseconds()
	g.lockedUntil[ip] = until
	delete(g.failCounts, ip)
	delete(g.lastFailAt, ip)
	infof(g.logger, fmt.Sprintf("源 IP %s 在 %d 分钟内连续登录失败 %d 次，锁定 %d 分钟",
		ip, g.window/time.Minute, n, g.lockFor/time.Minute))
	if g.events != nil {
		g.events.IPLocked(ip, until)
	}
}

// sweepExpiredLocked 分钟级清扫：移除失败计数窗口外与锁定已过期的 IP 条目（调用方需持锁）。
func (g *Guard) sweepExpiredLocked(now int64) {
	if now-g.lastSweepAt < sweepInterval.Milliseconds() {
		return
	}
	g.lastSweepAt = now
	for ip, t := range g.lastFailAt {
		if now-t > g.window.Milliseconds() {
			delete(g.lastFailAt, ip)
			delete(g.failCounts, ip)
		}
	}
	for ip, until := range g.lockedUntil {
		if now >= until {
			delete(g.lockedUntil, ip)
			delete(g.failCounts, ip)
			delete(g.lastFailAt, ip)
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func infof(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Info(msg)
	}
}

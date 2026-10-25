package web

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Web 控制台登录失败防护参数（独立于蜜罐的源 IP 锁定策略）。
const (
	loginMaxAttempts       = 5
	loginLockDuration      = 15 * time.Minute
	loginMaxFailureRecords = 65536           // 失败记录表容量上限，防伪造海量来源 IP 撑爆内存
	loginCleanupInterval   = 5 * time.Minute // 过期记录惰性清理最小间隔
)

// loginFailure 单个来源 IP 的失败计数与锁定截止时间。
type loginFailure struct {
	count int
	until time.Time
}

// Auth 控制台认证服务：口令校验 + 登录失败锁定（内存态，重启清零）。
type Auth struct {
	users  *UserRepo
	logger *slog.Logger

	mu          sync.Mutex
	failures    map[string]*loginFailure
	lastCleanup time.Time
}

func newAuth(users *UserRepo, logger *slog.Logger) *Auth {
	return &Auth{
		users:       users,
		logger:      logger,
		failures:    make(map[string]*loginFailure, 64),
		lastCleanup: time.Now(),
	}
}

// loginResult 登录结果：成功带用户信息，失败带错误描述（对应 HTTP 401）。
type loginResult struct {
	User *User
	Err  string
}

// login 校验用户名/口令。成功返回用户信息（不含哈希）并记录登录时间；
// 失败返回错误描述（IP 锁定 / 用户名或密码错误）。
func (a *Auth) login(ip, username, password string) (*loginResult, error) {
	if locked, wait := a.locked(ip); locked {
		return &loginResult{Err: fmt.Sprintf("连续登录失败次数过多，该来源 IP 已锁定，请 %d 分钟后重试", wait)}, nil
	}

	user, err := a.users.findByUsername(strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	if user == nil || !user.Enabled || !verifyPassword(password, user.PasswordHash) {
		a.recordFailure(ip)
		if a.logger != nil {
			a.logger.Warn(fmt.Sprintf("Web 控制台登录失败: ip=%s user=%s", ip, username))
		}
		return &loginResult{Err: "用户名或密码错误"}, nil
	}

	a.clearFailure(ip)
	if err := a.users.recordLogin(user.ID); err != nil {
		return nil, err
	}
	return &loginResult{User: &user.User}, nil
}

// locked 判断来源 IP 是否仍在锁定期内；wait 为剩余等待分钟数（向上取整）。
func (a *Auth) locked(ip string) (bool, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.failures[ip]
	if !ok || rec.count < loginMaxAttempts {
		return false, 0
	}
	now := time.Now()
	if now.Before(rec.until) {
		wait := int((rec.until.Sub(now) + 59*time.Second) / time.Minute)
		if wait < 1 {
			wait = 1
		}
		return true, wait
	}
	delete(a.failures, ip)
	return false, 0
}

// recordFailure 记录一次登录失败：计数 +1 或开启新窗口；表满时仅对已有记录的 IP 继续计数。
func (a *Auth) recordFailure(ip string) {
	a.mu.Lock()
	rec, exists := a.failures[ip]
	if !exists && len(a.failures) >= loginMaxFailureRecords {
		a.mu.Unlock() // 记录表已满且无该 IP 条目：放弃计数，仅影响锁定精度，不影响认证正确性
		return
	}
	now := time.Now()
	if !exists || !now.Before(rec.until) {
		a.failures[ip] = &loginFailure{count: 1, until: now.Add(loginLockDuration)}
	} else {
		rec.count++
	}
	a.mu.Unlock()

	a.cleanupExpired(now)
}

// clearFailure 登录成功后清除该 IP 的失败记录。
func (a *Auth) clearFailure(ip string) {
	a.mu.Lock()
	delete(a.failures, ip)
	a.mu.Unlock()
}

// cleanupExpired 惰性清理：间隔内至多执行一次，移除已过锁定窗口的记录。
func (a *Auth) cleanupExpired(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastCleanup) < loginCleanupInterval {
		return
	}
	a.lastCleanup = now
	for ip, rec := range a.failures {
		if !now.Before(rec.until) {
			delete(a.failures, ip)
		}
	}
}

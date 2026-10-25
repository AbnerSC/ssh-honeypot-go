package auth

import (
	"testing"
	"time"
)

func newTestGuard(maxFailures int) *Guard {
	return New(map[string][]string{
		"root":  {"123456", "toor"},
		"admin": {"admin123"},
	}, maxFailures, 5, 30, nil, nil)
}

func TestAuthenticatePasswordBook(t *testing.T) {
	g := newTestGuard(3)
	if !g.Authenticate("1.1.1.1", "root", "123456") {
		t.Fatal("密码本中的密码应放行")
	}
	if !g.Authenticate("1.1.1.1", "root", "toor") {
		t.Fatal("同账号多密码均应放行")
	}
	if g.Authenticate("1.1.1.1", "root", "wrong") {
		t.Fatal("密码本外的密码应拒绝")
	}
	if g.Authenticate("1.1.1.1", "nobody", "123456") {
		t.Fatal("密码本外的账号应拒绝")
	}
	if g.Authenticate("1.1.1.1", "", "") {
		t.Fatal("空用户名应拒绝")
	}
}

func TestLockAfterMaxFailures(t *testing.T) {
	g := newTestGuard(3)
	for i := 0; i < 2; i++ {
		if g.Authenticate("2.2.2.2", "root", "bad") {
			t.Fatal("错误密码不应放行")
		}
	}
	if g.IsLocked("2.2.2.2") {
		t.Fatal("未达阈值不应锁定")
	}
	if g.Authenticate("2.2.2.2", "root", "bad") {
		t.Fatal("第 3 次错误不应放行")
	}
	if !g.IsLocked("2.2.2.2") {
		t.Fatal("达到阈值应锁定")
	}
	// 锁定期间即使密码正确也拒绝
	if g.Authenticate("2.2.2.2", "root", "123456") {
		t.Fatal("锁定期间应拒绝正确密码")
	}
	// 其他 IP 不受影响
	if !g.Authenticate("3.3.3.3", "root", "123456") {
		t.Fatal("锁定应按 IP 隔离")
	}
	// RecordFailure 同样计入锁定（公钥认证路径）
	g2 := newTestGuard(2)
	g2.RecordFailure("4.4.4.4")
	if g2.IsLocked("4.4.4.4") {
		t.Fatal("单次失败不应锁定")
	}
	g2.RecordFailure("4.4.4.4")
	if !g2.IsLocked("4.4.4.4") {
		t.Fatal("公钥认证失败应计入锁定")
	}
}

func TestSuccessResetsFailureCount(t *testing.T) {
	g := newTestGuard(3)
	g.Authenticate("5.5.5.5", "root", "bad")
	g.Authenticate("5.5.5.5", "root", "bad")
	if !g.Authenticate("5.5.5.5", "root", "123456") {
		t.Fatal("正确密码应放行")
	}
	g.Authenticate("5.5.5.5", "root", "bad")
	g.Authenticate("5.5.5.5", "root", "bad")
	if g.IsLocked("5.5.5.5") {
		t.Fatal("登录成功应清零失败计数")
	}
}

func TestWindowAndLockExpiry(t *testing.T) {
	g := newTestGuard(2)
	now := time.Now().UnixMilli()

	// 窗口外的失败应重置计数：先记一次，再把它挪到 6 分钟前
	g.RecordFailure("6.6.6.6")
	g.lastFailAt["6.6.6.6"] = now - 6*60*1000
	g.RecordFailure("6.6.6.6")
	if g.IsLocked("6.6.6.6") {
		t.Fatal("窗口外的失败应重置计数，不应锁定")
	}

	// 锁定过期自动解除，且正确密码可再次登录
	g.RecordFailure("7.7.7.7")
	g.RecordFailure("7.7.7.7")
	if !g.IsLocked("7.7.7.7") {
		t.Fatal("应已锁定")
	}
	g.lockedUntil["7.7.7.7"] = now - 1000
	if g.IsLocked("7.7.7.7") {
		t.Fatal("锁定过期后应自动解除")
	}
	if !g.Authenticate("7.7.7.7", "root", "123456") {
		t.Fatal("解除锁定后应放行正确密码")
	}
}

func TestConstructorClampsAndReportsMaxFailures(t *testing.T) {
	g := New(map[string][]string{"root": {"x"}}, 0, 0, 0, nil, nil)
	if g.MaxFailures() != 1 {
		t.Fatalf("maxFailures 下限应为 1，实际 %d", g.MaxFailures())
	}
	if g == nil || g.window != time.Minute || g.lockFor != time.Minute {
		t.Fatal("窗口/锁定时长下限应为 1 分钟")
	}
	var nilGuard *Guard
	if nilGuard.IsLocked("1.1.1.1") || nilGuard.Authenticate("1.1.1.1", "root", "x") {
		t.Fatal("nil 守卫应安全返回 false")
	}
	if nilGuard.MaxFailures() != 1 {
		t.Fatal("nil 守卫 MaxFailures 应为 1")
	}
	nilGuard.RecordFailure("1.1.1.1") // 不应 panic
}

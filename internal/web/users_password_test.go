package web

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"unicode"
)

// withTestPasswordCleared 临时清空测试注入点，使 resolveDefaultAdminPassword 走环境变量/随机分支。
func withTestPasswordCleared(t *testing.T, fn func()) {
	t.Helper()
	saved := testDefaultAdminPassword
	testDefaultAdminPassword = ""
	t.Cleanup(func() { testDefaultAdminPassword = saved })
	fn()
}

// TestResolveDefaultAdminPasswordFromEnv 环境变量显式指定强口令时直接采用，并标记来自环境变量。
func TestResolveDefaultAdminPasswordFromEnv(t *testing.T) {
	withTestPasswordCleared(t, func() {
		t.Setenv(webAdminPasswordEnv, testDefaultAdminPasswordValue)
		r := &UserRepo{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		pwd, fromEnv := r.resolveDefaultAdminPassword()
		if !fromEnv {
			t.Fatalf("环境变量指定时应标记 fromEnv=true")
		}
		if pwd != testDefaultAdminPasswordValue {
			t.Fatalf("口令=%q，期望环境变量的 %q", pwd, testDefaultAdminPasswordValue)
		}
		// 环境变量指定时不得回显到 defaultAdminPassword（仅供随机口令打印使用）
		if defaultAdminPassword == testDefaultAdminPasswordValue {
			t.Fatalf("环境变量口令不应写入 defaultAdminPassword 日志变量")
		}
	})
}

// TestResolveDefaultAdminPasswordWeakEnvFallsBack 环境变量口令不满足强度策略时告警并回退随机生成。
func TestResolveDefaultAdminPasswordWeakEnvFallsBack(t *testing.T) {
	withTestPasswordCleared(t, func() {
		t.Setenv(webAdminPasswordEnv, "weak")
		r := &UserRepo{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		pwd, fromEnv := r.resolveDefaultAdminPassword()
		if fromEnv {
			t.Fatal("弱口令环境变量不应被采纳")
		}
		if pwd == "weak" || checkPassword(pwd) != "" {
			t.Fatalf("应回退为满足策略的随机口令，实际 %q", pwd)
		}
	})
}

// TestResolveDefaultAdminPasswordBlankEnv "未设置/空白视为未配置"，与项目 envValue 语义一致，回退随机。
func TestResolveDefaultAdminPasswordBlankEnv(t *testing.T) {
	withTestPasswordCleared(t, func() {
		t.Setenv(webAdminPasswordEnv, "   ")
		r := &UserRepo{}
		pwd, fromEnv := r.resolveDefaultAdminPassword()
		if fromEnv || checkPassword(pwd) != "" {
			t.Fatalf("空白环境变量应回退随机口令，实际 fromEnv=%v pwd=%q", fromEnv, pwd)
		}
	})
}

// TestGenerateDefaultAdminPassword 随机初始管理员口令：长度达标、四类字符全覆盖、
// 仅使用约定字符集、且每次生成结果互不相同。
func TestGenerateDefaultAdminPassword(t *testing.T) {
	const samples = 200
	seen := make(map[string]bool, samples)
	alphabet := pwdUpperPool + pwdLowerPool + pwdDigitPool + pwdSymbolPool

	for i := 0; i < samples; i++ {
		pwd, err := generateDefaultAdminPassword()
		if err != nil {
			t.Fatalf("生成初始口令失败: %v", err)
		}
		if len(pwd) != defaultAdminPasswordLength {
			t.Fatalf("口令长度=%d，期望 %d（%q）", len(pwd), defaultAdminPasswordLength, pwd)
		}
		if msg := checkPassword(pwd); msg != "" {
			t.Fatalf("口令不满足强度策略: %q -> %s", pwd, msg)
		}
		if got := passwordClassCount(pwd); got != 4 {
			t.Fatalf("口令字符种类=%d，期望四类全覆盖: %q", got, pwd)
		}
		for _, r := range pwd {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("口令包含字符集之外的字符 %q: %q", r, pwd)
			}
		}
		if seen[pwd] {
			t.Fatalf("两次生成出口令相同，随机性不足: %q", pwd)
		}
		seen[pwd] = true
	}
}

// TestDefaultAdminPasswordShuffled 校验首位字符类型分布：
// 若未洗牌，前四位固定按字符池顺序出现，可作为口令的先验结构被利用。
func TestDefaultAdminPasswordShuffled(t *testing.T) {
	var upperFirst, symbolFirst int
	for i := 0; i < 300; i++ {
		pwd, err := generateDefaultAdminPassword()
		if err != nil {
			t.Fatalf("生成初始口令失败: %v", err)
		}
		r := rune(pwd[0])
		switch {
		case unicode.IsUpper(r):
			upperFirst++
		case !unicode.IsLower(r) && !unicode.IsDigit(r):
			symbolFirst++
		}
	}
	if upperFirst == 300 || symbolFirst == 300 {
		t.Fatalf("口令首位出现单一类型固化：upper=%d symbol=%d", upperFirst, symbolFirst)
	}
	if upperFirst == 0 && symbolFirst == 0 {
		t.Fatalf("洗牌未生效，首位始终为同一字符池")
	}
}

// TestRandIndex 随机下标必须落在 [0, n) 内，非法范围报错。
func TestRandIndex(t *testing.T) {
	for _, n := range []int{1, 2, len(pwdDigitPool), len(pwdLowerPool), pwdAlphabetLen} {
		for i := 0; i < 50; i++ {
			idx, err := randIndex(n)
			if err != nil {
				t.Fatalf("randIndex(%d) 失败: %v", n, err)
			}
			if idx < 0 || idx >= n {
				t.Fatalf("randIndex(%d) 越界: %d", n, idx)
			}
		}
	}
	if _, err := randIndex(0); err == nil {
		t.Fatal("randIndex(0) 应返回错误")
	}
}

// TestAlphabetChar 下标到字符的映射必须覆盖四个字符池且不越界。
func TestAlphabetChar(t *testing.T) {
	alphabet := pwdUpperPool + pwdLowerPool + pwdDigitPool + pwdSymbolPool
	for idx := 0; idx < pwdAlphabetLen; idx++ {
		got := alphabetChar(idx)
		if !strings.ContainsRune(alphabet, rune(got)) {
			t.Fatalf("下标 %d 映射到集合外字符 %q", idx, got)
		}
	}
}

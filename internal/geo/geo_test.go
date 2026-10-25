package geo

import (
	"runtime"
	"testing"
)

// TestLoadKeepsMemorySmall 加载只应把向量索引（约 512KB/库）读入内存：
// 两个库合计 46MB，整库读入会带来数十 MB 的堆分配，回归时直接失败。
func TestLoadKeepsMemorySmall(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	l := Load(nil)
	defer l.Close()
	if !l.Available() {
		t.Fatal("内置 IP 库未能加载")
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("加载内置库累计分配 %d KB", allocated/1024)
	const limit = 12 << 20 // 12MB：远大于 2×512KB 索引，远小于 46MB 整库
	if allocated > limit {
		t.Fatalf("加载内置库累计分配 %d bytes（上限 %d），疑似整库读入内存", allocated, limit)
	}
}

func TestFormat(t *testing.T) {
	cases := map[string]string{
		"中国|0|广东省|深圳市|电信": "中国 广东省 深圳市",
		"中国|0|上海|上海|0":    "中国 上海",
		"中国|0|0|0|0":      "中国",
		"美国|0|0|0|Google": "美国",
		"0|0|0|0|0":       "",
		"":                "",
		"   ":             "",
		"中国|0|北京|北京市|联通|额外段":  "中国 北京 北京市",
		"中国|0| 广东省 | 深圳市 |电信": "中国 广东省 深圳市",
	}
	for in, want := range cases {
		if got := Format(in); got != want {
			t.Errorf("Format(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPrivate(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "127.0.0.1", "0.0.0.0", "169.254.1.1",
		"::1", "0:0:0:0:0:0:0:1", "::", "fd00::1", "fc00::1", "fe80::1",
	}
	for _, ip := range private {
		if !IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) = false, want true", ip)
		}
	}

	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "172.15.255.255",
		"192.169.0.1", "169.253.1.1", "2001:4860:4860::8888", "not-an-ip", "",
	}
	for _, ip := range public {
		if IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) = true, want false", ip)
		}
	}
}

// TestLocateWithBuiltinDB 用内置 xdb 验证真实解析结果（v4 + v6 + 内网）。
func TestLocateWithBuiltinDB(t *testing.T) {
	l := Load(nil)
	defer l.Close()

	if !l.Available() {
		t.Fatal("内置 IP 库未能加载")
	}

	if got := l.Locate("10.1.2.3"); got != PrivateLabel {
		t.Errorf("内网 IP = %q, want %q", got, PrivateLabel)
	}
	if got := l.Locate("127.0.0.1"); got != PrivateLabel {
		t.Errorf("环回 IP = %q, want %q", got, PrivateLabel)
	}
	if got := l.Locate(""); got != "" {
		t.Errorf("空 IP = %q, want 空串", got)
	}
	if got := l.Locate("bad-ip"); got != "" {
		t.Errorf("非法 IP = %q, want 空串", got)
	}

	// 公网 IPv4：库中应能解析出国家（不校验具体省份，避免库版本升级导致断言脆弱）
	loc := l.Locate("8.8.8.8")
	if loc == "" {
		t.Error("8.8.8.8 未解析出归属地")
	}
	t.Logf("8.8.8.8 -> %s", loc)

	// 缓存命中路径：第二次查询结果必须一致
	if again := l.Locate("8.8.8.8"); again != loc {
		t.Errorf("缓存结果不一致: %q != %q", again, loc)
	}

	// 公网 IPv6（Google DNS）
	if v6 := l.Locate("2001:4860:4860::8888"); v6 == "" {
		t.Error("IPv6 公网地址未解析出归属地")
	} else {
		t.Logf("2001:4860:4860::8888 -> %s", v6)
	}
}

// TestNilLocator 降级实例必须可安全调用。
func TestNilLocator(t *testing.T) {
	var l *Locator
	if l.Available() {
		t.Error("nil Locator 不应 Available")
	}
	if got := l.Locate("8.8.8.8"); got != "" {
		t.Errorf("nil Locator.Locate = %q, want 空串", got)
	}
	l.Close()

	empty := &Locator{}
	if empty.Available() {
		t.Error("空 Locator 不应 Available")
	}
	if got := empty.Locate("8.8.8.8"); got != "" {
		t.Errorf("空 Locator.Locate = %q, want 空串", got)
	}
}

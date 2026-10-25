package geo

import "testing"

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
	// 外部路径传空串，强制走内置库
	l := Load("", "", nil)
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

// TestLoadMissingExternalFallsBackBuiltin 外部路径不存在时应回退内置库。
func TestLoadMissingExternalFallsBackBuiltin(t *testing.T) {
	l := Load("/nonexistent/ip2region_v4.xdb", "/nonexistent/ip2region_v6.xdb", nil)
	defer l.Close()
	if !l.Available() {
		t.Fatal("外部库缺失时应回退内置库")
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

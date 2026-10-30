package shell

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/vfs"
)

// stubProcessor 把每条输入原样回显，便于断言行编辑行为。
type stubProcessor struct{}

func (stubProcessor) Execute(st *Session, line string) Output {
	switch line {
	case "exit":
		return Output{Exit: true}
	case "":
		return Output{}
	}
	return Output{Text: "OUT:" + line + "\n"}
}

func runShell(t *testing.T, input string) (string, *Session) {
	t.Helper()
	fs := vfs.New("svr01")
	st := NewSession("s1", "203.0.113.9", "root", fs, "svr01")
	var out bytes.Buffer
	sh := NewShell(strings.NewReader(input), &out, st, stubProcessor{}, nil, nil)
	sh.Run()
	return out.String(), st
}

func TestShellBannerAndPrompt(t *testing.T) {
	out, _ := runShell(t, "exit\r\n")
	if !strings.HasPrefix(out, banner) {
		t.Fatalf("输出应以登录横幅开头: %q", out)
	}
	if !strings.Contains(out, "root@svr01:~# ") {
		t.Fatalf("缺少提示符: %q", out)
	}
}

func TestShellEchoAndNewlineNormalization(t *testing.T) {
	out, _ := runShell(t, "hello\r\n")
	if !strings.Contains(out, "hello\r\nOUT:hello\r\n") {
		t.Fatalf("回显或输出换行不规范: %q", out)
	}
	if strings.Contains(out, "\r\r\n") {
		t.Fatalf("出现重复回车: %q", out)
	}

	// 只发 \n 也应正常执行
	out, _ = runShell(t, "hello\n")
	if !strings.Contains(out, "OUT:hello\r\n") {
		t.Fatalf("LF 结尾执行失败: %q", out)
	}
}

func TestShellBackspace(t *testing.T) {
	out, _ := runShell(t, "abX\b\rexit\r")
	if !strings.Contains(out, "OUT:ab\r\n") {
		t.Fatalf("退格未删除字符: %q", out)
	}
	if strings.Contains(out, "OUT:abX") {
		t.Fatalf("退格后仍包含被删字符: %q", out)
	}
}

func TestShellCtrlCAndCtrlD(t *testing.T) {
	out, _ := runShell(t, "abc\x03exit\r")
	if !strings.Contains(out, "^C\r\n") {
		t.Fatalf("Ctrl+C 应显示 ^C: %q", out)
	}
	if strings.Contains(out, "OUT:abc") {
		t.Fatalf("Ctrl+C 后不应执行当前行: %q", out)
	}

	// 空行 Ctrl+D = 登出：后续命令不再执行
	out, _ = runShell(t, "\x04OUT-AFTER\r")
	if strings.Contains(out, "OUT:OUT-AFTER") {
		t.Fatalf("Ctrl+D 应结束会话: %q", out)
	}
}

func TestShellHistoryNavigation(t *testing.T) {
	// 输入 one，然后上箭头回车再执行一次
	out, _ := runShell(t, "one\r\x1b[A\rexit\r")
	if got := strings.Count(out, "OUT:one\r\n"); got != 2 {
		t.Fatalf("历史导航应重复执行上一条命令，实际 %d 次: %q", got, out)
	}
}

// TestShellCommandLineLimit 超长输入必须截断到 maxCommandLine，
// 否则单会话内存与回显均可被无限放大（50 会话可成倍放大）。
func TestShellCommandLineLimit(t *testing.T) {
	long := strings.Repeat("A", maxCommandLine*2)
	out, _ := runShell(t, long+"\rexit\r")
	want := "OUT:" + strings.Repeat("A", maxCommandLine) + "\r\n"
	if !strings.Contains(out, want) {
		t.Fatalf("超长命令应截断到 %d 字节（实际输出 %d 字节）", maxCommandLine, len(out))
	}
}

// TestShellHistoryCapacity 历史表固定容量：常量数量的命令后不得无限增长。
func TestShellHistoryCapacity(t *testing.T) {
	st := NewSession("s1", "203.0.113.9", "root", vfs.New("svr01"), "svr01")
	sh := NewShell(strings.NewReader(""), io.Discard, st, stubProcessor{}, nil, nil)
	for i := 0; i < maxHistory+10; i++ {
		sh.pushHistory("cmd" + strconv.Itoa(i))
	}
	if len(sh.nav) != maxHistory {
		t.Fatalf("历史表长度 = %d, want %d", len(sh.nav), maxHistory)
	}
	if got := sh.nav[len(sh.nav)-1]; got != "cmd"+strconv.Itoa(maxHistory+9) {
		t.Fatalf("最新命令未保留: %q", got)
	}
	if got := sh.nav[0]; got != "cmd"+strconv.Itoa(10) {
		t.Fatalf("最旧命令应被挤出: %q", got)
	}
}

func TestSessionUserSanitizeAndPrompt(t *testing.T) {
	cases := map[string]string{
		"root":        "root",
		"admin":       "admin",
		"":            "nobody",
		"we ird/name": "we_ird_name",
		"a$b\\c":      "a_b_c",
		"..":          "..",
	}
	for in, want := range cases {
		if got := SanitizeUser(in); got != want {
			t.Errorf("SanitizeUser(%q)=%q, want %q", in, got, want)
		}
	}

	fs := vfs.New("svr01")
	st := NewSession("s1", "1.2.3.4", "ubuntu", fs, "svr01")
	if st.HomeDir != "/home/ubuntu" {
		t.Fatalf("普通用户主目录=%q", st.HomeDir)
	}
	if fs.Resolve("/", "/home/ubuntu") == nil {
		t.Fatal("应自动创建 /home/ubuntu")
	}
	if got := st.Prompt(); got != "ubuntu@svr01:~$ " {
		t.Fatalf("提示符=%q", got)
	}
	st.Cwd = "/home/ubuntu/project"
	if got := st.Prompt(); got != "ubuntu@svr01:~/project$ " {
		t.Fatalf("子目录提示符=%q", got)
	}
	st.Cwd = "/var/log"
	if got := st.Prompt(); got != "ubuntu@svr01:/var/log$ " {
		t.Fatalf("家目录外提示符=%q", got)
	}

	root := NewSession("s2", "1.2.3.4", "root", fs, "svr01")
	if got := root.Prompt(); got != "root@svr01:~# " {
		t.Fatalf("root 提示符=%q", got)
	}
}

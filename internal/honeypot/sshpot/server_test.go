package sshpot

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/attacklog"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/auth"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/shell/cmd"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/vfs"
)

type testEnv struct {
	server *Server
	addr   string
	events *attacklog.Logger
	guard  *auth.Guard
	logDir string
}

func newTestEnv(t *testing.T, maxFailures int) *testEnv {
	t.Helper()
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	events, err := attacklog.New(filepath.Join(logDir, "honeypot.jsonl"),
		filepath.Join(logDir, "database.db"), nil, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志失败: %v", err)
	}
	fs := vfs.New("svr01")
	guard := auth.New(map[string][]string{"root": {"123456"}}, maxFailures, 5, 30, events, logger)

	srv, err := New(Options{
		Addr:        "127.0.0.1:0",
		FS:          fs,
		Events:      events,
		Guard:       guard,
		Hostname:    "svr01",
		Processor:   cmd.New(events, "svr01"),
		Logger:      logger,
		HostKeyPath: filepath.Join(dir, "db", "hostkey.ser"),
	})
	if err != nil {
		t.Fatalf("构造 SSH 蜜罐失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 SSH 蜜罐失败: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = events.Close()
	})
	return &testEnv{server: srv, addr: srv.Addr(), events: events, guard: guard, logDir: logDir}
}

func clientConfig(password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

func TestBannerFingerprint(t *testing.T) {
	env := newTestEnv(t, 3)

	conn, err := net.Dial("tcp", env.addr)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("读取 banner 失败: %v", err)
	}
	if got := strings.TrimRight(line, "\r\n"); got != serverVersion {
		t.Fatalf("banner=%q, want %q", got, serverVersion)
	}
}

func TestExecAndEventLayering(t *testing.T) {
	env := newTestEnv(t, 3)

	client, err := ssh.Dial("tcp", env.addr, clientConfig("123456"))
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("exec 失败: %v", err)
	}
	if got := string(out); got != "root\n" {
		t.Fatalf("exec 输出=%q", got)
	}

	// 关闭日志后读取 JSONL，校验事件分层（ssh 认证 + ssh-exec 会话）
	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "ssh", "username": "root", "password": "123456", "success": "true",
	})
	assertHasEvent(t, events, "session_open", map[string]string{"protocol": "ssh"})
	assertHasEvent(t, events, "session_open", map[string]string{"protocol": "ssh-exec"})

	execSession := ""
	for _, ev := range events {
		if ev["event"] == "session_open" && ev["protocol"] == "ssh-exec" {
			execSession = ev["session"]
		}
	}
	if execSession == "" {
		t.Fatalf("缺少 ssh-exec 会话事件: %v", events)
	}
	assertHasEvent(t, events, "session_close", map[string]string{"session": execSession})
	assertHasEvent(t, events, "command", map[string]string{"command": "whoami", "session": execSession})
}

func TestShellSession(t *testing.T) {
	env := newTestEnv(t, 3)

	client, err := ssh.Dial("tcp", env.addr, clientConfig("123456"))
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	var outBuf bytes.Buffer
	sess.Stdout = &outBuf
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("获取 stdin 失败: %v", err)
	}
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("请求 pty 失败: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("启动 shell 失败: %v", err)
	}

	_, _ = stdin.Write([]byte("hello\r"))
	_, _ = stdin.Write([]byte("exit\r"))

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shell 会话未在 10s 内结束")
	}

	text := outBuf.String()
	if !strings.Contains(text, "root@svr01:~# ") {
		t.Fatalf("交互 shell 输出缺少提示符: %q", text)
	}
}

func TestPasswordLock(t *testing.T) {
	env := newTestEnv(t, 3)

	for i := 0; i < 3; i++ {
		if c, err := ssh.Dial("tcp", env.addr, clientConfig("bad")); err == nil {
			c.Close()
			t.Fatalf("第 %d 次错误密码不应登录成功", i+1)
		}
	}
	if _, err := ssh.Dial("tcp", env.addr, clientConfig("123456")); err == nil {
		t.Fatal("锁定期间正确密码也不应登录成功")
	}
	if !env.guard.IsLocked("127.0.0.1") {
		t.Fatal("连续失败后应锁定源 IP")
	}
}

// TestAuthSessionClosed 认证成功产生的 ssh 会话必须在连接结束后补 session_close，
// 否则 Web 端「在线会话」会随每次登录永久堆积（Java 版遗留缺陷）。
func TestAuthSessionClosed(t *testing.T) {
	env := newTestEnv(t, 5)

	client, err := ssh.Dial("tcp", env.addr, clientConfig("123456"))
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if _, err := sess.Output("whoami"); err != nil {
		t.Fatalf("exec 失败: %v", err)
	}
	_ = client.Close()

	// 给服务端一点时间处理断开并落盘
	time.Sleep(300 * time.Millisecond)
	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))

	authSessions := make([]string, 0, 2)
	for _, ev := range events {
		if ev["event"] == "session_open" && ev["protocol"] == "ssh" {
			authSessions = append(authSessions, ev["session"])
		}
	}
	if len(authSessions) == 0 {
		t.Fatal("缺少 ssh 认证会话事件")
	}
	for _, sid := range authSessions {
		assertHasEvent(t, events, "session_close", map[string]string{"session": sid})
	}
}

func readEvents(t *testing.T, path string) []map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 JSONL 失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]map[string]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		ev := make(map[string]string)
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("解析事件失败: %v (line=%s)", err, line)
		}
		out = append(out, ev)
	}
	return out
}

func assertHasEvent(t *testing.T, events []map[string]string, name string, fields map[string]string) {
	t.Helper()
	for _, ev := range events {
		if ev["event"] != name {
			continue
		}
		match := true
		for k, want := range fields {
			if ev[k] != want {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	t.Fatalf("未找到事件 %s %v\n实际事件: %v", name, fields, events)
}

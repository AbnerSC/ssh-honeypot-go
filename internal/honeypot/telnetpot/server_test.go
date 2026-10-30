package telnetpot

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	logDir := filepath.Join(t.TempDir(), "logs")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	events, err := attacklog.New(filepath.Join(logDir, "honeypot.jsonl"),
		filepath.Join(logDir, "database.db"), nil, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志失败: %v", err)
	}
	guard := auth.New(map[string][]string{"root": {"123456"}}, maxFailures, 5, 30, events, logger)

	srv, err := New(Options{
		Addr:      "127.0.0.1:0",
		FS:        vfs.New("svr01"),
		Events:    events,
		Guard:     guard,
		Hostname:  "svr01",
		Processor: cmd.New(events, "svr01"),
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("构造 Telnet 蜜罐失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 Telnet 蜜罐失败: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = events.Close()
	})
	return &testEnv{server: srv, addr: srv.Addr(), events: events, guard: guard, logDir: logDir}
}

// script 交互式客户端：保存未被消费的数据，避免跨断言丢包。
type script struct {
	t    *testing.T
	conn net.Conn
	buf  []byte
}

func dial(t *testing.T, addr string) (*script, func()) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	return &script{t: t, conn: conn}, func() { _ = conn.Close() }
}

// expect 等待输出中出现 needle，返回其之前（含）的全部数据，并消费到 needle 结尾。
func (s *script) expect(needle string) string {
	s.t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if i := bytes.Index(s.buf, []byte(needle)); i >= 0 {
			end := i + len(needle)
			out := string(s.buf[:end])
			s.buf = s.buf[end:]
			return out
		}
		chunk := make([]byte, 512)
		n, err := s.conn.Read(chunk)
		s.buf = append(s.buf, chunk[:n]...)
		if err != nil {
			s.t.Fatalf("等待 %q 失败: %q (err=%v)", needle, string(s.buf), err)
		}
	}
}

func (s *script) send(text string) {
	s.t.Helper()
	if _, err := s.conn.Write([]byte(text)); err != nil {
		s.t.Fatalf("发送 %q 失败: %v", text, err)
	}
}

// drain 读到连接关闭，返回剩余数据。
func (s *script) drain() string {
	_ = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	chunk := make([]byte, 512)
	for {
		n, err := s.conn.Read(chunk)
		s.buf = append(s.buf, chunk[:n]...)
		if err != nil {
			out := string(s.buf)
			s.buf = nil
			return out
		}
	}
}

func TestTelnetLoginAndShell(t *testing.T) {
	env := newTestEnv(t, 3)
	c, closeFn := dial(t, env.addr)
	defer closeFn()

	first := c.expect("login: ")
	if !strings.Contains(first, "Ubuntu 22.04.3 LTS") {
		t.Fatalf("缺少系统横幅: %q", first)
	}
	if !bytes.Contains([]byte(first), []byte{iac, will, optEcho}) {
		t.Fatalf("缺少 IAC ECHO 协商: %q", string([]byte(first)))
	}
	c.send("root\r")
	c.expect("Password: ")
	c.send("123456\r")
	c.expect("root@svr01:~# ")

	c.send("whoami\r")
	c.expect("whoami\r\n")
	c.expect("root@svr01:~# ")

	c.send("exit\r")
	_ = c.drain()

	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))
	assertHasEvent(t, events, "session_open", map[string]string{"protocol": "telnet"})
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "telnet", "username": "root", "password": "123456", "success": "true",
	})
	assertHasEvent(t, events, "command", map[string]string{"command": "whoami"})
	assertHasEvent(t, events, "command", map[string]string{"command": "exit"})
	assertHasEvent(t, events, "session_close", map[string]string{"src_ip": "127.0.0.1"})
}

func TestTelnetAuthFailureLocksIP(t *testing.T) {
	env := newTestEnv(t, 3)
	c, closeFn := dial(t, env.addr)
	defer closeFn()

	for i := 0; i < 3; i++ {
		c.expect("login: ")
		c.send("root\r")
		c.expect("Password: ")
		c.send("bad\r")
		c.expect("Login incorrect")
	}
	rest := c.drain()
	if strings.Contains(rest, "root@svr01") {
		t.Fatalf("认证失败后不应进入伪 Shell: %q", rest)
	}
	if !env.guard.IsLocked("127.0.0.1") {
		t.Fatal("连续失败达到阈值后应锁定源 IP")
	}

	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "telnet", "username": "root", "password": "bad", "success": "false",
	})
	assertHasEvent(t, events, "ip_locked", map[string]string{"src_ip": "127.0.0.1"})
}

func TestTelnetLoginLineTooLong(t *testing.T) {
	env := newTestEnv(t, 3)
	c, closeFn := dial(t, env.addr)
	defer closeFn()

	c.expect("login: ")
	// 无换行的超长输入不得在内存中无限累积，服务端应主动断开
	c.send(strings.Repeat("A", maxLoginLine*4))
	out := c.drain()
	if strings.Contains(out, "Password: ") {
		t.Fatalf("超长用户名不应进入口令阶段: %d 字节输出", len(out))
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

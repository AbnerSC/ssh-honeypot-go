package dbpot

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssh-honeypot-go/internal/attacklog"
)

// 测试脚手架

type testEnv struct {
	server *Server
	addr   string
	events *attacklog.Logger
	logDir string
}

func newTestEnv(t *testing.T, ctor func(Options) (*Server, error)) *testEnv {
	t.Helper()
	logDir := filepath.Join(t.TempDir(), "logs")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	events, err := attacklog.New(filepath.Join(logDir, "honeypot.jsonl"),
		filepath.Join(logDir, "database.db"), nil, logger)
	if err != nil {
		t.Fatalf("初始化攻击日志失败: %v", err)
	}
	srv, err := ctor(Options{Addr: "127.0.0.1:0", Events: events, Logger: logger})
	if err != nil {
		t.Fatalf("构造蜜罐失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("启动蜜罐失败: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = events.Close()
	})
	return &testEnv{server: srv, addr: srv.Addr(), events: events, logDir: logDir}
}

// script 协议客户端：socket + 未消费缓冲区。
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

func (s *script) write(b []byte) {
	s.t.Helper()
	if _, err := s.conn.Write(b); err != nil {
		s.t.Fatalf("发送失败: %v", err)
	}
}

// readN 精确读取 n 字节。
func (s *script) readN(n int) []byte {
	s.t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(s.buf) < n {
		chunk := make([]byte, 1024)
		got, err := s.conn.Read(chunk)
		s.buf = append(s.buf, chunk[:got]...)
		if err != nil {
			s.t.Fatalf("读取 %d 字节失败（已读 %d）: %v", n, len(s.buf), err)
		}
	}
	out := make([]byte, n)
	copy(out, s.buf[:n])
	s.buf = s.buf[n:]
	return out
}

// readUntil 读到 needle（含）为止。
func (s *script) readUntil(needle string) string {
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

// waitEvent 轮询 JSONL 等待指定事件落盘。
// 会话关闭记录发生在协议层发送响应之后，不能读完响应就立即断言。
func waitEvent(t *testing.T, path, name string) {
	t.Helper()
	needle := []byte(`"event":"` + name + `"`)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if data, err := os.ReadFile(path); err == nil && bytes.Contains(data, needle) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待事件 %s 超时", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
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

// MySQL

func TestMySQLHandshakeAndAccessDenied(t *testing.T) {
	env := newTestEnv(t, NewMySQL)
	c, closeFn := dial(t, env.addr)
	defer closeFn()

	// 1) 握手包：seq=0，协议版本 10，服务器版本 8.4.0，插件名 mysql_native_password
	seq, hs := mysqlClientRead(c)
	if seq != 0 {
		t.Fatalf("握手包序号=%d, want 0", seq)
	}
	if hs[0] != 0x0A {
		t.Fatalf("协议版本=%d, want 10", hs[0])
	}
	nul := bytes.IndexByte(hs, 0)
	if nul < 0 || string(hs[1:nul]) != mysqlServerVersion {
		t.Fatalf("服务器版本=%q, want %q", hs[1:nul], mysqlServerVersion)
	}
	if !bytes.Contains(hs, []byte(mysqlAuthPlugin)) {
		t.Fatalf("握手包缺少插件名 %q", mysqlAuthPlugin)
	}

	// 2) HandshakeResponse41：用户 root + 20 字节认证数据
	auth := bytes.Repeat([]byte{0xAB}, 20)
	caps := uint32(0x00000200 | 0x00008000 | 0x00080000)
	resp := make([]byte, 0, 64)
	resp = binary.LittleEndian.AppendUint32(resp, caps)
	resp = binary.LittleEndian.AppendUint32(resp, 16*1024*1024)
	resp = append(resp, 0x2D)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, "root"...)
	resp = append(resp, 0)
	resp = append(resp, byte(len(auth)))
	resp = append(resp, auth...)
	resp = append(resp, 0) // 插件名（空）+ NUL
	c.write(mysqlPacket(resp, 1))

	// 3) ERROR 1045 (28000)：用户名取自客户端提交的账号
	seq, errPacket := mysqlClientRead(c)
	if seq != 2 {
		t.Fatalf("错误包序号=%d, want 2", seq)
	}
	if errPacket[0] != 0xFF {
		t.Fatalf("错误包不以 0xFF 开头: %v", errPacket)
	}
	code := int(errPacket[1]) | int(errPacket[2])<<8
	if code != mysqlErrAccessDenied {
		t.Fatalf("错误码=%d, want %d", code, mysqlErrAccessDenied)
	}
	if errPacket[3] != '#' || string(errPacket[4:9]) != mysqlStateAccessDenied {
		t.Fatalf("SQLSTATE=%q, want %q", errPacket[3:9], mysqlStateAccessDenied)
	}
	msg := string(errPacket[9:])
	if !strings.Contains(msg, "Access denied for user 'root'@'127.0.0.1' (using password: YES)") {
		t.Fatalf("错误消息=%q", msg)
	}

	// session_close 在响应发送之后才记录，必须等它落盘再关闭日志
	waitEvent(t, filepath.Join(env.logDir, "honeypot.jsonl"), "session_close")

	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))
	assertHasEvent(t, events, "session_open", map[string]string{"protocol": "mysql"})
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "mysql", "username": "root",
		"password": strings.Repeat("ab", 20), "success": "false",
	})
	assertHasEvent(t, events, "session_close", map[string]string{"src_ip": "127.0.0.1"})
}

// mysqlClientRead 读取一个 MySQL 包，返回序号与负载。
func mysqlClientRead(c *script) (byte, []byte) {
	c.t.Helper()
	hdr := c.readN(4)
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	return hdr[3], c.readN(length)
}

// PostgreSQL

func TestPostgresStartupAndAuthFailed(t *testing.T) {
	env := newTestEnv(t, NewPostgres)
	c, closeFn := dial(t, env.addr)
	defer closeFn()

	// 1) SSLRequest：必须回 'N' 拒绝 TLS，随后客户端以明文重发启动报文
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl[0:], 8)
	binary.BigEndian.PutUint32(ssl[4:], pgSSLRequest)
	c.write(ssl)
	if got := c.readN(1)[0]; got != 'N' {
		t.Fatalf("SSLRequest 响应=%q, want 'N'", got)
	}

	// 2) StartupMessage v3：user=postgres
	startup := []byte{}
	startup = binary.BigEndian.AppendUint32(startup, 0) // 长度占位
	startup = binary.BigEndian.AppendUint32(startup, pgProtocolV3)
	startup = append(startup, "user\x00postgres\x00\x00"...)
	binary.BigEndian.PutUint32(startup[0:], uint32(len(startup)))
	c.write(startup)

	// 3) AuthenticationCleartextPassword
	typ, body := pgClientRead(c)
	if typ != 'R' {
		t.Fatalf("认证请求类型=%q, want 'R'", typ)
	}
	if len(body) != 4 || binary.BigEndian.Uint32(body) != 3 {
		t.Fatalf("认证请求体=%v, want AuthenticationCleartextPassword", body)
	}

	// 4) PasswordMessage
	password := []byte("s3cret")
	pwMsg := []byte{'p'}
	pwMsg = binary.BigEndian.AppendUint32(pwMsg, uint32(4+len(password)+1))
	pwMsg = append(pwMsg, password...)
	pwMsg = append(pwMsg, 0)
	c.write(pwMsg)

	// 5) ErrorResponse FATAL / 28P01
	typ, body = pgClientRead(c)
	if typ != 'E' {
		t.Fatalf("错误响应类型=%q, want 'E'", typ)
	}
	fields := pgParseError(body)
	if fields['S'] != "FATAL" || fields['V'] != "FATAL" {
		t.Fatalf("错误级别=%q/%q, want FATAL", fields['S'], fields['V'])
	}
	if fields['C'] != "28P01" {
		t.Fatalf("SQLSTATE=%q, want 28P01", fields['C'])
	}
	if want := `password authentication failed for user "postgres"`; fields['M'] != want {
		t.Fatalf("错误消息=%q, want %q", fields['M'], want)
	}
	if fields['F'] != "auth.c" || fields['R'] != "auth_failed" || fields['L'] != "327" {
		t.Fatalf("错误来源字段=%v", fields)
	}

	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))
	assertHasEvent(t, events, "session_open", map[string]string{"protocol": "postgresql"})
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "postgresql", "username": "postgres", "password": "s3cret", "success": "false",
	})
}

// pgClientRead 读取一个带类型字节的 PG 消息。
func pgClientRead(c *script) (byte, []byte) {
	c.t.Helper()
	typ := c.readN(1)[0]
	length := int(binary.BigEndian.Uint32(c.readN(4)))
	if length < 4 {
		c.t.Fatalf("非法报文长度: %d", length)
	}
	return typ, c.readN(length - 4)
}

// pgParseError 把 ErrorResponse 的字段列表解析为 map。
func pgParseError(body []byte) map[byte]string {
	out := make(map[byte]string)
	for i := 0; i < len(body) && body[i] != 0; {
		code := body[i]
		end := bytes.IndexByte(body[i+1:], 0)
		if end < 0 {
			break
		}
		out[code] = string(body[i+1 : i+1+end])
		i += end + 2
	}
	return out
}

// Redis

func TestRedisAuthCapture(t *testing.T) {
	env := newTestEnv(t, NewRedis)

	// 非认证命令先回 -NOAUTH 诱导客户端提交 AUTH
	c, closeFn := dial(t, env.addr)
	c.write([]byte("INFO\r\n"))
	if got := c.readUntil("\r\n"); got != "-NOAUTH Authentication required.\r\n" {
		t.Fatalf("INFO 响应=%q", got)
	}
	// AUTH <user> <pass>：捕获后一律 -WRONGPASS
	c.write([]byte("AUTH admin s3cret\r\n"))
	if got := c.readUntil("\r\n"); !strings.HasPrefix(got, "-WRONGPASS") {
		t.Fatalf("AUTH 响应=%q", got)
	}
	closeFn()

	// HELLO 3 AUTH <user> <pass> 同样捕获
	c2, closeFn2 := dial(t, env.addr)
	c2.write([]byte("HELLO 3 AUTH dbuser dbpass\r\n"))
	if got := c2.readUntil("\r\n"); !strings.HasPrefix(got, "-WRONGPASS") {
		t.Fatalf("HELLO AUTH 响应=%q", got)
	}
	closeFn2()

	// RESP 数组形式的单参数 AUTH 记为默认用户
	c3, closeFn3 := dial(t, env.addr)
	c3.write([]byte("*2\r\n$4\r\nAUTH\r\n$9\r\nredispass\r\n"))
	if got := c3.readUntil("\r\n"); !strings.HasPrefix(got, "-WRONGPASS") {
		t.Fatalf("RESP AUTH 响应=%q", got)
	}
	closeFn3()

	if err := env.events.Close(); err != nil {
		t.Fatalf("关闭日志失败: %v", err)
	}
	events := readEvents(t, filepath.Join(env.logDir, "honeypot.jsonl"))
	assertHasEvent(t, events, "session_open", map[string]string{"protocol": "redis"})
	assertHasEvent(t, events, "command", map[string]string{"command": "INFO", "username": ""})
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "redis", "username": "admin", "password": "s3cret", "success": "false",
	})
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "redis", "username": "dbuser", "password": "dbpass",
	})
	assertHasEvent(t, events, "auth_attempt", map[string]string{
		"protocol": "redis", "username": "default", "password": "redispass",
	})
}

func TestRedisConnectionLimit(t *testing.T) {
	env := newTestEnv(t, NewRedis)

	// 占满并发额度：这些连接不发送任何数据，由服务端读超时或 Close 回收
	idle := make([]net.Conn, 0, maxConnections)
	for i := 0; i < maxConnections; i++ {
		conn, err := net.Dial("tcp", env.addr)
		if err != nil {
			t.Fatalf("第 %d 个连接失败: %v", i+1, err)
		}
		idle = append(idle, conn)
	}
	defer func() {
		for _, conn := range idle {
			_ = conn.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond) // 等待各会话完成计数

	over, err := net.Dial("tcp", env.addr)
	if err != nil {
		t.Fatalf("超限连接失败: %v", err)
	}
	defer over.Close()
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := over.Read(buf)
	if err != nil {
		t.Fatalf("读取超限响应失败: %v", err)
	}
	if got := string(buf[:n]); got != string(redisTooMany) {
		t.Fatalf("超限响应=%q, want %q", got, redisTooMany)
	}
}

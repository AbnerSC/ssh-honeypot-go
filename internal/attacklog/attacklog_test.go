package attacklog

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestBuildLine(t *testing.T) {
	got := buildLine("2026-10-25 12:00:00.123", []field{
		{"event", "auth_attempt"},
		{"session", "s1-abc"},
		{"password", `p"a\ss`},
	})
	want := `{"ts":"2026-10-25 12:00:00.123","event":"auth_attempt","session":"s1-abc","password":"p\"a\\ss"}`
	if got != want {
		t.Errorf("buildLine =\n  %s\nwant\n  %s", got, want)
	}
}

func TestEscape(t *testing.T) {
	cases := map[string]string{
		"plain": "plain",
		`a"b`:   `a\"b`,
		`a\b`:   `a\\b`,
		"a\nb":  `a\nb`,
		"a\rb":  `a\rb`,
		"a\tb":  `a\tb`,
		"中文":    "中文",
		"":      "",
	}
	for in, want := range cases {
		if got := escape(in); got != want {
			t.Errorf("escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewSessionID(t *testing.T) {
	l := &Logger{}
	first := l.NewSessionID()
	second := l.NewSessionID()

	pattern := regexp.MustCompile(`^s\d+-[0-9a-f]+$`)
	if !pattern.MatchString(first) {
		t.Errorf("会话编号格式不符: %q", first)
	}
	if first == second {
		t.Errorf("会话编号应递增互异: %q", first)
	}
	if !strings.HasPrefix(first, "s1-") {
		t.Errorf("首个会话编号应为 s1- 前缀: %q", first)
	}
	if !strings.HasPrefix(second, "s2-") {
		t.Errorf("第二个会话编号应为 s2- 前缀: %q", second)
	}
}

func TestLoggerWritesJSONLAndSQLite(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "logs", "honeypot.jsonl")
	dbFile := filepath.Join(dir, "db", "database.db")

	l, err := New(logFile, dbFile, nil, nil)
	if err != nil {
		t.Fatalf("初始化日志器失败: %v", err)
	}
	if !l.Healthy() {
		t.Error("SQLite 应初始化成功")
	}

	sid := l.NewSessionID()
	l.SessionOpen(sid, "ssh", "203.0.113.7", 51234)
	l.AuthAttempt(sid, "ssh", "203.0.113.7", "root", "123456", true)
	l.Command(sid, "203.0.113.7", "root", "uname -a")
	l.Download(sid, "203.0.113.7", "root", "http://evil/x.sh")
	l.IPLocked("203.0.113.7", time.Now().Add(time.Hour).UnixMilli())
	l.SessionClose(sid, "203.0.113.7", 4877)

	if err := l.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("读取 JSONL 失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 6 {
		t.Fatalf("JSONL 行数 = %d, want 6:\n%s", len(lines), data)
	}

	// 每行都必须以 ts 开头且事件类型按写入顺序排列
	events := []string{"session_open", "auth_attempt", "command", "download", "ip_locked", "session_close"}
	tsPattern := regexp.MustCompile(`^\{"ts":"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}"`)
	for i, line := range lines {
		if !tsPattern.MatchString(line) {
			t.Errorf("第 %d 行 ts 格式不符: %s", i+1, line)
		}
		if !strings.Contains(line, `"event":"`+events[i]+`"`) {
			t.Errorf("第 %d 行事件类型不符: %s", i+1, line)
		}
	}

	// 无归属地时不应输出 location 字段
	if strings.Contains(lines[0], `"location"`) {
		t.Errorf("定位器不可用时不应输出 location: %s", lines[0])
	}
	// 关键字段必须存在
	for _, want := range []string{`"protocol":"ssh"`, `"src_port":"51234"`, `"src_ip":"203.0.113.7"`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("session_open 缺少 %s: %s", want, lines[0])
		}
	}
	if !strings.Contains(lines[1], `"password":"123456"`) || !strings.Contains(lines[1], `"success":"true"`) {
		t.Errorf("auth_attempt 字段不符: %s", lines[1])
	}
	if !strings.Contains(lines[3], `"url":"http://evil/x.sh"`) {
		t.Errorf("download 字段不符: %s", lines[3])
	}
	if !strings.Contains(lines[5], `"duration_ms":"4877"`) {
		t.Errorf("session_close 字段不符: %s", lines[5])
	}

	// SQLite 双写校验
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()

	counts := map[string]int{}
	for _, table := range []string{"sessions", "auth_attempts", "commands", "downloads", "ip_locks"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("统计 %s 失败: %v", table, err)
		}
		counts[table] = n
	}
	for table, want := range map[string]int{
		"sessions": 1, "auth_attempts": 1, "commands": 1, "downloads": 1, "ip_locks": 1,
	} {
		if counts[table] != want {
			t.Errorf("%s 行数 = %d, want %d", table, counts[table], want)
		}
	}

	var duration int64
	if err := db.QueryRow(`SELECT duration_ms FROM sessions WHERE session_id = ?`, sid).Scan(&duration); err != nil {
		t.Fatalf("查询会话时长失败: %v", err)
	}
	if duration != 4877 {
		t.Errorf("duration_ms = %d, want 4877", duration)
	}
}

// TestQueueFullDoesNotBlock 队列灌满后调用必须立即返回（不阻塞会话线程）。
func TestQueueFullDoesNotBlock(t *testing.T) {
	l := &Logger{queue: make(chan event, 2)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			l.write([]field{{"event", "command"}}, nil)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("队列已满时 write 阻塞了调用方")
	}
	if got := l.dropped.Load(); got != 98 {
		t.Errorf("丢弃计数 = %d, want 98", got)
	}
}

// TestCloseIdempotent 重复关闭必须安全，关闭后写入不再入队。
func TestCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	l, err := New(filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "a.db"), nil, nil)
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("首次关闭失败: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("重复关闭失败: %v", err)
	}
	l.Command("s1", "1.2.3.4", "root", "id") // 关闭后写入应为空操作，不 panic
}

// TestNilLogger 降级/空实例调用安全性。
func TestNilLogger(t *testing.T) {
	var l *Logger
	if l.Healthy() {
		t.Error("nil Logger 不应 Healthy")
	}
	if err := l.Close(); err != nil {
		t.Errorf("nil Logger.Close 应返回 nil: %v", err)
	}
	if got := l.locate("1.2.3.4"); got != "" {
		t.Errorf("nil Logger.locate = %q, want 空串", got)
	}
}

// TestFlushWithinOneSecond 未关闭时事件也应在 1 秒批量刷盘周期内落盘。
func TestFlushWithinOneSecond(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "batch.jsonl")
	dbFile := filepath.Join(dir, "batch.db")

	l, err := New(logFile, dbFile, nil, nil)
	if err != nil {
		t.Fatalf("初始化日志器失败: %v", err)
	}
	defer l.Close()

	l.Command("s1", "1.2.3.4", "root", "id")

	// 定时器每 1s 触发一次，留出余量后校验 JSONL 已落盘（不依赖 Close）
	deadline := time.Now().Add(3 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(logFile)
		if strings.Contains(string(data), `"command":"id"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(string(data), `"command":"id"`) {
		t.Fatalf("事件未在批量刷盘周期内写入 JSONL: %q", data)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM commands`).Scan(&n); err != nil {
		t.Fatalf("统计命令数失败: %v", err)
	}
	if n != 1 {
		t.Errorf("SQLite 命令数 = %d, want 1", n)
	}
}

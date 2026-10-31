package main

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// forgedLine 攻击者尝试插入的伪造日志行。
const forgedLine = "2026-01-01 00:00:00.000 WARN  伪造的日志行"

// newTestLineHandler 构造写入 buf 的行日志器。
func newTestLineHandler(buf *bytes.Buffer) *slog.Logger {
	return slog.New(&lineHandler{w: buf, mu: &sync.Mutex{}, level: slog.LevelDebug})
}

// TestLineHandlerSanitizes 攻击者可控数据里带换行时，一条记录必须仍只占一行：
// 否则 Web 登录用户名、未知命令之类的内容就能伪造整行日志，污染取证与告警。
func TestLineHandlerSanitizes(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLineHandler(&buf)

	logger.Warn("Web 控制台登录失败 user=admin\n"+forgedLine,
		"user", "admin\n"+forgedLine,
		"err", errors.New("boom\r\n"+forgedLine),
		"ansi", "\x1b[31mred\x1b[0m")

	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("一条日志记录必须只占一行，实际:\n%q", out)
	}
	if strings.ContainsRune(out, '\r') || strings.ContainsRune(out, 0x1b) {
		t.Fatalf("回车/ANSI 控制字符未转义: %q", out)
	}
	// 消息中的换行转成字面量 \n；属性值（含空白）走 %q 加引号
	if !strings.Contains(out, `失败 user=admin\n`+forgedLine) {
		t.Fatalf("消息中的换行未转义: %s", out)
	}
	if !strings.Contains(out, `user="admin\n`) {
		t.Fatalf("属性值应加引号并转义换行: %s", out)
	}
}

// TestLineHandlerPlainMessage 无控制字符时保持原样（日志格式不变）。
func TestLineHandlerPlainMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLineHandler(&buf)

	logger.Info("Web 控制台已启动", "port", "8080", "ok", true)

	out := buf.String()
	if !strings.Contains(out, " INFO  Web 控制台已启动 port=8080 ok=true") {
		t.Fatalf("普通日志格式被改变: %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("单条日志应只占一行: %q", out)
	}
}

// TestSanitizeLine 控制字符一律转成可见转义，其余字节原样保留。
func TestSanitizeLine(t *testing.T) {
	cases := map[string]string{
		"plain":    "plain",
		"a b":      "a b",
		"中文":       "中文",
		"a\nb":     `a\nb`,
		"a\r\nb":   `a\r\nb`,
		"a\tb":     `a\tb`,
		"a\x00b":   `a\x00b`,
		"a\x1b[0m": `a\x1b[0m`,
		"a\x7fb":   `a\x7fb`,
	}
	for in, want := range cases {
		if got := sanitizeLine(in); got != want {
			t.Errorf("sanitizeLine(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

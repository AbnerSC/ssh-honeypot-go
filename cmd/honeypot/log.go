package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// newLogger 构造日志器，输出风格贴近 Java 版 JUL 文本格式：
//
//	2006-01-02 15:04:05.000 LEVEL 消息 key=value
//
// 关键行保持可 grep（与 Java 版日志关键字一致）。
func newLogger(level slog.Level) *slog.Logger {
	return slog.New(&lineHandler{w: os.Stderr, mu: &sync.Mutex{}, level: level})
}

// lineHandler 单行文本日志 Handler：不使用 slog.TextHandler 是因为其 time 值含空格会被加引号，
// 与 Java 版日志形态差异较大。
type lineHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	level slog.Level
	attrs []slog.Attr
	group string
}

func (h *lineHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("2006-01-02 15:04:05.000"))
	b.WriteByte(' ')
	b.WriteString(levelLabel(r.Level))
	b.WriteByte(' ')
	// 消息里可能含攻击者可控内容（Web 登录用户名、命令等）：必须去掉换行，
	// 否则一条日志记录就能伪造出多行，污染取证与告警
	b.WriteString(sanitizeLine(r.Message))
	for _, a := range h.attrs {
		h.writeAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		h.writeAttr(&b, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := *h
	nh.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	nh.attrs = append(nh.attrs, h.attrs...)
	for _, a := range attrs {
		nh.attrs = append(nh.attrs, nh.prefixed(a))
	}
	return &nh
}

func (h *lineHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.group = h.group + name + "."
	return &nh
}

func (h *lineHandler) prefixed(a slog.Attr) slog.Attr {
	if h.group != "" {
		a.Key = h.group + a.Key
	}
	return a
}

func (h *lineHandler) writeAttr(b *strings.Builder, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	b.WriteByte(' ')
	b.WriteString(h.group + a.Key)
	b.WriteByte('=')
	b.WriteString(formatAttrValue(a.Value))
}

// formatAttrValue 输出属性值：字符串原样输出，含空白的值加双引号便于区分字段边界。
// 两条分支都保证不会把换行等控制字符原样写进去（日志注入）。
func formatAttrValue(v slog.Value) string {
	if v.Kind() == slog.KindString {
		s := v.String()
		if strings.ContainsAny(s, " \t\n\r") {
			return fmt.Sprintf("%q", s)
		}
		return sanitizeLine(s)
	}
	return sanitizeLine(fmt.Sprint(v.Any()))
}

// hexDigits 控制字符转义用的十六进制字符表。
const hexDigits = "0123456789abcdef"

// sanitizeLine 把控制字符转成可见转义，保证一条日志记录只占一行。
//
// 日志里会混入攻击者可控的数据（Web 登录用户名、口令、未知命令、panic 值等），
// 其中可能含换行或 ANSI 控制序列：不转义就能伪造整行日志、误导排查与告警。
func sanitizeLine(s string) string {
	dirty := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			dirty = true
			break
		}
	}
	if !dirty {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				b.WriteString(`\x`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0x0f])
				continue
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

// levelLabel 固定 5 字符宽度，保证日志列对齐。
func levelLabel(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO "
	case l < slog.LevelError:
		return "WARN "
	default:
		return "ERROR"
	}
}

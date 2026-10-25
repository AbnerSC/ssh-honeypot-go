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
	b.WriteString(r.Message)
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
func formatAttrValue(v slog.Value) string {
	if v.Kind() == slog.KindString {
		s := v.String()
		if strings.ContainsAny(s, " \t\n\r") {
			return fmt.Sprintf("%q", s)
		}
		return s
	}
	return fmt.Sprint(v.Any())
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

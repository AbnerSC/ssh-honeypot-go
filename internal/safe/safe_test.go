package safe

import (
	"io"
	"log/slog"
	"testing"
)

// TestLogPanic 记录 panic 不应自身报错（供已自行 recover 的调用方使用）。
func TestLogPanic(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	LogPanic(logger, "test", "boom")
	LogPanic(nil, "test", nil) // nil logger 退回 slog.Default
}

// TestRecover Recover 必须吃掉 panic，不能让调用方进程终止。
func TestRecover(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	func() {
		defer Recover(logger, "test")
		panic("boom")
	}()
}

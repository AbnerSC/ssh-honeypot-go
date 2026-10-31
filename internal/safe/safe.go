// Package safe 为长生命周期的 goroutine 与 HTTP 处理器提供 panic 兜底。
//
// 蜜罐的所有输入都来自攻击者：进程内任何一处未捕获的 panic 都会终止整个
// 进程，使「一条恶意命令」升级为「全部协议拒绝服务」。这里仅做兜底记录，
// 让出错的那一个连接/请求失败，其余会话继续服务。
package safe

import (
	"fmt"
	"log/slog"
	"runtime/debug"
)

// Recover 供 defer 直接使用：捕获 panic 并记录调用栈。
//
// 用法：函数体第一行 `defer safe.Recover(logger, "ssh 连接")`。
//
// 注意：recover 只能由 defer 的函数「直接」调用，因此本函数必须整体作为
// defer 目标，不能再包一层（`defer func(){ safe.Recover(...) }()` 会失效）。
func Recover(logger *slog.Logger, scope string) {
	if r := recover(); r != nil {
		LogPanic(logger, scope, r)
	}
}

// LogPanic 记录一次 panic（供已经自行 recover、还需要补偿动作的调用方使用，
// 例如 HTTP 中间件在返回 500 前留痕）。
func LogPanic(logger *slog.Logger, scope string, r any) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("捕获到 panic，已隔离本次请求",
		"scope", scope,
		"panic", fmt.Sprint(r),
		"stack", string(debug.Stack()))
}

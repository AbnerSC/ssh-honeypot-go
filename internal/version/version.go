// Package version 提供构建信息（版本号 / 提交号 / 构建时间）的格式化输出。
//
// 实际取值由 main 包变量承载，构建时通过 -ldflags "-X main.version=... -X main.commit=... -X main.buildAt=..."
// 注入，未注入时使用以下默认值（就地 go run 时为 2.0.0 / none / unknown）。
package version

import (
	"fmt"
	"runtime"
	"strings"
)

// Default 源码基线版本号。Go 版自 2.0.0 起，与 Java 版 1.2.1 区分。
const Default = "2.0.0"

// Info 一组构建信息。
type Info struct {
	Version   string
	Commit    string
	BuildAt   string
	GoVersion string
}

// New 构造构建信息，GoVersion 默认取当前运行时（去掉 go 前缀）。
func New(ver, commit, buildAt string) Info {
	return Info{
		Version:   ver,
		Commit:    commit,
		BuildAt:   buildAt,
		GoVersion: strings.TrimPrefix(runtime.Version(), "go"),
	}
}

// Short 返回版本号本身，用于启动横幅。
func (i Info) Short() string {
	return i.Version
}

// String 返回 -version 的完整单行输出。
func (i Info) String() string {
	return fmt.Sprintf("ssh-honeypot %s (commit %s, built %s, go %s)",
		i.Version, i.Commit, i.BuildAt, i.GoVersion)
}

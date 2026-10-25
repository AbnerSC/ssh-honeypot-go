package cmd

import (
	"strconv"
	"strings"
	"unicode"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/shell"
)

// 时间格式：与 Java 版 DateTimeFormatter 模板一一对应。
const (
	layoutTimeHMS   = "15:04:05"
	layoutTimeHM    = "15:04"
	layoutDateTime  = "2006-01-02 15:04:05"
	layoutCTime     = "Mon Jan 02 15:04:05 UTC 2006"
	layoutStatTime  = "2006-01-02T15:04:05.000"
	layoutLsNewline = "\n"
)

// text 构造普通文本输出（由 Execute 负责补换行）。
func text(s string) shell.Output {
	return shell.Output{Text: s}
}

// exitOutput 构造会话退出输出。
func exitOutput() shell.Output {
	return shell.Output{Exit: true}
}

// firstNonFlag 取第一个非选项参数；没有则返回空串（对应 Java firstNonFlag）。
func firstNonFlag(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// nonFlags 过滤掉选项参数，保留操作数。
func nonFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// hasArg 是否包含某个精确参数（如 "--decode" / "-v"）。
func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// hasShort 是否包含带某短选项字母的选项参数（如 ls -al 中的 l）。
func hasShort(args []string, ch byte) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && strings.IndexByte(a, ch) >= 0 {
			return true
		}
	}
	return false
}

// lastArg 取最后一个参数，args 为空时返回 def。
func lastArg(args []string, def string) string {
	if len(args) == 0 {
		return def
	}
	return args[len(args)-1]
}

// stripTrailing 去掉尾部空白（等价 Java String.stripTrailing）。
func stripTrailing(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// humanSize 把字节数转成 12K / 3M / 1G 形式（du -h）。
func humanSize(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + "B"
	case n < 1024*1024:
		return strconv.FormatInt(n/1024, 10) + "K"
	case n < 1024*1024*1024:
		return strconv.FormatInt(n/1024/1024, 10) + "M"
	default:
		return strconv.FormatInt(n/1024/1024/1024, 10) + "G"
	}
}

// joinLines 拼接多行文本并在末尾补一个换行（无内容时返回空串）。
func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, layoutLsNewline) + layoutLsNewline
}

// splitLines 按 \n 切分并保留空行（等价 Java split("\n", -1)）。
func splitLines(s string) []string {
	return strings.Split(s, layoutLsNewline)
}

// logCommand 记录一条带内部标记的命令（提权/后门/危险操作等），events 可为 nil。
func (p *Processor) logCommand(st *shell.Session, cmdline string) {
	if p.events != nil {
		p.events.Command(st.ID, st.IP, st.Username, cmdline)
	}
}

// logDownload 记录一次恶意下载。
func (p *Processor) logDownload(st *shell.Session, url string) {
	if p.events != nil {
		p.events.Download(st.ID, st.IP, st.Username, url)
	}
}

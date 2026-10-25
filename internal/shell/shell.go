package shell

import (
	"bufio"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/attacklog"
)

// banner 登录横幅：内容固定，编译期拼接一次复用。
const banner = "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n" +
	" * Documentation:  https://help.ubuntu.com\r\n" +
	" * Management:     https://landscape.canonical.com\r\n" +
	" * Support:        https://ubuntu.com/advantage\r\n\r\n" +
	"Last login: Mon Aug 11 06:25:01 2026 from 203.0.113.44\r\n"

// 行编辑使用到的控制字符。
const (
	cr        byte = 13
	lf        byte = 10
	bs        byte = 8
	del       byte = 127
	ctrlC     byte = 3
	ctrlD     byte = 4
	esc       byte = 27
	telnetIAC byte = 0xFF
	telnetSB  byte = 0xFA
	telnetSE  byte = 0xF0
)

// Output 单条命令的执行结果。
//
// 用结构体取代 Java 版的 `\x00NONL` / `\x00__EXIT__` 字符串标记（plan 5.2 允许的软契约）。
type Output struct {
	// Text 命令输出（可含 \n，由 Shell 统一转换为 \r\n）。
	Text string
	// NoNewline 末尾不补换行（对应 echo -n 等）。
	NoNewline bool
	// Exit 请求结束会话（exit / logout / 危险操作导致断开）。
	Exit bool
}

// Processor 命令解释器接口，由 internal/shell/cmd 实现。
type Processor interface {
	Execute(st *Session, line string) Output
}

// Shell 交互式伪 Shell：实现行编辑（回显、退格、上下翻历史、Ctrl-C/Ctrl-D），
// 并把输入交给 CommandProcessor。SSH 与 Telnet 两个协议共用这一个实现。
type Shell struct {
	in     *bufio.Reader
	out    io.Writer
	st     *Session
	proc   Processor
	events *attacklog.Logger
	onExit func(*Session)

	start  time.Time
	closed sync.Once

	// nav 历史导航用的输入行（与 st.History 分开：导航只关心本会话键入的内容）
	nav       []string
	navIdx    int
	pendingLF bool
}

// NewShell 构造伪 Shell。onExit 可为 nil，在会话结束时回调（协议层负责关闭连接）。
func NewShell(in io.Reader, out io.Writer, st *Session, proc Processor,
	events *attacklog.Logger, onExit func(*Session)) *Shell {
	return &Shell{
		in:     bufio.NewReaderSize(in, 4096),
		out:    out,
		st:     st,
		proc:   proc,
		events: events,
		onExit: onExit,
		start:  time.Now(),
		navIdx: -1,
	}
}

// Run 主循环（阻塞），应在独立 goroutine 中调用。
func (s *Shell) Run() {
	defer s.Close()
	if _, err := s.out.Write([]byte(banner)); err != nil {
		return
	}
	for {
		if err := s.writeRawString(s.st.Prompt()); err != nil {
			return
		}
		line, ok := s.readLine()
		if !ok {
			return
		}
		s.pushHistory(line)
		out := s.proc.Execute(s.st, line)
		if out.Exit {
			return
		}
		if out.Text == "" {
			continue
		}
		if err := s.write(out.Text); err != nil {
			return
		}
	}
}

// Close 幂等关闭：无论正常 exit、Ctrl-D、连接异常断开还是协议层主动销毁，
// 都保证 session_close 事件恰好记录一次。
func (s *Shell) Close() {
	s.closed.Do(func() {
		if s.events != nil {
			s.events.SessionClose(s.st.ID, s.st.IP, time.Since(s.start).Milliseconds())
		}
		if s.onExit != nil {
			s.onExit(s.st)
		}
	})
}

// 行编辑器

// readLine 读取一行，处理回显/退格/历史。ok 为 false 表示会话结束。
func (s *Shell) readLine() (string, bool) {
	buf := make([]byte, 0, 128)
	for {
		b, err := s.in.ReadByte()
		if err != nil {
			return "", false
		}

		switch b {
		case telnetIAC:
			s.skipTelnetCommand()
			continue
		case esc:
			buf = s.handleEscape(buf)
			continue
		case cr:
			s.pendingLF = true
			if err := s.writeRawString("\r\n"); err != nil {
				return "", false
			}
			return string(buf), true
		case lf:
			if s.pendingLF { // 吞掉 \r\n 残留的 \n
				s.pendingLF = false
				continue
			}
			if err := s.writeRawString("\r\n"); err != nil {
				return "", false
			}
			return string(buf), true
		}
		s.pendingLF = false

		switch b {
		case bs, del:
			if len(buf) > 0 {
				buf = trimLastRune(buf)
				if err := s.writeRawString("\b \b"); err != nil {
					return "", false
				}
			}
			continue
		case ctrlC:
			if err := s.writeRawString("^C\r\n"); err != nil {
				return "", false
			}
			return "", true
		case ctrlD:
			if len(buf) == 0 { // 空行按 Ctrl-D = 登出
				return "", false
			}
			continue
		}
		if b < 0x20 { // 忽略其它控制字符
			continue
		}
		buf = append(buf, b)
		if err := s.writeRawByte(b); err != nil {
			return "", false
		}
	}
}

// handleEscape 历史导航（上/下箭头），其余转义序列直接吞掉。
func (s *Shell) handleEscape(buf []byte) []byte {
	b1, err := s.in.ReadByte()
	if err != nil || (b1 != '[' && b1 != 'O') {
		return buf
	}
	b2, err := s.in.ReadByte()
	if err != nil {
		return buf
	}

	var target string
	switch b2 {
	case 'A':
		if len(s.nav) == 0 {
			return buf
		}
		if s.navIdx == -1 {
			s.navIdx = len(s.nav) - 1
		} else if s.navIdx > 0 {
			s.navIdx--
		}
		target = s.nav[s.navIdx]
	case 'B':
		if s.navIdx == -1 {
			return buf
		}
		if s.navIdx < len(s.nav)-1 {
			s.navIdx++
			target = s.nav[s.navIdx]
		} else {
			s.navIdx = -1
			target = ""
		}
	default:
		// 左右箭头/Delete/Home/End 等：吞掉序列尾部，忽略
		for b2 >= 0x30 && b2 <= 0x3F {
			if b2, err = s.in.ReadByte(); err != nil {
				return buf
			}
		}
		return buf
	}

	// 重绘当前行：回车 + 提示符 + 新内容 + 清到行尾
	buf = append(buf[:0], target...)
	if err := s.writeRawString("\r" + s.st.Prompt() + target + "\x1b[K"); err != nil {
		return buf
	}
	return buf
}

// skipTelnetCommand 吞掉 Telnet IAC 协商序列（出现在数据流中间的情况）。
func (s *Shell) skipTelnetCommand() {
	cmd, err := s.in.ReadByte()
	if err != nil {
		return
	}
	switch {
	case cmd >= 0xFB && cmd <= 0xFE: // WILL/WONT/DO/DONT
		_, _ = s.in.ReadByte()
	case cmd == telnetSB: // 子协商：读到 IAC SE
		var prev byte
		for {
			cur, err := s.in.ReadByte()
			if err != nil {
				return
			}
			if prev == telnetIAC && cur == telnetSE {
				return
			}
			prev = cur
		}
	}
}

// trimLastRune 删除末尾一个字符（多字节字符整段删除，终端只占一列）。
func trimLastRune(b []byte) []byte {
	_, size := utf8.DecodeLastRune(b)
	if size <= 0 {
		return b
	}
	return b[:len(b)-size]
}

// 输出

// write 输出命令结果，并把换行统一规范化为 \r\n（单遍扫描，无中间字符串）。
func (s *Shell) write(text string) error {
	if text == "" {
		return nil
	}
	if strings.IndexByte(text, lf) < 0 {
		_, err := s.out.Write([]byte(text))
		return err
	}
	out := make([]byte, 0, len(text)+16)
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case cr:
			if i+1 < len(text) && text[i+1] == lf {
				out = append(out, cr, lf)
				i++
			} else {
				out = append(out, cr) // 孤立 CR 原样保留
			}
		case lf:
			out = append(out, cr, lf)
		default:
			out = append(out, text[i])
		}
	}
	_, err := s.out.Write(out)
	return err
}

func (s *Shell) writeRawString(text string) error {
	_, err := s.out.Write([]byte(text))
	return err
}

func (s *Shell) writeRawByte(b byte) error {
	_, err := s.out.Write([]byte{b})
	return err
}

// pushHistory 记录已完成的命令供历史导航使用。
func (s *Shell) pushHistory(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	s.nav = append(s.nav, line)
	s.navIdx = -1
}

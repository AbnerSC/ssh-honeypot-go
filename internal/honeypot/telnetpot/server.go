// Package telnetpot Telnet 蜜罐服务。
//
// 模拟经典 Linux login 提示符并完成 IAC 选项协商，按密码本校验凭证：
//   - 单连接最多重试 maxFailures 次，连续失败达阈值后由 Guard 锁定源 IP
//   - 认证成功后进入伪 Shell，与 SSH 共用同一个 CommandProcessor 与 VFS
//   - 并发连接数与认证阶段/空闲阶段读超时都有硬上限，防连接洪泛与挂死
package telnetpot

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/attacklog"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/auth"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/safe"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/shell"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/vfs"
)

// Telnet 协议控制字节（RFC 854/857/858/1073/1091）。
const (
	iac  byte = 255
	wont byte = 252
	will byte = 251
	dont byte = 254
	do   byte = 253
	sb   byte = 250
	se   byte = 240

	optEcho         byte = 1  // ECHO
	optSuppressGA   byte = 3  // SUPPRESS-GO-AHEAD
	optNAWS         byte = 31 // 窗口尺寸
	optLinemode     byte = 34 // LINEMODE（不支持，明确拒绝）
	echoPasswordChr byte = '*'
)

// 行编辑用到的 ASCII 控制字符。
const (
	cr  byte = 13
	lf  byte = 10
	esc byte = 27
	bs  byte = 8
	del byte = 127
)

const (
	// maxConnections 最大并发连接数：超限直接断开（Telnet 无标准超载响应，
	// 与真实 telnetd 超载行为一致）；交互式协议略高于数据库蜜罐的 20。
	maxConnections = 50
	// authTimeout 认证阶段超时：1 分钟内未完成登录即断开，防扫描器长期挂连接。
	authTimeout = 60 * time.Second
	// idleTimeout 登录后空闲超时：10 分钟无操作自动断开（交互会话需更长的空闲容忍）。
	idleTimeout = 10 * time.Minute
)

var (
	// 固定响应字节序列：内容不随连接变化，包级变量避免每次连接重复分配。
	systemBanner    = []byte("\r\nUbuntu 22.04.3 LTS\r\n")
	loginIncorrect  = []byte("\r\nLogin incorrect\r\n")
	tooManyAttempts = []byte("\r\nToo many failed attempts. Connection locked.\r\n")
	crlf            = []byte("\r\n")
	bsEcho          = []byte{8, ' ', 8}
)

// Options Telnet 蜜罐启动参数。
type Options struct {
	// Addr 监听地址，如 ":2323"。
	Addr      string
	FS        *vfs.FS
	Events    *attacklog.Logger
	Guard     *auth.Guard
	Hostname  string
	Processor shell.Processor
	Logger    *slog.Logger
}

// Server Telnet 蜜罐服务。
type Server struct {
	opts Options
	ln   net.Listener

	active atomic.Int64
	wg     sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	closeOnce sync.Once
}

// New 构造 Telnet 蜜罐服务（不监听端口）。
func New(opts Options) (*Server, error) {
	if opts.FS == nil {
		return nil, errors.New("telnetpot: FS 不能为空")
	}
	if opts.Events == nil {
		return nil, errors.New("telnetpot: Events 不能为空")
	}
	if opts.Processor == nil {
		return nil, errors.New("telnetpot: Processor 不能为空")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Server{opts: opts, conns: make(map[net.Conn]struct{}, maxConnections)}, nil
}

// Start 开始监听并接受连接（非阻塞）。
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("Telnet 监听 %s 失败: %w", s.opts.Addr, err)
	}
	s.ln = ln
	go s.acceptLoop()
	infof(s.opts.Logger, "Telnet 蜜罐已启动，监听 "+ln.Addr().String())
	return nil
}

// Addr 返回实际监听地址（Start 之后有效）。
func (s *Server) Addr() string {
	if s.ln == nil {
		return s.opts.Addr
	}
	return s.ln.Addr().String()
}

// Close 停止接受新连接，并在 5s 内关闭在途连接。
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.connMu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.connMu.Unlock()

		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			warnf(s.opts.Logger, "Telnet 会话未在 5s 内全部关闭")
		}
	})
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			warnf(s.opts.Logger, "Telnet 接受连接失败: "+err.Error())
			continue
		}
		if s.active.Add(1) > maxConnections {
			s.active.Add(-1)
			// 超限直接断开：与真实 telnetd 一致，且不产生日志噪音
			_ = conn.Close()
			continue
		}
		s.trackConn(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			defer s.active.Add(-1)
			defer conn.Close()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) trackConn(conn net.Conn) {
	s.connMu.Lock()
	s.conns[conn] = struct{}{}
	s.connMu.Unlock()
}

func (s *Server) untrackConn(conn net.Conn) {
	s.connMu.Lock()
	delete(s.conns, conn)
	s.connMu.Unlock()
}

// handleConn 认证 + 伪 Shell。session_close 只由一处记录：
// 认证失败路径由本函数补记，进入伪 Shell 后由 shell.Shell.Close 负责。
func (s *Server) handleConn(conn net.Conn) {
	// 协议报文与登录名/口令完全来自攻击者：任何解析 panic 只断开本连接，
	// 不能让整个进程（其余协议与会话）一起退出。
	defer safe.Recover(s.opts.Logger, "telnet 连接")
	ip, port := addrParts(conn.RemoteAddr())
	sid := s.opts.Events.NewSessionID()
	s.opts.Events.SessionOpen(sid, "telnet", ip, port)
	start := time.Now()
	entered := false
	defer func() {
		if !entered {
			s.opts.Events.SessionClose(sid, ip, time.Since(start).Milliseconds())
		}
	}()

	// 认证阶段限时：慢速扫描器不允许长期占用连接额度
	_ = conn.SetReadDeadline(time.Now().Add(authTimeout))

	br := bufio.NewReaderSize(conn, 1024)
	s.negotiate(conn)
	_, _ = conn.Write(systemBanner)

	username, authed := s.authenticate(conn, newLineReader(br), ip, sid)
	if !authed {
		return
	}
	_, _ = conn.Write(crlf)

	// 认证成功：把同一个 reader 交给伪 Shell，已缓冲的预输入数据不会丢失
	st := shell.NewSession(sid, ip, username, s.opts.FS, s.opts.Hostname)
	entered = true
	idle := &idleReader{conn: conn, br: br, timeout: idleTimeout}
	shell.NewShell(idle, conn, st, s.opts.Processor, s.opts.Events, nil).Run()
}

// authenticate 逐次索取用户名/口令并校验，每次尝试都记录 auth_attempt。
func (s *Server) authenticate(out io.Writer, in *lineReader, ip, sid string) (string, bool) {
	maxAttempts := s.opts.Guard.MaxFailures()
	username := ""
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if s.opts.Guard.IsLocked(ip) {
			_, _ = out.Write(tooManyAttempts)
			return username, false
		}

		u, ok := in.readLine(out, s.opts.Hostname+" login: ", true)
		if !ok {
			return username, false // 客户端断开
		}
		p, ok := in.readLine(out, "Password: ", false)
		if !ok {
			p = ""
		}
		username = strings.TrimSpace(u)
		password := strings.TrimSpace(p)

		authed := s.opts.Guard.Authenticate(ip, username, password)
		s.opts.Events.AuthAttempt(sid, "telnet", ip, username, password, authed)
		if authed {
			return username, true
		}
		_, _ = out.Write(loginIncorrect)
	}
	return username, false
}

// negotiate 服务端主动协商：我们负责回显，客户端逐字符发送，客户端上报窗口尺寸。
func (s *Server) negotiate(out io.Writer) {
	_, _ = out.Write([]byte{
		iac, will, optEcho,
		iac, will, optSuppressGA,
		iac, do, optSuppressGA,
		iac, do, optNAWS,
		iac, dont, optLinemode,
	})
}

// lineReader 登录阶段行读取器。pendingLF 记录跨行残留的 \n：
// 客户端把 \r\n 拆成两个报文时不会被误判为空行，同时兼容只发 \n 的扫描器。
type lineReader struct {
	in        *bufio.Reader
	pendingLF bool
}

// maxLoginLine 登录阶段单行最大字节数。
// 不设上限时，攻击者可发送超长行（无换行）使缓冲区无限增长，
// 且逐字节回显会把内存放大为 CPU/带宽放大（5MB 输入实测 RSS +5.4MB）。
const maxLoginLine = 4096

func newLineReader(in *bufio.Reader) *lineReader {
	return &lineReader{in: in}
}

// readLine 输出提示符并读取一行，兼容逐字符与整行两种客户端。
func (l *lineReader) readLine(out io.Writer, prompt string, echo bool) (string, bool) {
	_, _ = io.WriteString(out, prompt)

	buf := make([]byte, 0, 64)
	for {
		b, err := l.in.ReadByte()
		if err != nil {
			return "", false
		}
		if b == iac {
			skipTelnetCommand(l.in)
			continue
		}
		if b == esc {
			skipEscape(l.in)
			continue
		}
		switch b {
		case cr:
			l.pendingLF = true
			// 缓冲区已有后续字节时顺手吃掉 \r\n 的 \n 或 telnet 的 CR NUL；
			// 否则不阻塞等待（只发单个 \r 的客户端不应卡到认证超时）
			if l.in.Buffered() > 0 {
				if next, err := l.in.ReadByte(); err == nil {
					switch next {
					case lf:
						l.pendingLF = false
					case 0: // CR NUL：已消费
					default:
						_ = l.in.UnreadByte()
					}
				}
			}
			_, _ = out.Write(crlf)
			return string(buf), true
		case lf:
			if l.pendingLF { // 吞掉 \r\n 拆分后迟到的 \n
				l.pendingLF = false
				continue
			}
			_, _ = out.Write(crlf)
			return string(buf), true
		}
		l.pendingLF = false

		if b == bs || b == del {
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if echo {
					_, _ = out.Write(bsEcho)
				}
			}
			continue
		}
		if b < 0x20 { // 其余控制字符忽略
			continue
		}
		buf = append(buf, b)
		if len(buf) > maxLoginLine { // 超长行直接断开：内存与回显开销必须封顶
			_, _ = out.Write(crlf)
			return "", false
		}
		if echo {
			_, _ = out.Write([]byte{b})
		} else {
			_, _ = out.Write([]byte{echoPasswordChr}) // 口令不回显明文
		}
	}
}

// skipTelnetCommand 吞掉 IAC 协商序列。
func skipTelnetCommand(in *bufio.Reader) {
	cmd, err := in.ReadByte()
	if err != nil {
		return
	}
	switch {
	case cmd >= will && cmd <= dont: // WILL/WONT/DO/DONT + 选项字节
		_, _ = in.ReadByte()
	case cmd == sb: // 子协商：读到 IAC SE
		var prev byte
		for {
			cur, err := in.ReadByte()
			if err != nil {
				return
			}
			if prev == iac && cur == se {
				return
			}
			prev = cur
		}
	}
}

// skipEscape 吞掉方向键等功能键转义序列（吞到首个非参数字节为止）。
func skipEscape(in *bufio.Reader) {
	b, err := in.ReadByte()
	if err != nil || (b != '[' && b != 'O') {
		return
	}
	for {
		c, err := in.ReadByte()
		if err != nil || c < 0x30 || c > 0x3F {
			return
		}
	}
}

// idleReader 每次底层读取前刷新读超时，实现「空闲 N 分钟断开」语义。
// 与一次性 SoTimeout 不同：有数据来往的会话不会被固定截止时间误杀。
type idleReader struct {
	conn    net.Conn
	br      *bufio.Reader
	timeout time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
	return r.br.Read(p)
}

// addrParts 拆分远端地址为 IP 与端口（v4-mapped 地址归一为点分十进制）。
func addrParts(addr net.Addr) (string, int) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String(), tcp.Port
	}
	return "unknown", 0
}

func infof(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Info(msg)
	}
}

func warnf(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Warn(msg)
	}
}

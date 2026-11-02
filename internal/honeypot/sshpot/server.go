// Package sshpot SSH 蜜罐服务。
//
// 特点：
//   - 伪装成 OpenSSH_8.9p1 (Ubuntu)，指纹与 Java 版完全一致
//   - 按密码本校验登录凭证，不再全部放行；全部尝试均记录日志
//   - 同一源 IP 连续失败达到阈值后被临时锁定，禁止登录
//   - 支持交互式 shell 与 exec 两种攻击方式
package sshpot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"ssh-honeypot-go/internal/attacklog"
	"ssh-honeypot-go/internal/auth"
	"ssh-honeypot-go/internal/safe"
	"ssh-honeypot-go/internal/shell"
	"ssh-honeypot-go/internal/vfs"
)

const (
	// serverVersion 对外 banner：与真实 Ubuntu 22.04 的 OpenSSH 完全一致（硬契约）。
	serverVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
	// maxSessions 最大并发 SSH 会话数：pre-auth 连接即计入，超限直接断开
	// （对应真实 sshd 的 MaxStartups 行为），防连接洪泛耗尽资源。
	maxSessions = 50
	// handshakeTimeout 握手（含认证）超时：未完成握手的连接不允许长期占用会话额度。
	handshakeTimeout = 30 * time.Second
	// heartbeatInterval / heartbeatMaxMissed 心跳探测：攻击端直接断开（无 TCP FIN、
	// 无 SSH 断开报文）时靠 keepalive 主动发现死连接，保证 session_close 不丢。
	heartbeatInterval     = 30 * time.Second
	heartbeatMaxMissed    = 2
	heartbeatReplyTimeout = 10 * time.Second
)

// errAuthFailed 认证失败返回给客户端（内容不会展示给攻击者，x/crypto 统一回 SSH_MSG_USERAUTH_FAILURE）。
var errAuthFailed = errors.New("permission denied")

// Options SSH 蜜罐启动参数。
type Options struct {
	// Addr 监听地址，如 ":2222"。
	Addr      string
	FS        *vfs.FS
	Events    *attacklog.Logger
	Guard     *auth.Guard
	Hostname  string
	Processor shell.Processor
	Logger    *slog.Logger

	// HostKeyPath 新 hostkey 路径，默认 DefaultHostKeyPath。
	HostKeyPath string
	// LegacyHostKeyPath 旧 hostkey 路径，默认 DefaultLegacyHostKeyPath。
	LegacyHostKeyPath string
}

// Server SSH 蜜罐服务。
type Server struct {
	opts   Options
	config *ssh.ServerConfig
	ln     net.Listener

	active atomic.Int64
	wg     sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	closeOnce sync.Once
}

// New 构造 SSH 蜜罐服务（加载/生成 hostkey，不监听端口）。
func New(opts Options) (*Server, error) {
	if opts.FS == nil {
		return nil, errors.New("sshpot: FS 不能为空")
	}
	if opts.Events == nil {
		return nil, errors.New("sshpot: Events 不能为空")
	}
	if opts.Processor == nil {
		return nil, errors.New("sshpot: Processor 不能为空")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.HostKeyPath == "" {
		opts.HostKeyPath = DefaultHostKeyPath
	}
	if opts.LegacyHostKeyPath == "" {
		opts.LegacyHostKeyPath = DefaultLegacyHostKeyPath
	}

	s := &Server{opts: opts, conns: make(map[net.Conn]struct{}, maxSessions)}

	signer, err := loadOrCreateHostKey(opts.HostKeyPath, opts.LegacyHostKeyPath, opts.Logger)
	if err != nil {
		return nil, err
	}

	s.config = &ssh.ServerConfig{
		ServerVersion:     serverVersion,
		MaxAuthTries:      6,
		PasswordCallback:  s.passwordCallback,
		PublicKeyCallback: s.publicKeyCallback,
	}
	s.config.AddHostKey(signer)
	return s, nil
}

// Start 开始监听并接受连接（非阻塞）。
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("SSH 监听 %s 失败: %w", s.opts.Addr, err)
	}
	s.ln = ln
	go s.acceptLoop()
	infof(s.opts.Logger, "SSH 蜜罐已启动，监听 "+ln.Addr().String())
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
			warnf(s.opts.Logger, "SSH 会话未在 5s 内全部关闭")
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
			warnf(s.opts.Logger, "SSH 接受连接失败: "+err.Error())
			continue
		}
		if s.active.Add(1) > maxSessions {
			s.active.Add(-1)
			warnf(s.opts.Logger, fmt.Sprintf("SSH 并发会话超过 %d，拒绝新连接 %s", maxSessions, conn.RemoteAddr()))
			_ = conn.Close()
			continue
		}
		s.trackConn(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			defer s.active.Add(-1)
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

func (s *Server) handleConn(conn net.Conn) {
	// 攻击者输入会一路流到伪 Shell：任何一处 panic 只允许断开本连接，
	// 不能让整个进程（其余协议与会话）一起退出。
	defer safe.Recover(s.opts.Logger, "ssh 连接")
	defer conn.Close()
	begin := time.Now()

	// 握手（含认证）限时，避免慢速攻击长期占用会话额度
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		// 握手/认证失败：事件已由认证回调记录，这里只留调试信息
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer serverConn.Close()
	// 认证成功时补 session_close：ssh 会话代表「一次连接」，连接结束才关闭，
	// 否则失败尝试已闭合、成功尝试永远挂着，Web 端在线会话统计会持续累积。
	ip, _ := addrParts(conn.RemoteAddr())
	if perm := serverConn.Permissions; perm != nil {
		if sid := perm.Extensions["sid"]; sid != "" {
			defer func() { s.opts.Events.SessionClose(sid, ip, time.Since(begin).Milliseconds()) }()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.keepalive(ctx, serverConn)

	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			go s.handleSession(newChan, serverConn)
		default:
			// 未识别的 channel 类型按真实 OpenSSH 行为拒绝
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// 认证

// passwordCallback 密码认证：按密码本校验，所有尝试均记录日志。
//
// 事件分层（硬契约）：成功与失败都记录 auth_attempt + session_open；失败立即
// session_close(duration=0)，成功则把 sid 放到 Permissions，由 handleConn 在连接
// 结束时补 session_close，保证 Web 端会话统计覆盖全部爆破源连接且不会永久挂起。
func (s *Server) passwordCallback(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ip, port := addrParts(meta.RemoteAddr())
	user := meta.User()
	sid := s.opts.Events.NewSessionID()

	ok := s.opts.Guard.Authenticate(ip, user, string(password))
	s.opts.Events.AuthAttempt(sid, "ssh", ip, user, string(password), ok)
	s.opts.Events.SessionOpen(sid, "ssh", ip, port)
	if !ok {
		s.opts.Events.SessionClose(sid, ip, 0)
		return nil, errAuthFailed
	}
	return &ssh.Permissions{Extensions: map[string]string{"user": user, "sid": sid}}, nil
}

// publicKeyCallback 公钥认证：记录算法并拒绝（攻击者极少有合法公钥，拒绝更像真实主机）；
// 失败同样计入 CredentialGuard 锁定，防止改用公钥爆破绕过失败锁定策略。
func (s *Server) publicKeyCallback(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	ip, port := addrParts(meta.RemoteAddr())
	s.opts.Guard.RecordFailure(ip)
	sid := s.opts.Events.NewSessionID()
	s.opts.Events.AuthAttempt(sid, "ssh", ip, meta.User(), "[pubkey:"+key.Type()+"]", false)
	s.opts.Events.SessionOpen(sid, "ssh", ip, port)
	s.opts.Events.SessionClose(sid, ip, 0)
	return nil, errAuthFailed
}

// 心跳

// keepalive 定期发送 keepalive@openssh.com 全局请求，连续无应答达上限判定死连接并关闭。
func (s *Server) keepalive(ctx context.Context, conn *ssh.ServerConn) {
	defer safe.Recover(s.opts.Logger, "ssh 心跳")
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	missed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			done := make(chan error, 1)
			go func() {
				defer safe.Recover(s.opts.Logger, "ssh 心跳请求")
				_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					missed = 0
					continue
				}
				missed++
			case <-time.After(heartbeatReplyTimeout):
				missed++
			}
			if missed >= heartbeatMaxMissed {
				warnf(s.opts.Logger, fmt.Sprintf("SSH 连接 %s 心跳无应答，关闭会话", conn.RemoteAddr()))
				_ = conn.Close()
				return
			}
		}
	}
}

// 会话 / 通道

// handleSession 处理单个 session 通道的请求流：pty-req、window-change、env、shell、exec。
func (s *Server) handleSession(newChan ssh.NewChannel, conn *ssh.ServerConn) {
	// 会话通道在独立 goroutine 中运行，panic 必须就地收敛
	defer safe.Recover(s.opts.Logger, "ssh session 通道")
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	username := "root"
	if v, ok := conn.Permissions.Extensions["user"]; ok && v != "" {
		username = v
	}

	var started bool
	done := make(chan struct{})

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			// TERM + 行列：仅记录，供 stty/tput 类命令使用
			if _, _, ok := parsePtyReq(req.Payload); !ok {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
		case "window-change":
			parseWindowChange(req.Payload)
			_ = req.Reply(true, nil)
		case "env":
			_ = req.Reply(true, nil)
		case "shell":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			_ = req.Reply(true, nil)
			go drainRequests(reqs)
			go func() {
				defer close(done)
				s.runShell(ch, conn, username)
			}()
		case "exec":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			command, ok := parseExecPayload(req.Payload)
			if !ok {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go drainRequests(reqs)
			go func() {
				defer close(done)
				s.runExec(ch, conn, username, command)
			}()
		default:
			// subsystem(sftp) 等：与真实主机未启用该功能一致，直接拒绝
			_ = req.Reply(false, nil)
		}

		if started {
			<-done
			return
		}
	}
}

// drainRequests 会话启动后继续应答剩余请求，避免客户端因请求无响应而阻塞传输层。
func drainRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		_ = req.Reply(false, nil)
	}
}

// runShell 运行交互式伪 Shell（protocol=ssh-shell）。
func (s *Server) runShell(ch ssh.Channel, conn *ssh.ServerConn, username string) {
	defer safe.Recover(s.opts.Logger, "ssh 交互会话")
	ip, port := addrParts(conn.RemoteAddr())
	st := shell.NewSession(s.opts.Events.NewSessionID(), ip, username, s.opts.FS, s.opts.Hostname)
	s.opts.Events.SessionOpen(st.ID, "ssh-shell", ip, port)

	sh := shell.NewShell(ch, ch, st, s.opts.Processor, s.opts.Events, nil)
	sh.Run()

	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 0}))
}

// runExec 执行 exec 命令（protocol=ssh-exec），结束时补 session_close。
func (s *Server) runExec(ch ssh.Channel, conn *ssh.ServerConn, username, command string) {
	defer safe.Recover(s.opts.Logger, "ssh exec 会话")
	begin := time.Now()
	ip, port := addrParts(conn.RemoteAddr())
	st := shell.NewSession(s.opts.Events.NewSessionID(), ip, username, s.opts.FS, s.opts.Hostname)
	s.opts.Events.SessionOpen(st.ID, "ssh-exec", ip, port)

	res := s.opts.Processor.Execute(st, command)
	if !res.Exit && res.Text != "" {
		_, _ = ch.Write([]byte(res.Text))
	}
	s.opts.Events.SessionClose(st.ID, ip, time.Since(begin).Milliseconds())
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 0}))
}

// exitStatus SSH_MSG_CHANNEL_REQUEST "exit-status" 的载荷。
type exitStatus struct {
	Status uint32
}

// ptyRequest RFC 4254 §6.2 pty-req 载荷。
type ptyRequest struct {
	Term    string
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
	Modes   string
}

// windowChange RFC 4254 §6.7 window-change 载荷。
type windowChange struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

func parsePtyReq(payload []byte) (cols, rows uint32, ok bool) {
	var req ptyRequest
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return 0, 0, false
	}
	return req.Columns, req.Rows, true
}

func parseWindowChange(payload []byte) (cols, rows uint32, ok bool) {
	var req windowChange
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return 0, 0, false
	}
	return req.Columns, req.Rows, true
}

// parseExecPayload 解析 exec 请求的 command 字段（RFC 4254 §6.5）。
func parseExecPayload(payload []byte) (string, bool) {
	var req struct {
		Command string
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return "", false
	}
	return req.Command, true
}

// addrParts 拆分远端地址为 IP 与端口（与 Java 版 getHostAddress 输出一致，v4-mapped 归一为点分十进制）。
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

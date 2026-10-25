// Package dbpot 数据库蜜罐（MySQL / PostgreSQL / Redis）。
//
// 三种协议共用同一套连接骨架：监听、并发限流、会话开闭日志、读超时、
// 关闭时中断在途连接；协议差异只体现在报文解析与错误响应上。
//
// 设计要点（与 Java 版一致）：
//   - 无论提交什么凭证一律返回认证失败，同时把凭证写入 auth_attempt 事件
//   - 活跃连接数超限时返回协议标准的「连接数超限」响应后断开
//   - 未收到完整登录报文（扫描器/提前断开）时静默断开，不发送多余报文
package dbpot

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/attacklog"
)

const (
	// maxConnections 最大并发连接数：超限连接返回协议标准错误后断开，防连接洪泛。
	maxConnections = 20
	// readTimeout 等待客户端报文的最长时间，防止扫描器挂住连接。
	readTimeout = 15 * time.Second
)

// Options 数据库蜜罐启动参数。
type Options struct {
	// Addr 监听地址，如 ":3306"。
	Addr   string
	Events *attacklog.Logger
	Logger *slog.Logger
}

// conn 一条数据库蜜罐连接及其会话上下文。
type conn struct {
	srv   *Server
	nc    net.Conn
	br    *bufio.Reader
	ip    string
	port  int
	id    string
	start time.Time
}

// write 发送响应字节（错误忽略：客户端提前断开属正常现象）。
func (c *conn) write(b []byte) {
	_, _ = c.nc.Write(b)
}

// Server 数据库蜜罐服务（三种协议共用）。
type Server struct {
	proto   string
	label   string
	version string
	opts    Options
	handle  func(*conn)
	tooMany []byte

	ln     net.Listener
	active atomic.Int64
	wg     sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	closeOnce sync.Once
}

// newServer 构造数据库蜜罐（不监听端口）。
func newServer(proto, label, version string, opts Options, tooMany []byte, handle func(*conn)) (*Server, error) {
	if opts.Events == nil {
		return nil, errors.New(proto + ": Events 不能为空")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Server{
		proto:   proto,
		label:   label,
		version: version,
		opts:    opts,
		handle:  handle,
		tooMany: tooMany,
		conns:   make(map[net.Conn]struct{}, maxConnections),
	}, nil
}

// Start 开始监听并接受连接（非阻塞）。
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("%s 监听 %s 失败: %w", s.label, s.opts.Addr, err)
	}
	s.ln = ln
	go s.acceptLoop()
	infof(s.opts.Logger, fmt.Sprintf("%s 蜜罐已启动，监听 %s（%s，最大并发连接 %d）",
		s.label, ln.Addr(), s.version, maxConnections))
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
			warnf(s.opts.Logger, s.label+" 会话未在 5s 内全部关闭")
		}
	})
	return nil
}

func (s *Server) acceptLoop() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			warnf(s.opts.Logger, s.label+" 接受连接失败: "+err.Error())
			continue
		}
		s.trackConn(nc)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(nc)
			defer nc.Close()
			s.handleConn(nc)
		}()
	}
}

func (s *Server) trackConn(nc net.Conn) {
	s.connMu.Lock()
	s.conns[nc] = struct{}{}
	s.connMu.Unlock()
}

func (s *Server) untrackConn(nc net.Conn) {
	s.connMu.Lock()
	delete(s.conns, nc)
	s.connMu.Unlock()
}

// handleConn 限流 + 会话开闭日志 + 超时设置，然后交给协议处理器。
func (s *Server) handleConn(nc net.Conn) {
	ip, port := addrParts(nc.RemoteAddr())
	c := &conn{
		srv:   s,
		nc:    nc,
		br:    bufio.NewReaderSize(nc, 1024),
		ip:    ip,
		port:  port,
		id:    s.opts.Events.NewSessionID(),
		start: time.Now(),
	}
	s.opts.Events.SessionOpen(c.id, s.proto, ip, port)
	defer func() {
		s.opts.Events.SessionClose(c.id, ip, time.Since(c.start).Milliseconds())
	}()

	// 并发限流：先原子递增再判断，保证并发下不超限
	if s.active.Add(1) > maxConnections {
		s.active.Add(-1)
		_ = nc.SetWriteDeadline(time.Now().Add(readTimeout))
		c.write(s.tooMany)
		return
	}
	defer s.active.Add(-1)

	_ = nc.SetReadDeadline(time.Now().Add(readTimeout))
	s.handle(c)
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

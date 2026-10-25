// Package web 是蜜罐的 Web 可视化控制台：内嵌前端资源 + REST API + 服务端会话。
//
// 与 Java 版（Javalin/Jetty 实现）保持行为一致的要点：
//   - 23 条 API 路由、响应包络 {"ok":true,"data":...} / {"ok":false,"error":"..."}；
//   - 中间件顺序：请求体限额 → 审计采集 → 鉴权 → 业务处理 → 审计异步落库；
//   - 会话存内存（Cookie 名 JSESSIONID、HttpOnly、SameSite=Lax），滑动过期，登录成功换新 ID；
//   - 登录失败 5 次锁定来源 IP 15 分钟（独立于蜜罐源 IP 锁定策略）；
//   - 系统用户存 sys_users（PBKDF2-HMAC-SHA256），操作审计存 sys_audit_log。
package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/geo"
	webassets "git.pi.mmxx.fun/tool/ssh-honeypot-go/web"
)

// maxBodyBytes 请求体大小上限：控制台请求体均为小 JSON，超过即拒绝，
// 防恶意客户端提交超大 body 被全量读入内存并撑爆审计表。
const maxBodyBytes = 1024 * 1024

// errBodyTooLarge 请求体超限（映射 HTTP 413）。
var errBodyTooLarge = errors.New("请求体过大")

// Options Web 控制台启动参数。
type Options struct {
	// Addr 监听地址，如 ":8080"。
	Addr string
	// DBPath SQLite 数据库文件（与攻击日志同库）。
	DBPath string
	// SessionTimeoutMinutes 管理端登录会话滑动过期时间（分钟）。
	SessionTimeoutMinutes int
	// Locator IP 归属地定位器（审计日志记录来源归属地），可为 nil。
	Locator *geo.Locator
	// Logger 运行日志。
	Logger *slog.Logger
}

// Server Web 控制台服务器。
type Server struct {
	opts   Options
	logger *slog.Logger

	readDB  *sql.DB
	writeDB *sql.DB

	logs     *LogRepo
	users    *UserRepo
	audit    *AuditRepo
	auth     *Auth
	sessions *SessionStore

	httpServer *http.Server
	ln         net.Listener
	closeOnce  sync.Once
}

// New 打开数据库、初始化系统表并装配路由；不监听端口。
func New(opts Options) (*Server, error) {
	if strings.TrimSpace(opts.DBPath) == "" {
		return nil, errors.New("Web 控制台缺少数据库路径")
	}
	logger := opts.Logger

	// 先开写连接：由它把数据库切到 WAL（数据库级持久设置），只读连接随后自然继承
	writeDB, err := openWriteDB(opts.DBPath)
	if err != nil {
		return nil, err
	}
	readDB, err := openReadDB(opts.DBPath)
	if err != nil {
		writeDB.Close()
		return nil, err
	}
	users, err := newUserRepo(writeDB, logger)
	if err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, err
	}
	// 避免 typed-nil 接口：未配置定位器时留空接口，Record 处以 nil 判定跳过
	var locator GeoLocator
	if opts.Locator != nil {
		locator = opts.Locator
	}
	audit, err := newAuditRepo(writeDB, readDB, locator, logger)
	if err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, err
	}

	s := &Server{
		opts:     opts,
		logger:   logger,
		readDB:   readDB,
		writeDB:  writeDB,
		logs:     newLogRepo(readDB),
		users:    users,
		audit:    audit,
		sessions: newSessionStore(time.Duration(opts.SessionTimeoutMinutes) * time.Minute),
	}
	s.auth = newAuth(users, logger)
	s.httpServer = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s, nil
}

// Start 开始监听；返回错误时调用方仅告警，不影响蜜罐其余服务。
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("Web 控制台监听 %s 失败: %w", s.opts.Addr, err)
	}
	s.ln = ln

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			warnf(s.logger, "Web 控制台服务异常退出: "+err.Error())
		}
	}()

	port := s.opts.Addr
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		port = strconv.Itoa(tcp.Port)
	}
	infof(s.logger, "Web 控制台已启动: http://<host>:"+port+"/ （默认管理员 "+
		defaultAdminUsername+"/"+defaultAdminPassword+"，首次登录强制改密）")
	return nil
}

// Addr 实际监听地址（端口为 0 时便于测试获取随机端口）。
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close 停止 HTTP 服务并释放连接（先排空审计队列，再关库）。
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.httpServer != nil {
			err = s.httpServer.Shutdown(ctx)
		}
		if s.audit != nil {
			s.audit.Close()
		}
		if s.sessions != nil {
			s.sessions.Close()
		}
		if s.readDB != nil {
			_ = s.readDB.Close()
		}
		if s.writeDB != nil {
			_ = s.writeDB.Close()
		}
	})
	return err
}

// routes 注册 23 条 API（Go 1.22+ ServeMux 原生支持方法 + 路径参数）。
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// 认证
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("PUT /api/password", s.handleChangePassword)

	// 攻击日志统计
	mux.HandleFunc("GET /api/stats/overview", s.handleOverview)
	mux.HandleFunc("GET /api/stats/trend", s.handleTrend)
	mux.HandleFunc("GET /api/stats/protocol", s.handleProtocolDist)
	mux.HandleFunc("GET /api/stats/top-ips", s.handleTopIPs)
	mux.HandleFunc("GET /api/stats/top-locations", s.handleTopLocations)
	mux.HandleFunc("GET /api/stats/top-usernames", s.handleTopUsernames)
	mux.HandleFunc("GET /api/stats/top-passwords", s.handleTopPasswords)

	// 攻击日志明细
	mux.HandleFunc("GET /api/sessions", s.handleSessions)
	mux.HandleFunc("GET /api/auth-attempts", s.handleAuthAttempts)
	mux.HandleFunc("GET /api/commands", s.handleCommands)
	mux.HandleFunc("GET /api/downloads", s.handleDownloads)
	mux.HandleFunc("GET /api/ip-locks", s.handleIPLocks)

	// 操作审计（仅 admin）
	mux.HandleFunc("GET /api/audit-logs", s.handleAuditLogs)
	mux.HandleFunc("GET /api/audit-logs/trend", s.handleAuditTrend)

	// 系统用户管理（仅 admin）
	mux.HandleFunc("GET /api/users", s.handleUsers)
	mux.HandleFunc("POST /api/users", s.handleUserCreate)
	mux.HandleFunc("PUT /api/users/{id}/status", s.handleUserStatus)
	mux.HandleFunc("PUT /api/users/{id}/password", s.handleUserPassword)
	mux.HandleFunc("DELETE /api/users/{id}", s.handleUserDelete)

	// ECharts 图表库：请求时从内嵌资源流式输出，不常驻堆内存
	mux.HandleFunc("GET /api/vendor/echarts.js", s.handleECharts)

	// 前端静态资源（页面）
	mux.HandleFunc("/", s.handleStatic)

	return s.middleware(mux)
}

// bodyKey 缓存审计采集阶段读取的请求体，避免业务处理器二次读取。
type bodyKey struct{}

// auditKey / auditState 在请求生命周期内传递审计上下文。
// 登录接口在响应前才建立会话，Cookie 尚未回到客户端，审计落库需由处理器回填本次登录用户名。
type auditKey struct{}

type auditState struct {
	username string
}

func auditStateFrom(r *http.Request) *auditState {
	if state, ok := r.Context().Value(auditKey{}).(*auditState); ok {
		return state
	}
	return nil
}

// middleware 中间件链：请求体限额 → 审计采集 → 鉴权 → 业务处理 → 审计落库。
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1) 请求体限额（Content-Length 预检）
		if r.ContentLength > maxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "请求体过大")
			return
		}

		// 2) 审计采集：仅 API 且非 vendor 静态资源
		audited := isAuditedPath(r.URL.Path)
		var (
			auditStart time.Time
			reqBody    []byte
			state      *auditState
		)
		if audited {
			auditStart = time.Now()
			body, err := readLimitedBody(r)
			if err != nil {
				writeError(w, http.StatusRequestEntityTooLarge, "请求体过大")
				return
			}
			reqBody = body
			state = &auditState{}
			ctx := context.WithValue(r.Context(), bodyKey{}, body)
			ctx = context.WithValue(ctx, auditKey{}, state)
			r = r.WithContext(ctx)
		}

		// 3) 鉴权：登录接口与登录页静态资源放行
		if s.sessionFrom(r) == nil && !isPublicPath(r.URL.Path) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
			} else {
				http.Redirect(w, r, "/login.html", http.StatusFound)
			}
			return
		}

		// 4) 业务处理（记录实际状态码供审计使用）
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		// 5) 审计落库（异步）
		if !audited {
			return
		}
		status := recorder.status
		ok := status < http.StatusBadRequest
		respBody := `{"ok":true}`
		if !ok {
			respBody = `{"ok":false,"status":` + strconv.Itoa(status) + `}`
		}
		username := ""
		if state != nil {
			username = state.username
		}
		if username == "" {
			if sess := s.sessionFrom(r); sess != nil {
				username = sess.Username
			}
		}
		s.audit.Record(username, ClientIP(r), r.Method, r.URL.Path, r.URL.RawQuery,
			maskBody(string(reqBody)), status, respBody,
			time.Since(auditStart).Milliseconds(), ok)
	})
}

// isAuditedPath 是否需要记录操作审计。
func isAuditedPath(p string) bool {
	return strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/api/vendor/")
}

// isPublicPath 无需登录即可访问的路径：登录接口、登录页及其静态资源。
func isPublicPath(p string) bool {
	if p == "/api/login" {
		return true
	}
	if strings.HasPrefix(p, "/api/") {
		return false
	}
	return p == "/login.html" || p == "/favicon.ico" ||
		strings.HasPrefix(p, "/css/") || strings.HasPrefix(p, "/js/") || strings.HasPrefix(p, "/img/")
}

// readLimitedBody 读取并缓存请求体，超限返回 errBodyTooLarge。
func readLimitedBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBodyBytes {
		return nil, errBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}

// sessionFrom 读取 Cookie 并返回有效会话（顺延过期时间）。
func (s *Server) sessionFrom(r *http.Request) *Session {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	return s.sessions.Get(cookie.Value)
}

// setSessionCookie 下发会话 Cookie（HttpOnly 阻断脚本窃取，SameSite=Lax 缓解 CSRF）。
func setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie 让浏览器立即丢弃会话 Cookie。
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

// handleStatic 输出前端静态资源（禁止目录浏览，禁止直接访问 vendor）。
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/") {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	if strings.HasPrefix(p, "/vendor/") {
		http.NotFound(w, r)
		return
	}
	// HTML/JS/CSS 禁用缓存，确保升级与改密等状态变更后浏览器始终加载最新版本
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// 目录请求归一为 index.html；非法路径经 Clean 归一后不可能越出内嵌资源根
	name := strings.TrimPrefix(path.Clean("/"+p), "/")
	if name == "" || name == "." {
		name = "index.html"
	}
	file, err := webassets.FS.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	seeker, ok := file.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, info.Name(), info.ModTime(), bytes.NewReader(data))
		return
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), seeker)
}

// handleECharts 输出 ECharts 图表库（屏蔽 WebJar 版本号依赖）。
func (s *Server) handleECharts(w http.ResponseWriter, r *http.Request) {
	file, err := webassets.FS.Open("vendor/echarts.min.js")
	if err != nil {
		s.internalError(w, r, fmt.Errorf("ECharts 资源读取失败: %w", err))
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if seeker, ok := file.(io.ReadSeeker); ok {
		http.ServeContent(w, r, "echarts.min.js", time.Time{}, seeker)
		return
	}
	data, err := io.ReadAll(file)
	if err != nil {
		s.internalError(w, r, fmt.Errorf("ECharts 资源读取失败: %w", err))
		return
	}
	http.ServeContent(w, r, "echarts.min.js", time.Time{}, bytes.NewReader(data))
}

// statusRecorder 记录实际写出的状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if !r.wrote {
		r.status = status
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

func infof(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Info(msg)
	}
}

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// usernamePattern 用户名规则：字母、数字、下划线、点、短横线，长度 2-32。
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{2,32}$`)

// ============================ 响应与参数工具 ============================

// writeJSON 输出 JSON 响应（关闭 HTML 转义，与 Java 版 Gson 输出一致）。
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)
}

// writeError 输出失败包络 {"ok":false,"error":"..."}。
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": message})
}

// writeOK 输出成功包络 {"ok":true,"data":...}。
func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
}

// writeUser 输出用户包络 {"ok":true,"user":...}（登录与 /api/me 专用）。
func writeUser(w http.ResponseWriter, user *User) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
}

// internalError 记录异常并返回 500。
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	if s.logger != nil {
		s.logger.Warn(fmt.Sprintf("Web 请求处理失败: %s %s -> %v", r.Method, r.URL.Path, err))
	}
	writeError(w, http.StatusInternalServerError, "服务器内部错误")
}

// requireAdmin 校验管理员角色；失败时已写出响应。
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, sess *Session) bool {
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
		return false
	}
	if sess.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "仅管理员可执行该操作")
		return false
	}
	return true
}

// requestBody 返回中间件缓存的请求体。
func requestBody(r *http.Request) []byte {
	if data, ok := r.Context().Value(bodyKey{}).([]byte); ok {
		return data
	}
	return nil
}

// parseBody 解析请求体为 JSON 对象；空体视为空对象，非法 JSON 返回错误。
// 与 Java 版 Gson 行为一致：容忍 UTF-8 BOM（手工构造的请求文件常见）。
func parseBody(r *http.Request) (map[string]any, error) {
	data := bytes.TrimPrefix(requestBody(r), []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// str 取字符串参数并去空白（对应 Java 版 String.valueOf(o).trim()）。
func str(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// queryInt 整数查询参数，缺省或非法时返回默认值。
func queryInt(r *http.Request, name string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// queryLong 长整数查询参数，缺省或非法时返回 nil。
func queryLong(r *http.Request, name string) *int64 {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

// queryBool 布尔查询参数（1/true 为真），缺省返回 nil。
func queryBool(r *http.Request, name string) *bool {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return nil
	}
	b := v == "1" || strings.EqualFold(v, "true")
	return &b
}

func pageParam(r *http.Request) int {
	return max(1, queryInt(r, "page", 1))
}

func sizeParam(r *http.Request) int {
	return min(200, max(1, queryInt(r, "size", 20)))
}

func limitParam(r *http.Request) int {
	return min(50, max(1, queryInt(r, "limit", 10)))
}

func daysParam(r *http.Request) int {
	return min(30, max(1, queryInt(r, "days", 14)))
}

// pathID 解析路径参数 {id}。
func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// ============================ 认证相关 ============================

// handleLogin POST /api/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	username := str(body["username"])
	password := str(body["password"])
	if username == "" || password == "" {
		writeError(w, http.StatusBadRequest, "请输入用户名和密码")
		return
	}

	result, err := s.auth.login(ClientIP(r), username, password)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if result.User == nil {
		writeError(w, http.StatusUnauthorized, result.Err)
		return
	}

	// 登录成功换新会话 ID，防会话固定攻击
	if old := s.sessionFrom(r); old != nil {
		s.sessions.Destroy(old.ID)
	}
	sess := s.sessions.Create(result.User.ID, result.User.Username, result.User.Role)
	setSessionCookie(w, sess.ID)
	if state := auditStateFrom(r); state != nil {
		state.username = result.User.Username
	}
	writeUser(w, result.User)
}

// handleLogout POST /api/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := s.sessionFrom(r); sess != nil {
		s.sessions.Destroy(sess.ID)
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMe GET /api/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	user, err := s.users.findById(sess.UID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if user == nil || !user.Enabled {
		// 账号已删除/禁用，清除残留会话
		s.sessions.Destroy(sess.ID)
		clearSessionCookie(w)
		writeError(w, http.StatusUnauthorized, "账号不可用")
		return
	}
	writeUser(w, user)
}

// handleChangePassword PUT /api/password
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	oldPassword := str(body["oldPassword"])
	newPassword := str(body["newPassword"])
	if msg := checkPassword(newPassword); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	dbUser, err := s.users.findByUsername(sess.Username)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if dbUser == nil || !verifyPassword(oldPassword, dbUser.PasswordHash) {
		writeError(w, http.StatusBadRequest, "原密码错误")
		return
	}
	if err := s.users.changePassword(sess.UID, newPassword); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ============================ 攻击日志统计 ============================

// handleOverview GET /api/stats/overview
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.Overview()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleTrend GET /api/stats/trend
func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.Trend(daysParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleProtocolDist GET /api/stats/protocol
func (s *Server) handleProtocolDist(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.ProtocolDist()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleTopIPs GET /api/stats/top-ips
func (s *Server) handleTopIPs(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.TopIPs(limitParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleTopLocations GET /api/stats/top-locations
func (s *Server) handleTopLocations(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.TopLocations(limitParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleTopUsernames GET /api/stats/top-usernames
func (s *Server) handleTopUsernames(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.TopUsernames(limitParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleTopPasswords GET /api/stats/top-passwords
func (s *Server) handleTopPasswords(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.TopPasswords(limitParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// ============================ 攻击日志明细 ============================

// handleSessions GET /api/sessions
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, err := s.logs.Sessions(q.Get("srcIp"), q.Get("protocol"),
		queryLong(r, "start"), queryLong(r, "end"), pageParam(r), sizeParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleAuthAttempts GET /api/auth-attempts
func (s *Server) handleAuthAttempts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, err := s.logs.AuthAttempts(q.Get("srcIp"), q.Get("username"), q.Get("protocol"),
		queryBool(r, "success"), queryLong(r, "start"), queryLong(r, "end"), pageParam(r), sizeParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleCommands GET /api/commands
func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, err := s.logs.Commands(q.Get("sessionId"), q.Get("srcIp"), q.Get("username"), q.Get("keyword"),
		queryLong(r, "start"), queryLong(r, "end"), pageParam(r), sizeParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleDownloads GET /api/downloads
func (s *Server) handleDownloads(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, err := s.logs.Downloads(q.Get("srcIp"), q.Get("keyword"),
		queryLong(r, "start"), queryLong(r, "end"), pageParam(r), sizeParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleIPLocks GET /api/ip-locks
func (s *Server) handleIPLocks(w http.ResponseWriter, r *http.Request) {
	data, err := s.logs.IPLocks(r.URL.Query().Get("srcIp"), pageParam(r), sizeParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// ============================ 操作审计（仅 admin） ============================

// handleAuditLogs GET /api/audit-logs
func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, s.sessionFrom(r)) {
		return
	}
	q := r.URL.Query()
	data, err := s.audit.List(auditListQuery{
		username:    q.Get("username"),
		srcIP:       q.Get("srcIp"),
		method:      q.Get("method"),
		pathKeyword: q.Get("path"),
		start:       queryLong(r, "start"),
		end:         queryLong(r, "end"),
		page:        pageParam(r),
		size:        sizeParam(r),
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// handleAuditTrend GET /api/audit-logs/trend
func (s *Server) handleAuditTrend(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, s.sessionFrom(r)) {
		return
	}
	data, err := s.audit.Trend(daysParam(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, data)
}

// ============================ 系统用户管理（仅 admin） ============================

// handleUsers GET /api/users
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, s.sessionFrom(r)) {
		return
	}
	users, err := s.users.list()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeOK(w, users)
}

// handleUserCreate POST /api/users
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, s.sessionFrom(r)) {
		return
	}
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	username := str(body["username"])
	password := str(body["password"])
	role := str(body["role"])

	if !usernamePattern.MatchString(username) {
		writeError(w, http.StatusBadRequest, "用户名仅允许字母、数字、下划线、点、短横线，长度 2-32")
		return
	}
	if msg := checkPassword(password); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if role != RoleAdmin && role != RoleViewer {
		writeError(w, http.StatusBadRequest, "角色非法，仅支持 admin / viewer")
		return
	}

	existing, err := s.users.findByUsername(username)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if existing != nil {
		writeError(w, http.StatusBadRequest, "用户名已存在")
		return
	}

	mustChange := true
	if v, ok := body["mustChange"].(bool); ok {
		mustChange = v
	}
	id, err := s.users.create(username, password, role, mustChange)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "data": map[string]any{"id": id}})
}

// handleUserStatus PUT /api/users/{id}/status
func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	self := s.sessionFrom(r)
	if !s.requireAdmin(w, r, self) {
		return
	}
	targetID, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "用户 ID 非法")
		return
	}
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	enabled, ok := body["enabled"].(bool)
	if !ok {
		writeError(w, http.StatusBadRequest, "参数 enabled 缺失")
		return
	}

	target, err := s.users.findById(targetID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	if !enabled && target.Role == RoleAdmin {
		if targetID == self.UID {
			writeError(w, http.StatusBadRequest, "不能禁用当前登录账号")
			return
		}
		admins, err := s.users.countAdmins()
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if admins <= 1 {
			writeError(w, http.StatusBadRequest, "至少保留一个启用状态的管理员")
			return
		}
	}
	if err := s.users.setStatus(targetID, enabled); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUserPassword PUT /api/users/{id}/password
func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, s.sessionFrom(r)) {
		return
	}
	targetID, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "用户 ID 非法")
		return
	}
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	password := str(body["password"])
	if msg := checkPassword(password); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	target, err := s.users.findById(targetID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	mustChange := true
	if v, ok := body["mustChange"].(bool); ok {
		mustChange = v
	}
	if err := s.users.resetPassword(targetID, password, mustChange); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUserDelete DELETE /api/users/{id}
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	self := s.sessionFrom(r)
	if !s.requireAdmin(w, r, self) {
		return
	}
	targetID, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "用户 ID 非法")
		return
	}
	if targetID == self.UID {
		writeError(w, http.StatusBadRequest, "不能删除当前登录账号")
		return
	}

	target, err := s.users.findById(targetID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	if target.Role == RoleAdmin {
		admins, err := s.users.countAdmins()
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if admins <= 1 {
			writeError(w, http.StatusBadRequest, "至少保留一个启用状态的管理员")
			return
		}
	}
	if err := s.users.delete(targetID); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// checkPassword 校验口令长度（按字符数，与 Java 版 String.length 语义接近）；合法返回空串。
func checkPassword(password string) string {
	if len([]rune(password)) < 8 {
		return "密码长度至少 8 位"
	}
	return ""
}

package web

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GeoLocator IP 归属地解析（*geo.Locator 实现；可为 nil，此时归属地留空）。
type GeoLocator interface {
	Locate(ip string) string
}

// sqlCreateAudit 系统操作审计表（DDL 与 Java 版逐字一致）。
const sqlCreateAudit = `
CREATE TABLE IF NOT EXISTS sys_audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,                 -- 操作时间 yyyy-MM-dd HH:mm:ss
    epoch_ms    INTEGER NOT NULL,                 -- 毫秒时间戳（排序/范围过滤）
    username    TEXT,                             -- 操作用户名（未登录为 NULL）
    src_ip      TEXT    NOT NULL,                 -- 来源 IP
    method      TEXT    NOT NULL,                 -- HTTP 方法
    path        TEXT    NOT NULL,                 -- 请求路径
    path_desc   TEXT,                             -- 路径中文描述（按方法+路由模式映射）
    query       TEXT,                             -- 查询串
    req_body    TEXT,                             -- 请求体（敏感字段脱敏）
    status      INTEGER NOT NULL,                 -- 响应状态码
    resp_body   TEXT,                             -- 响应体摘要（截断）
    duration_ms INTEGER NOT NULL,                 -- 处理耗时（毫秒）
    ok          INTEGER NOT NULL,                 -- 1 成功 / 0 失败
    location    TEXT                              -- 来源 IP 归属地
)`

// auditIndexes 审计表索引（幂等）。
var auditIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_audit_epoch ON sys_audit_log(epoch_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_user ON sys_audit_log(username)`,
}

// pathDescMap 路径 → 中文描述：键为「方法 路由模式」（数字路径段归一为 {id}），覆盖全部 23 条路由。
var pathDescMap = map[string]string{
	// 认证
	"POST /api/login":   "用户登录",
	"POST /api/logout":  "退出登录",
	"GET /api/me":       "获取当前用户信息",
	"PUT /api/password": "修改登录密码",
	// 攻击日志统计
	"GET /api/stats/overview":      "攻击总览统计",
	"GET /api/stats/trend":         "攻击趋势统计",
	"GET /api/stats/protocol":      "协议分布统计",
	"GET /api/stats/top-ips":       "攻击源 IP TOP 统计",
	"GET /api/stats/top-locations": "攻击源地区 TOP 统计",
	"GET /api/stats/top-usernames": "高频爆破用户名统计",
	"GET /api/stats/top-passwords": "高频尝试口令统计",
	// 攻击日志明细
	"GET /api/sessions":      "会话记录查询",
	"GET /api/auth-attempts": "登录尝试查询",
	"GET /api/commands":      "命令记录查询",
	"GET /api/downloads":     "恶意下载查询",
	"GET /api/ip-locks":      "IP 锁定记录查询",
	// 操作审计
	"GET /api/audit-logs":       "审计日志查询",
	"GET /api/audit-logs/trend": "审计日志趋势统计",
	// 系统用户管理
	"GET /api/users":               "用户列表查询",
	"POST /api/users":              "新增用户",
	"PUT /api/users/{id}/status":   "启用/禁用用户",
	"PUT /api/users/{id}/password": "重置用户密码",
	"DELETE /api/users/{id}":       "删除用户",
}

// digitsPattern 把路径中的数字段归一为 {id}（如 /api/users/3/status → /api/users/{id}/status）。
var digitsPattern = regexp.MustCompile(`/\d+`)

// pathDesc 解析路径中文描述；未命中返回空串（存 NULL）。
func pathDesc(method, path string) string {
	if method == "" || path == "" {
		return ""
	}
	return pathDescMap[method+" "+digitsPattern.ReplaceAllString(path, "/{id}")]
}

// auditRecord 一条待落库的审计记录。
type auditRecord struct {
	ts         string
	epochMs    int64
	username   string
	srcIP      string
	method     string
	path       string
	pathDesc   string
	query      string
	reqBody    string
	status     int
	respBody   string
	durationMs int64
	ok         bool
}

// AuditRepo 系统操作审计日志仓库。
//
// 写入走独立单协程异步落库，不阻塞 Web 请求；查询走只读连接池，
// 与 LogRepo 互不影响（WAL 模式下读写并发）。
type AuditRepo struct {
	writeDB *sql.DB
	readDB  *sql.DB
	logger  *slog.Logger
	locator GeoLocator

	queue     chan auditRecord
	done      chan struct{}
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	dropped   atomic.Uint64
}

// newAuditRepo 建表 + 补齐存量列，并启动异步写入协程。
func newAuditRepo(writeDB, readDB *sql.DB, locator GeoLocator, logger *slog.Logger) (*AuditRepo, error) {
	if _, err := writeDB.Exec(sqlCreateAudit); err != nil {
		return nil, fmt.Errorf("初始化审计表失败: %w", err)
	}
	for _, ddl := range auditIndexes {
		if _, err := writeDB.Exec(ddl); err != nil {
			return nil, fmt.Errorf("初始化审计索引失败: %w", err)
		}
	}
	// 存量表迁移：旧表无 location / path_desc 列时补加
	ensureAuditColumn(writeDB, logger, "location", "ALTER TABLE sys_audit_log ADD COLUMN location TEXT")
	ensureAuditColumn(writeDB, logger, "path_desc", "ALTER TABLE sys_audit_log ADD COLUMN path_desc TEXT")

	a := &AuditRepo{
		writeDB: writeDB,
		readDB:  readDB,
		logger:  logger,
		locator: locator,
		queue:   make(chan auditRecord, 4096),
		done:    make(chan struct{}),
	}
	go a.run()
	return a, nil
}

// ensureAuditColumn 列不存在时补加，失败仅告警（不阻塞启动）。
func ensureAuditColumn(db *sql.DB, logger *slog.Logger, column, alterStmt string) {
	exists, err := auditHasColumn(db, column)
	if err != nil {
		warnf(logger, fmt.Sprintf("检查审计表列 %s 失败: %v", column, err))
		return
	}
	if exists {
		return
	}
	if _, err := db.Exec(alterStmt); err != nil {
		warnf(logger, fmt.Sprintf("审计表迁移跳过（%s）: %v", alterStmt, err))
	}
}

// auditHasColumn 通过 PRAGMA table_info 判断列是否存在。
func auditHasColumn(db *sql.DB, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(sys_audit_log)")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Record 异步记录一条审计日志（脱敏 + 截断由调用方完成）。
func (a *AuditRepo) Record(username, srcIP, method, path, query, reqBody string,
	status int, respBody string, durationMs int64, ok bool) {
	now := time.Now()
	rec := auditRecord{
		ts:         now.Format(tsLayout),
		epochMs:    now.UnixMilli(),
		username:   username,
		srcIP:      srcIP,
		method:     method,
		path:       path,
		pathDesc:   pathDesc(method, path),
		query:      query,
		reqBody:    reqBody,
		status:     status,
		respBody:   respBody,
		durationMs: durationMs,
		ok:         ok,
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return
	}
	select {
	case a.queue <- rec:
	default:
		// 队列满：丢弃并计数，绝不阻塞 Web 请求线程
		n := a.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			warnf(a.logger, fmt.Sprintf("审计日志队列已满，已丢弃 %d 条记录", n))
		}
	}
}

// run 单协程串行落库。
func (a *AuditRepo) run() {
	defer close(a.done)
	for rec := range a.queue {
		a.insert(rec)
	}
}

// insert 写入一条审计记录；归属地在写入协程内解析，不阻塞请求。
func (a *AuditRepo) insert(rec auditRecord) {
	location := ""
	if a.locator != nil {
		location = a.locator.Locate(rec.srcIP)
	}
	_, err := a.writeDB.Exec(`INSERT INTO sys_audit_log(ts, epoch_ms, username, src_ip, method, path, path_desc, query,
			req_body, status, resp_body, duration_ms, ok, location)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.ts, rec.epochMs, nullString(rec.username), rec.srcIP, rec.method, rec.path,
		nullString(rec.pathDesc), nullString(rec.query), nullString(rec.reqBody), rec.status,
		nullString(rec.respBody), rec.durationMs, boolToInt(rec.ok), nullString(location))
	if err != nil {
		warnf(a.logger, "审计日志写入失败: "+err.Error())
	}
}

// Close 停止接收新记录，等待队列排空（上限 2s）后返回。
func (a *AuditRepo) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		close(a.queue)
		a.mu.Unlock()

		select {
		case <-a.done:
		case <-time.After(2 * time.Second):
			warnf(a.logger, "审计日志队列未在 2s 内排空，剩余记录已丢弃")
		}
	})
}

// maskBody 请求体脱敏：password / oldPassword / newPassword 替换为 ***，并截断至 2000 字符。
func maskBody(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil || obj == nil {
		return truncate(body)
	}
	for _, key := range []string{"password", "oldPassword", "newPassword"} {
		if v, ok := obj[key]; ok && v != nil {
			obj[key] = "***"
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return truncate(body)
	}
	return truncate(string(out))
}

// maskResponse 响应体摘要：仅保留 ok / error / user 字段，rows 只记条数，截断至 2000 字符。
func maskResponse(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil || obj == nil {
		return truncate(body)
	}
	out := make(map[string]any, 4)
	for _, key := range []string{"ok", "error", "user"} {
		if v, ok := obj[key]; ok {
			out[key] = v
		}
	}
	if data, ok := obj["data"]; ok {
		d, isObject := data.(map[string]any)
		rows, hasRows := d["rows"].([]any)
		if isObject && hasRows {
			summary := make(map[string]any, len(d))
			for k, v := range d {
				if k != "rows" {
					summary[k] = v
				}
			}
			summary["rowsCount"] = len(rows)
			out["data"] = summary
		} else {
			out["data"] = data
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return truncate(body)
	}
	return truncate(string(encoded))
}

// truncate 超长文本截断，避免撑爆审计表。
func truncate(s string) string {
	runes := []rune(s)
	if len(runes) > 2000 {
		return string(runes[:2000]) + "…(truncated)"
	}
	return s
}

// auditListQuery 审计明细过滤条件。
type auditListQuery struct {
	username    string
	srcIP       string
	method      string
	pathKeyword string
	start       *int64
	end         *int64
	page        int
	size        int
}

// List 审计日志明细（分页，支持用户名 / 来源 IP / 方法 / 路径关键字 / 时间范围过滤）。
func (a *AuditRepo) List(q auditListQuery) (map[string]any, error) {
	w := &where{}
	w.like("username", q.username)
	w.like("src_ip", q.srcIP)
	if v := strings.TrimSpace(q.method); v != "" {
		w.raw("method = ?")
		w.args = append(w.args, strings.ToUpper(v))
	}
	if v := strings.TrimSpace(q.pathKeyword); v != "" {
		// 路径关键字同时匹配原始路径与中文描述，支持按中文（如「登录」）检索
		w.raw("(path LIKE ? OR path_desc LIKE ?)")
		w.args = append(w.args, "%"+v+"%", "%"+v+"%")
	}
	w.rangeMs("epoch_ms", q.start, q.end)

	var total int64
	if err := a.readDB.QueryRow("SELECT COUNT(*) FROM sys_audit_log"+w.clause(), w.args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("统计审计日志失败: %w", err)
	}

	args := make([]any, 0, len(w.args)+2)
	args = append(args, w.args...)
	args = append(args, q.size, int64(q.page-1)*int64(q.size))
	rows, err := a.readDB.Query("SELECT * FROM sys_audit_log"+w.clause()+
		" ORDER BY epoch_ms DESC, id DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, fmt.Errorf("查询审计日志失败: %w", err)
	}
	defer rows.Close()

	labels, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("读取审计列名失败: %w", err)
	}
	records := make([]map[string]any, 0, min(q.size, 200))
	for rows.Next() {
		values := make([]any, len(labels))
		targets := make([]any, len(labels))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("读取审计记录失败: %w", err)
		}
		record := make(map[string]any, len(labels))
		for i, label := range labels {
			if raw, ok := values[i].([]byte); ok {
				record[label] = string(raw)
			} else {
				record[label] = values[i]
			}
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取审计记录失败: %w", err)
	}

	return map[string]any{
		"total": total,
		"page":  q.page,
		"size":  q.size,
		"rows":  records,
	}, nil
}

// Trend 审计日志按日趋势（近 N 天）：总操作数 / 失败数。
func (a *AuditRepo) Trend(days int) ([]map[string]any, error) {
	rows, err := a.readDB.Query(`SELECT substr(ts,1,10) d, COUNT(*) c, SUM(ok = 0) f
		FROM sys_audit_log WHERE epoch_ms >= ? GROUP BY d ORDER BY d`, sinceDaysMs(days))
	if err != nil {
		return nil, fmt.Errorf("查询审计趋势失败: %w", err)
	}
	defer rows.Close()

	out := make([]map[string]any, 0, days)
	for rows.Next() {
		var (
			day      string
			total    int64
			failures sql.NullInt64
		)
		if err := rows.Scan(&day, &total, &failures); err != nil {
			return nil, fmt.Errorf("读取审计趋势失败: %w", err)
		}
		out = append(out, map[string]any{
			"day":      day,
			"total":    total,
			"failures": failures.Int64,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取审计趋势失败: %w", err)
	}
	return out, nil
}

// nullString 空串写 NULL，保持与 Java 版「null 字段写 NULL」一致的语义。
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func warnf(logger *slog.Logger, msg string) {
	if logger != nil {
		logger.Warn(msg)
	}
}

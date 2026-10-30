package web

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// statsTTL 统计接口结果缓存有效期。
// Dashboard 每次切入会并发拉取 7 个统计接口，全部走预聚合表（不会扫明细表）；
// 短 TTL 缓存可合并并发请求的重复查询。
const statsTTL = 60 * time.Second

// statCache 统计结果 TTL 缓存（键含当日日期，跨日 midnight 后自动失效）。
type statCache struct {
	mu    sync.Mutex
	items map[string]statEntry
}

type statEntry struct {
	until time.Time
	value any
}

func newStatCache() *statCache {
	return &statCache{items: make(map[string]statEntry)}
}

// cached 泛型缓存包装：TTL 内命中直接返回，过期后重新查询并刷新。
func cached[T any](c *statCache, key string, load func() (T, error)) (T, error) {
	c.mu.Lock()
	entry, ok := c.items[key]
	if ok && time.Now().Before(entry.until) {
		value, hit := entry.value.(T)
		c.mu.Unlock()
		if hit {
			return value, nil
		}
	}
	c.mu.Unlock()

	value, err := load()
	if err != nil {
		var zero T
		return zero, err
	}
	c.mu.Lock()
	c.items[key] = statEntry{until: time.Now().Add(statsTTL), value: value}
	c.mu.Unlock()
	return value, nil
}

// LogRepo 攻击日志只读查询仓库（Web 控制台统计与明细的数据源）。
type LogRepo struct {
	db    *sql.DB
	cache *statCache
	// agg 预聚合统计表可用（store 建表成功）。
	// 旧库或独立测试库缺失时回退到明细表全量统计，保证控制台不白屏；
	// 回退路径会扫明细表全表（user_version 6 已退役口令/归属地索引，分组统计会慢到百毫秒级），
	// 仅在聚合表缺失的异常库上发生。
	agg bool
	// locCountry stats_locations 带 country 列（user_version 7）；
	// 缺失时只让地区排行回退到从 location 推断，其余统计仍走聚合表。
	locCountry bool
}

func newLogRepo(db *sql.DB) *LogRepo {
	return &LogRepo{
		db:         db,
		cache:      newStatCache(),
		agg:        hasStatsTables(db),
		locCountry: hasColumn(db, "stats_locations", "country"),
	}
}

// aggTables 预聚合统计表（user_version 4 的总量表 + 5 的排行表）。
var aggTables = []string{
	"stats_daily", "stats_ip_daily",
	"stats_usernames", "stats_passwords", "stats_locations",
}

// hasStatsTables 探测预聚合统计表是否全部存在；探测失败按不可用处理（回退明细统计）。
func hasStatsTables(db *sql.DB) bool {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(aggTables)), ",")
	args := make([]any, len(aggTables))
	for i, name := range aggTables {
		args[i] = name
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN (`+placeholders+`)`, args...).Scan(&n)
	return err == nil && n == len(aggTables)
}

// hasColumn 探测表是否带指定列（旧库未迁移时缺列，如 stats_locations.country）。
func hasColumn(db *sql.DB, table, column string) bool {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
	return err == nil && n == 1
}

// sqlOverviewAgg 预聚合总览：只扫按天表（数十行）与按 IP 聚合表，不碰百万级明细。
const sqlOverviewAgg = `
SELECT (SELECT COALESCE(SUM(sessions),0)      FROM stats_daily)        AS total_sessions,
       (SELECT COALESCE(SUM(auth_attempts),0) FROM stats_daily)        AS total_auth,
       (SELECT COALESCE(SUM(commands),0)      FROM stats_daily)        AS total_commands,
       (SELECT COALESCE(SUM(downloads),0)     FROM stats_daily)        AS total_downloads,
       (SELECT COUNT(DISTINCT src_ip) FROM stats_ip_daily
         WHERE auth_attempts > 0)                                     AS unique_ips,
       COALESCE((SELECT sessions      FROM stats_daily WHERE day = ?), 0) AS today_sessions,
       COALESCE((SELECT auth_attempts FROM stats_daily WHERE day = ?), 0) AS today_auth,
       COALESCE((SELECT commands      FROM stats_daily WHERE day = ?), 0) AS today_commands,
       COALESCE((SELECT downloads     FROM stats_daily WHERE day = ?), 0) AS today_downloads,
       (SELECT COUNT(DISTINCT src_ip) FROM ip_locks
         WHERE locked_until > datetime('now','localtime'))            AS active_locks`

// sqlOverview 总览统计：各事件总量、独立攻击源 IP 数、今日新增、当前生效锁定 IP 数。
const sqlOverview = `
SELECT (SELECT COUNT(*) FROM sessions)                                AS total_sessions,
       (SELECT COUNT(*) FROM auth_attempts)                           AS total_auth,
       (SELECT COUNT(*) FROM commands)                                AS total_commands,
       (SELECT COUNT(*) FROM downloads)                               AS total_downloads,
       (SELECT COUNT(DISTINCT src_ip) FROM auth_attempts)             AS unique_ips,
       (SELECT COUNT(*) FROM sessions      WHERE opened_epoch_ms >= ?) AS today_sessions,
       (SELECT COUNT(*) FROM auth_attempts WHERE ts_epoch_ms >= ?)     AS today_auth,
       (SELECT COUNT(*) FROM commands      WHERE ts_epoch_ms >= ?)     AS today_commands,
       (SELECT COUNT(*) FROM downloads     WHERE ts_epoch_ms >= ?)     AS today_downloads,
       (SELECT COUNT(DISTINCT src_ip) FROM ip_locks
         WHERE locked_until > datetime('now','localtime'))            AS active_locks`

// Overview 总览统计。
func (l *LogRepo) Overview() (map[string]any, error) {
	key := "overview:" + todayKey()
	return cached(l.cache, key, func() (map[string]any, error) {
		var (
			totalSessions, totalAuth, totalCommands, totalDownloads int64
			uniqueIPs                                               int64
			todaySessions, todayAuth, todayCommands                 int64
			todayDownloads, activeLocks                             int64
		)
		var err error
		if l.agg {
			day := todayKey()
			err = l.db.QueryRow(sqlOverviewAgg, day, day, day, day).Scan(
				&totalSessions, &totalAuth, &totalCommands, &totalDownloads, &uniqueIPs,
				&todaySessions, &todayAuth, &todayCommands, &todayDownloads, &activeLocks)
		} else {
			today := todayStartMs()
			err = l.db.QueryRow(sqlOverview, today, today, today, today).Scan(
				&totalSessions, &totalAuth, &totalCommands, &totalDownloads, &uniqueIPs,
				&todaySessions, &todayAuth, &todayCommands, &todayDownloads, &activeLocks)
		}
		if err != nil {
			return nil, fmt.Errorf("查询总览统计失败: %w", err)
		}
		return map[string]any{
			"totalSessions":  totalSessions,
			"totalAuth":      totalAuth,
			"totalCommands":  totalCommands,
			"totalDownloads": totalDownloads,
			"uniqueIps":      uniqueIPs,
			"todaySessions":  todaySessions,
			"todayAuth":      todayAuth,
			"todayCommands":  todayCommands,
			"todayDownloads": todayDownloads,
			"activeLocks":    activeLocks,
		}, nil
	})
}

// Trend 最近 N 天按日趋势：会话 / 登录尝试 / 命令执行。
func (l *LogRepo) Trend(days int) ([]map[string]any, error) {
	key := "trend:" + strconv.Itoa(days) + ":" + todayKey()
	return cached(l.cache, key, func() ([]map[string]any, error) {
		return l.queryTrend(days)
	})
}

func (l *LogRepo) queryTrend(days int) ([]map[string]any, error) {
	if l.agg {
		return l.queryTrendAgg(days)
	}
	since := sinceDaysMs(days)
	byDay := make(map[string]*[3]int64, days)
	queries := []struct {
		sql string
		idx int
	}{
		{`SELECT substr(opened_at,1,10) d, COUNT(*) c FROM sessions WHERE opened_epoch_ms >= ? GROUP BY d`, 0},
		{`SELECT substr(ts,1,10) d, COUNT(*) c FROM auth_attempts WHERE ts_epoch_ms >= ? GROUP BY d`, 1},
		{`SELECT substr(ts,1,10) d, COUNT(*) c FROM commands WHERE ts_epoch_ms >= ? GROUP BY d`, 2},
	}
	for _, q := range queries {
		rows, err := l.db.Query(q.sql, since)
		if err != nil {
			return nil, fmt.Errorf("查询趋势统计失败: %w", err)
		}
		for rows.Next() {
			var (
				day   string
				count int64
			)
			if err := rows.Scan(&day, &count); err != nil {
				rows.Close()
				return nil, fmt.Errorf("读取趋势统计失败: %w", err)
			}
			slot, ok := byDay[day]
			if !ok {
				slot = &[3]int64{}
				byDay[day] = slot
			}
			slot[q.idx] = count
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("读取趋势统计失败: %w", err)
		}
		rows.Close()
	}

	daysList := make([]string, 0, len(byDay))
	for day := range byDay {
		daysList = append(daysList, day)
	}
	sort.Strings(daysList)

	rows := make([]map[string]any, 0, len(daysList))
	for _, day := range daysList {
		slot := byDay[day]
		rows = append(rows, map[string]any{
			"day":      day,
			"sessions": slot[0],
			"auth":     slot[1],
			"commands": slot[2],
		})
	}
	return rows, nil
}

// queryTrendAgg 从按天聚合表读趋势：一行一天，代价与历史数据量无关。
func (l *LogRepo) queryTrendAgg(days int) ([]map[string]any, error) {
	since := time.UnixMilli(sinceDaysMs(days)).Format("2006-01-02")
	rows, err := l.db.Query(`SELECT day, sessions, auth_attempts, commands FROM stats_daily
		WHERE day >= ? ORDER BY day`, since)
	if err != nil {
		return nil, fmt.Errorf("查询趋势统计失败: %w", err)
	}
	defer rows.Close()

	out := make([]map[string]any, 0, days)
	for rows.Next() {
		var (
			day                  string
			sessions, auth, cmds int64
		)
		if err := rows.Scan(&day, &sessions, &auth, &cmds); err != nil {
			return nil, fmt.Errorf("读取趋势统计失败: %w", err)
		}
		out = append(out, map[string]any{
			"day":      day,
			"sessions": sessions,
			"auth":     auth,
			"commands": cmds,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取趋势统计失败: %w", err)
	}
	return out, nil
}

// ProtocolDist 会话数按协议分布。
func (l *LogRepo) ProtocolDist() ([]map[string]any, error) {
	return cached(l.cache, "protocol", func() ([]map[string]any, error) {
		return l.list(`SELECT protocol AS name, COUNT(*) AS value FROM sessions GROUP BY protocol ORDER BY value DESC`)
	})
}

// TopIPs 攻击源 IP 排行（按登录尝试次数）。
func (l *LogRepo) TopIPs(limit int) ([]map[string]any, error) {
	return cached(l.cache, "topIps:"+strconv.Itoa(limit), func() ([]map[string]any, error) {
		if l.agg {
			return l.listLimit(`SELECT src_ip AS name, SUM(auth_attempts) AS value FROM stats_ip_daily
				WHERE auth_attempts > 0 GROUP BY src_ip ORDER BY value DESC LIMIT ?`, limit)
		}
		return l.listLimit(`SELECT src_ip AS name, COUNT(*) AS value FROM auth_attempts
			GROUP BY src_ip ORDER BY value DESC LIMIT ?`, limit)
	})
}

// TopUsernames 被爆破用户名排行。
func (l *LogRepo) TopUsernames(limit int) ([]map[string]any, error) {
	return cached(l.cache, "topUsernames:"+strconv.Itoa(limit), func() ([]map[string]any, error) {
		if l.agg {
			return l.listLimit(`SELECT username AS name, auth_attempts AS value FROM stats_usernames
				ORDER BY value DESC, name LIMIT ?`, limit)
		}
		return l.listLimit(`SELECT username AS name, COUNT(*) AS value FROM auth_attempts
			GROUP BY username ORDER BY value DESC LIMIT ?`, limit)
	})
}

// TopPasswords 被尝试口令排行。
func (l *LogRepo) TopPasswords(limit int) ([]map[string]any, error) {
	return cached(l.cache, "topPasswords:"+strconv.Itoa(limit), func() ([]map[string]any, error) {
		if l.agg {
			return l.listLimit(`SELECT password AS name, auth_attempts AS value FROM stats_passwords
				ORDER BY value DESC, name LIMIT ?`, limit)
		}
		return l.listLimit(`SELECT password AS name, COUNT(*) AS value FROM auth_attempts
			GROUP BY password ORDER BY value DESC LIMIT ?`, limit)
	})
}

// domesticCountry 国内归属地的国家段；国内再细分到省份，其余直接按国家聚合。
const domesticCountry = "中国"

// TopLocations 攻击源地区排行（国内按省份、国外按国家聚合，空值归入「未知」）。
//
// user_version 7 起优先用 stats_locations.country：location 是「国家 省份 城市」
// 拼接串，多词国家名（South Korea、United States）按空格切分只能得到首词。
func (l *LogRepo) TopLocations(limit int) ([]map[string]any, error) {
	return cached(l.cache, "topLocations:"+strconv.Itoa(limit), func() ([]map[string]any, error) {
		// 回退路径（旧库 / 独立测试库）没有 country 列，用空串占位后按 location 推断；
		// 聚合表存在但缺列时同样只能按 location 推断（仅 1 次启动前的旧库会命中）
		query := `SELECT location, '' AS country, COUNT(*) FROM auth_attempts GROUP BY location`
		if l.agg && l.locCountry {
			query = `SELECT location, country, auth_attempts FROM stats_locations`
		} else if l.agg {
			query = `SELECT location, '' AS country, auth_attempts FROM stats_locations`
		}
		rows, err := l.db.Query(query)
		if err != nil {
			return nil, fmt.Errorf("查询地区统计失败: %w", err)
		}
		defer rows.Close()

		byRegion := make(map[string]int64, 16)
		for rows.Next() {
			var (
				location sql.NullString
				country  sql.NullString
				count    int64
			)
			if err := rows.Scan(&location, &country, &count); err != nil {
				return nil, fmt.Errorf("读取地区统计失败: %w", err)
			}
			byRegion[regionName(location.String, country.String)] += count
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("读取地区统计失败: %w", err)
		}

		names := make([]string, 0, len(byRegion))
		for name := range byRegion {
			names = append(names, name)
		}
		// 次数降序；同次数按名称升序，保证输出稳定
		sort.Slice(names, func(i, j int) bool {
			if byRegion[names[i]] != byRegion[names[j]] {
				return byRegion[names[i]] > byRegion[names[j]]
			}
			return names[i] < names[j]
		})
		if len(names) > limit {
			names = names[:limit]
		}
		out := make([]map[string]any, 0, len(names))
		for _, name := range names {
			out = append(out, map[string]any{"name": name, "value": byRegion[name]})
		}
		return out, nil
	})
}

// regionName 归属地聚合名：国内细分到省份，国外直接取国家；空值归入「未知」。
//
// country 为空串（旧库、回填失败、库无记录）时回退 regionOf，
// 那种情况下多词国家名仍然会被截成首词（user_version 6 及以前的既有行为）。
func regionName(location, country string) string {
	country = strings.TrimSpace(country)
	if country == "" {
		return regionOf(location)
	}
	if country != domesticCountry {
		return country
	}
	if parts := strings.Fields(location); len(parts) >= 2 {
		return parts[1]
	}
	return country
}

// regionOf location（国家 省份 城市）取地区名：国内取省份，国外取国家；空值返回「未知」。
// 仅用于没有国家段的回退路径（见 regionName）。
func regionOf(location string) string {
	parts := strings.Fields(location)
	if len(parts) == 0 {
		return "未知"
	}
	if parts[0] == domesticCountry && len(parts) >= 2 {
		return parts[1]
	}
	return parts[0]
}

// Sessions 会话明细（按来源 IP / 协议 / 时间范围过滤）。
func (l *LogRepo) Sessions(srcIP, protocol string, start, end *int64, page, size int) (map[string]any, error) {
	w := &where{}
	w.like("src_ip", srcIP)
	w.eq("protocol", protocol)
	w.rangeMs("opened_epoch_ms", start, end)
	return l.pageQuery("sessions", "*", w, page, size, "ORDER BY opened_epoch_ms DESC, id DESC")
}

// AuthAttempts 登录尝试明细（按来源 IP / 用户名 / 协议 / 是否成功 / 时间范围过滤）。
func (l *LogRepo) AuthAttempts(srcIP, username, protocol string, success *bool, start, end *int64,
	page, size int) (map[string]any, error) {
	w := &where{}
	w.like("src_ip", srcIP)
	w.eq("username", username)
	w.eq("protocol", protocol)
	if success != nil {
		if *success {
			w.raw("success = 1")
		} else {
			w.raw("success = 0")
		}
	}
	w.rangeMs("ts_epoch_ms", start, end)
	return l.pageQuery("auth_attempts", "*", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC")
}

// Commands 命令执行明细（按会话编号 / 来源 IP / 用户名 / 命令关键字 / 时间范围过滤）。
func (l *LogRepo) Commands(sessionID, srcIP, username, keyword string, start, end *int64,
	page, size int) (map[string]any, error) {
	w := &where{}
	w.eq("session_id", sessionID)
	w.like("src_ip", srcIP)
	w.eq("username", username)
	w.like("command", keyword)
	w.rangeMs("ts_epoch_ms", start, end)
	return l.pageQuery("commands", "*", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC")
}

// Downloads 恶意下载明细（按来源 IP / URL 关键字 / 时间范围过滤）。
func (l *LogRepo) Downloads(srcIP, keyword string, start, end *int64, page, size int) (map[string]any, error) {
	w := &where{}
	w.like("src_ip", srcIP)
	w.like("url", keyword)
	w.rangeMs("ts_epoch_ms", start, end)
	return l.pageQuery("downloads", "*", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC")
}

// IPLocks IP 锁定记录（按来源 IP 过滤；lockedActive 表示当前是否仍在锁定中）。
func (l *LogRepo) IPLocks(srcIP string, page, size int) (map[string]any, error) {
	w := &where{}
	w.like("src_ip", srcIP)
	result, err := l.pageQuery("ip_locks",
		"*, locked_until > datetime('now','localtime') AS lockedActive",
		w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC")
	if err != nil {
		return nil, err
	}
	// SQLite 表达式结果为 0/1，转为布尔保持 API 响应与原实现一致
	if rows, ok := result["rows"].([]map[string]any); ok {
		for _, row := range rows {
			row["lockedActive"] = toInt64(row["lockedActive"]) == 1
		}
	}
	return result, nil
}

// where 参数化 WHERE 条件构造器，所有过滤值均走占位符，杜绝 SQL 注入。
type where struct {
	cond []string
	args []any
}

func (w *where) raw(condition string) {
	w.cond = append(w.cond, condition)
}

func (w *where) eq(column, value string) {
	if v := strings.TrimSpace(value); v != "" {
		w.raw(column + " = ?")
		w.args = append(w.args, v)
	}
}

func (w *where) like(column, value string) {
	if v := strings.TrimSpace(value); v != "" {
		// 通配符转义：用户输入的 % 与 _ 按字面量匹配，避免被当作模式通配
		w.raw(column + ` LIKE ? ESCAPE '\'`)
		w.args = append(w.args, "%"+escapeLike(v)+"%")
	}
}

// escapeLike 转义 LIKE 模式中的通配符（配合 ESCAPE '\'）。
func escapeLike(s string) string {
	if !strings.ContainsAny(s, `%_\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (w *where) rangeMs(column string, start, end *int64) {
	if start != nil {
		w.raw(column + " >= ?")
		w.args = append(w.args, *start)
	}
	if end != nil {
		w.raw(column + " <= ?")
		w.args = append(w.args, *end)
	}
}

func (w *where) clause() string {
	if len(w.cond) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.cond, " AND ")
}

// maxPage 分页页码上限：限制 OFFSET 规模，避免超大页码退化为全表扫描/整数溢出。
const maxPage = 1_000_000

// pageQuery 通用分页查询：返回 {total,page,size,rows}。
func (l *LogRepo) pageQuery(table, columns string, w *where, page, size int,
	order string) (map[string]any, error) {
	var total int64
	if err := l.db.QueryRow("SELECT COUNT(*) FROM "+table+w.clause(), w.args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("统计 %s 失败: %w", table, err)
	}

	args := make([]any, 0, len(w.args)+2)
	// 偏移量用 int64 计算并限幅：page/size 来自查询参数，溢出后可能变成负数
	offset := int64(page-1) * int64(size)
	if offset < 0 || int64(page) > maxPage {
		offset = 0
		page = 1
	}
	args = append(args, w.args...)
	args = append(args, size, offset)
	sqlText := "SELECT " + columns + " FROM " + table + w.clause() + " " + order + " LIMIT ? OFFSET ?"

	rows, err := l.db.Query(sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("查询 %s 失败: %w", table, err)
	}
	defer rows.Close()

	labels, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("读取 %s 列名失败: %w", table, err)
	}
	records := make([]map[string]any, 0, min(size, 200))
	for rows.Next() {
		values := make([]any, len(labels))
		targets := make([]any, len(labels))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("读取 %s 记录失败: %w", table, err)
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
		return nil, fmt.Errorf("读取 %s 记录失败: %w", table, err)
	}

	return map[string]any{
		"total": total,
		"page":  page,
		"size":  size,
		"rows":  records,
	}, nil
}

// list 两列统计查询（name/value）。
func (l *LogRepo) list(sqlText string) ([]map[string]any, error) {
	rows, err := l.db.Query(sqlText)
	if err != nil {
		return nil, fmt.Errorf("查询统计失败: %w", err)
	}
	defer rows.Close()

	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var (
			name  sql.NullString
			value int64
		)
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("读取统计失败: %w", err)
		}
		out = append(out, map[string]any{"name": name.String, "value": value})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取统计失败: %w", err)
	}
	return out, nil
}

// listLimit 两列统计查询（带 limit 参数）。
func (l *LogRepo) listLimit(sqlText string, limit int) ([]map[string]any, error) {
	rows, err := l.db.Query(sqlText, limit)
	if err != nil {
		return nil, fmt.Errorf("查询排行统计失败: %w", err)
	}
	defer rows.Close()

	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var (
			name  sql.NullString
			value int64
		)
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("读取排行统计失败: %w", err)
		}
		out = append(out, map[string]any{"name": name.String, "value": value})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取排行统计失败: %w", err)
	}
	return out, nil
}

// todayKey 缓存键使用的当日日期（跨日自动失效，避免把「今日新增」缓存成昨天）。
func todayKey() string {
	return time.Now().Format("2006-01-02")
}

// todayStartMs 当日零点的毫秒时间戳（本地时区）。
func todayStartMs() int64 {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).UnixMilli()
}

// sinceDaysMs 近 days 天窗口起点（含当天）的毫秒时间戳。
func sinceDaysMs(days int) int64 {
	start := time.UnixMilli(todayStartMs())
	return start.AddDate(0, 0, -(days - 1)).UnixMilli()
}

// toInt64 把 SQLite 数值统一为 int64（bool 也接受）。
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	case bool:
		if n {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// Package attacklog 攻击日志记录器：JSON Lines 格式（每条事件一行，便于 jq/ELK 分析），
// 同时输出到控制台便于实时观察，并把同一份数据双写到 SQLite（store）供 Web 可视化查询。
//
// 性能设计：事件提交到有界异步队列，调用方（会话协程）不阻塞在磁盘 I/O 上；
// 单写入协程每 1 秒（或攒满一批）落一次盘：JSONL 一次 Flush，SQLite 一个事务提交，
// 既保证行序不乱，也把 N 次 fsync 降为 1 次。
//
// 事件类型：session_open / auth_attempt / command / download / session_close / ip_locked
package attacklog

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"ssh-honeypot-go/internal/geo"
	"ssh-honeypot-go/internal/store"
)

const (
	// TSLayout 时间格式：与 Java 版 DateTimeFormatter 一致，保留毫秒便于排序。
	TSLayout = "2006-01-02 15:04:05.000"
	// queueSize 异步写入队列容量；队列满时丢弃并计数（plan 要求，防止内存无界增长）。
	queueSize = 8192
	// flushInterval 批量落盘间隔：事件先在内存攒批，每 1 秒写一次 JSONL 并提交一个 SQLite 事务。
	flushInterval = time.Second
	// maxBatch 单批上限：突发流量占满即刷，避免内存膨胀与落盘延迟。
	maxBatch = 512
	// closeTimeout 关闭时等待队列排空的上限。
	closeTimeout = 5 * time.Second
	// dropReportInterval 队列丢弃计数的告警周期。
	dropReportInterval = 30 * time.Second
)

// field JSONL 中的单个有序字段。
type field struct {
	key   string
	value string
}

// dbSink SQLite 写入动作：与对应 JSONL 记录共用同一时间戳/毫秒时钟，在写协程批量执行。
// 参数为 store.Writer：正常攒批时是 *store.Tx（一批一个事务），也便于单测注入。
type dbSink func(w store.Writer, ts string, epochMs int64) error

// event 待写入的一条事件。
type event struct {
	tsText  string
	epochMs int64
	line    string
	dbWrite dbSink
}

// Logger 攻击日志记录器。
type Logger struct {
	file       *os.File
	writer     *bufio.Writer
	db         *store.Store
	locator    *geo.Locator
	logger     *slog.Logger
	queue      chan event
	done       chan struct{}
	sessionSeq atomic.Uint64
	dropped    atomic.Uint64

	// fileMu 串行化「写协程刷盘」与「关闭时 flush/close」，避免关闭阶段的竞态
	fileMu sync.Mutex
	// mu 保护 closed + queue 的发送/关闭配对
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
}

// New 打开 JSONL 日志文件并初始化 SQLite（数据库失败时降级为仅写 JSONL）。
func New(logFile, dbFile string, locator *geo.Locator, logger *slog.Logger) (*Logger, error) {
	abs, err := filepath.Abs(logFile)
	if err != nil {
		return nil, fmt.Errorf("解析日志路径 %s 失败: %w", logFile, err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("打开攻击日志文件 %s 失败: %w", abs, err)
	}

	l := &Logger{
		file:    f,
		writer:  bufio.NewWriter(f),
		locator: locator,
		logger:  logger,
		queue:   make(chan event, queueSize),
		done:    make(chan struct{}),
	}

	if db, err := store.Open(dbFile, logger, store.WithCountryResolver(locator)); err != nil {
		warnf(logger, "SQLite 数据库初始化失败，仅写入 JSONL 日志: "+err.Error())
	} else {
		l.db = db
	}

	infof(logger, "攻击日志写入: "+abs)
	go l.run()
	return l, nil
}

// Healthy 数据库是否初始化成功（Web 控制台依赖数据库，不可用时不启动）。
func (l *Logger) Healthy() bool {
	return l != nil && l.db.Healthy()
}

// NewSessionID 生成会话编号：`s<序号>-<毫秒时间戳十六进制>`（与 Java 版格式一致）。
func (l *Logger) NewSessionID() string {
	return "s" + strconv.FormatUint(l.sessionSeq.Add(1), 10) + "-" +
		strconv.FormatInt(time.Now().UnixMilli(), 16)
}

// SessionOpen 记录会话开始。
func (l *Logger) SessionOpen(sessionID, protocol, ip string, port int) {
	location := l.locate(ip)
	fields := []field{
		{"event", "session_open"},
		{"session", sessionID},
		{"protocol", protocol},
		{"src_ip", ip},
		{"src_port", strconv.Itoa(port)},
	}
	fields = appendLocation(fields, location)
	l.write(fields, func(w store.Writer, ts string, epochMs int64) error {
		return w.RecordSessionOpen(ts, epochMs, sessionID, protocol, ip, port, location)
	})
}

// AuthAttempt 记录一次登录尝试，并打印控制台摘要。
func (l *Logger) AuthAttempt(sessionID, protocol, ip, username, password string, success bool) {
	region := l.locateRegion(ip)
	fields := []field{
		{"event", "auth_attempt"},
		{"session", sessionID},
		{"protocol", protocol},
		{"src_ip", ip},
		{"username", username},
		{"password", password},
		{"success", strconv.FormatBool(success)},
	}
	fields = appendLocation(fields, region.Location)
	l.write(fields, func(w store.Writer, ts string, epochMs int64) error {
		return w.RecordAuthAttempt(ts, epochMs, sessionID, protocol, ip, username, password, success,
			region.Location, region.Country)
	})

	result := "拒绝"
	if success {
		result = "放行(蜜罐)"
	}
	infof(l.logger, fmt.Sprintf("[%s] 登录尝试 %s 用户=%s 密码=%s -> %s", protocol, ip, username, password, result))
}

// IPLocked 记录源 IP 锁定事件。
func (l *Logger) IPLocked(ip string, untilMillis int64) {
	until := time.UnixMilli(untilMillis).Format(TSLayout)
	location := l.locate(ip)
	fields := []field{
		{"event", "ip_locked"},
		{"src_ip", ip},
		{"until", until},
	}
	fields = appendLocation(fields, location)
	l.write(fields, func(w store.Writer, ts string, epochMs int64) error {
		return w.RecordIPLocked(ts, epochMs, ip, until, location)
	})

	infof(l.logger, fmt.Sprintf("源 IP %s 连续登录失败已达上限，锁定至 %s", ip, until))
}

// Command 记录一条命令。
func (l *Logger) Command(sessionID, ip, username, cmdline string) {
	location := l.locate(ip)
	fields := []field{
		{"event", "command"},
		{"session", sessionID},
		{"src_ip", ip},
		{"username", username},
		{"command", cmdline},
	}
	fields = appendLocation(fields, location)
	l.write(fields, func(w store.Writer, ts string, epochMs int64) error {
		return w.RecordCommand(ts, epochMs, sessionID, ip, username, cmdline, location)
	})

	infof(l.logger, fmt.Sprintf("[%s] %s$ %s", ip, username, cmdline))
}

// Download 记录一次恶意下载。
func (l *Logger) Download(sessionID, ip, username, url string) {
	location := l.locate(ip)
	fields := []field{
		{"event", "download"},
		{"session", sessionID},
		{"src_ip", ip},
		{"username", username},
		{"url", url},
	}
	fields = appendLocation(fields, location)
	l.write(fields, func(w store.Writer, ts string, epochMs int64) error {
		return w.RecordDownload(ts, epochMs, sessionID, ip, username, url, location)
	})

	infof(l.logger, fmt.Sprintf("[%s] 恶意下载: %s", ip, url))
}

// SessionClose 记录会话结束（调用方保证幂等）。
func (l *Logger) SessionClose(sessionID, ip string, durationMs int64) {
	location := l.locate(ip)
	fields := []field{
		{"event", "session_close"},
		{"session", sessionID},
		{"src_ip", ip},
		{"duration_ms", strconv.FormatInt(durationMs, 10)},
	}
	fields = appendLocation(fields, location)
	l.write(fields, func(w store.Writer, ts string, epochMs int64) error {
		return w.RecordSessionClose(ts, sessionID, durationMs)
	})
}

// locate 解析来源 IP 归属地；定位器不可用时返回空串（JSONL 不输出该字段，SQLite 存 NULL）。
func (l *Logger) locate(ip string) string {
	return l.locateRegion(ip).Location
}

// locateRegion 解析归属地与所属国家段（登录尝试需要国家段做按国家聚合）。
func (l *Logger) locateRegion(ip string) geo.Region {
	if l == nil || l.locator == nil {
		return geo.Region{}
	}
	return l.locator.LocateRegion(ip)
}

// appendLocation 归属地非空时才追加字段，与 Java 版「null 不输出」一致。
func appendLocation(fields []field, location string) []field {
	if location == "" {
		return fields
	}
	return append(fields, field{"location", location})
}

// write 序列化并投递到异步队列；队列满时丢弃并计数。
func (l *Logger) write(fields []field, sink dbSink) {
	now := time.Now()
	tsText := now.Format(TSLayout)
	ev := event{
		tsText:  tsText,
		epochMs: now.UnixMilli(),
		line:    buildLine(tsText, fields),
		dbWrite: sink,
	}

	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return
	}
	select {
	case l.queue <- ev:
	default:
		// 队列满：丢弃并累计，由写协程周期告警；绝不阻塞会话线程
		l.dropped.Add(1)
	}
}

// run 单写入协程：攒批后串行落盘（每 flushInterval 或攒满 maxBatch 触发一次）。
func (l *Logger) run() {
	defer close(l.done)

	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()
	dropTicker := time.NewTicker(dropReportInterval)
	defer dropTicker.Stop()

	batch := make([]event, 0, maxBatch)
	for {
		select {
		case ev, ok := <-l.queue:
			if !ok {
				l.flush(batch) // channel 已关闭：刷完剩余事件再退出
				return
			}
			batch = append(batch, ev)
			if len(batch) >= maxBatch {
				l.flush(batch)
				batch = batch[:0]
			}
		case <-flushTicker.C:
			if len(batch) > 0 {
				l.flush(batch)
				batch = batch[:0]
			}
		case <-dropTicker.C:
			if n := l.dropped.Swap(0); n > 0 {
				warnf(l.logger, fmt.Sprintf("攻击日志队列已满，过去 %s 丢弃 %d 条事件",
					dropReportInterval, n))
			}
		}
	}
}

// flush 一批事件：JSONL 整体 Flush 一次，SQLite 一个事务提交。
func (l *Logger) flush(batch []event) {
	if len(batch) == 0 {
		return
	}
	l.flushLines(batch)
	if l.db == nil {
		return
	}

	tx, err := l.db.Begin()
	if err != nil {
		warnf(l.logger, "开启写入事务失败（本批仅写 JSONL）: "+err.Error())
		return
	}
	failed := 0
	for _, ev := range batch {
		if ev.dbWrite == nil {
			continue
		}
		if err := ev.dbWrite(tx, ev.tsText, ev.epochMs); err != nil {
			failed++
			if failed <= 3 { // 异常流量下避免日志风暴
				warnf(l.logger, err.Error())
			}
		}
	}
	if err := tx.Commit(); err != nil {
		warnf(l.logger, fmt.Sprintf("提交写入事务失败（%d 条）: %v", len(batch), err))
		_ = tx.Rollback()
		return
	}
	if failed > 0 {
		warnf(l.logger, fmt.Sprintf("本批 %d 条事件中有 %d 条未写入 SQLite", len(batch), failed))
	}
}

// flushLines 把整批 JSONL 行写入缓冲并只 Flush 一次。
func (l *Logger) flushLines(batch []event) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	var err error
	for _, ev := range batch {
		if _, err = l.writer.WriteString(ev.line + "\n"); err != nil {
			break
		}
	}
	if err == nil {
		err = l.writer.Flush()
	}
	if err != nil {
		warnf(l.logger, "日志写入失败: "+err.Error())
	}
}

// Close 停止接收新事件，等待队列排空后刷盘并关闭数据库。
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.queue)
		l.mu.Unlock()

		select {
		case <-l.done:
		case <-time.After(closeTimeout):
			warnf(l.logger, "攻击日志写入队列未在 5s 内排空，剩余事件已丢弃")
		}

		l.fileMu.Lock()
		if err := l.writer.Flush(); err != nil {
			warnf(l.logger, "日志刷盘失败: "+err.Error())
		}
		if err := l.file.Close(); err != nil {
			warnf(l.logger, "日志文件关闭失败: "+err.Error())
		}
		l.fileMu.Unlock()

		if l.db != nil {
			if err := l.db.Close(); err != nil {
				warnf(l.logger, "SQLite 关闭失败: "+err.Error())
			}
		}
	})
	return nil
}

// buildLine 构造一行 JSON：{"ts":"...","event":"...",...}。
// 手工序列化而非 encoding/json：字段顺序稳定、无反射开销，且与 Java 版输出逐字节一致。
func buildLine(ts string, fields []field) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString(`{"ts":"`)
	b.WriteString(escape(ts))
	b.WriteByte('"')
	for _, f := range fields {
		b.WriteString(`,"`)
		b.WriteString(f.key)
		b.WriteString(`":"`)
		b.WriteString(escape(f.value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// hexDigits JSON \u00XX 转义用的十六进制字符表。
const hexDigits = "0123456789abcdef"

// needsEscape 判断是否需要转义：反向代理/攻击者可在用户名、口令、命令中
// 注入任意字节，含控制字符或非法 UTF-8 时 JSONL 行不再合法，必须逐字节处理。
func needsEscape(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c == '\\' || c == '"' {
			return true
		}
	}
	return false
}

// escape 转义 JSON 特殊字符、全部控制字符（<0x20、0x7F）与非法 UTF-8 字节；
// 不含特殊字符时直接复用原串，避免无谓拷贝。
func escape(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				b.WriteString(`\ufffd`) // 非法 UTF-8 字节：替换为 Unicode 替换符，保证行合法
				i++
				continue
			}
			b.WriteString(s[i : i+size])
			i += size
			continue
		}
		i++
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 || c == 0x7f {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0x0f])
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
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

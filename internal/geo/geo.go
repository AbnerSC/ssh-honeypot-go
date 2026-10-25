// Package geo 基于 ip2region xdb 离线库解析 IP 归属地，
// 供攻击日志（sessions/auth_attempts/...）与 Web 审计日志记录「国家 省份 城市」。
//
// 加载优先级（与 Java 版 IpLocator 一致）：
//  1. 配置中的外部文件（log.ipdb_v4 / log.ipdb_v6）
//  2. 二进制内置库（go:embed，首次使用时释放到临时文件）
//  3. 均不可用则降级：Locate 恒返回空串，不影响蜜罐运行
//
// 内存策略：采用向量索引（约 512KB/库）常驻内存，数据段按需从文件读取，
// 避免 37MB 级 v6 库整体加载导致低配额容器内存超限；查询另有进程内结果缓存。
package geo

import (
	"embed"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// 内置库：随二进制打包，镜像不挂载 db 卷时依然可解析归属地。
//
//go:embed assets/ip2region_v4.xdb assets/ip2region_v6.xdb
var builtinFS embed.FS

const (
	// PrivateLabel 内网 / 环回 / 链路本地地址的归属地占位值。
	PrivateLabel = "内网IP"
	// cacheLimit 结果缓存容量上限：蜜罐来源 IP 数量有限，超限后仅查询不缓存，防异常流量撑爆内存。
	cacheLimit = 8192
	// builtinV4 / builtinV6 内置库在 embed.FS 中的路径。
	builtinV4 = "assets/ip2region_v4.xdb"
	builtinV6 = "assets/ip2region_v6.xdb"
)

// regionIdx 从「国家|区域|省份|城市|ISP」中取国家、省份、城市。
var regionIdx = []int{0, 2, 3}

// Locator IP 归属地定位器；v4/v6 任一可用即可工作，均不可用时为空实现。
type Locator struct {
	// mu 保护 searcher：xdb 的读取实现是 Seek+Read，非并发安全；
	// 同时保护 cache。蜜罐查询频率低且命中缓存，串行化开销可忽略。
	mu    sync.Mutex
	v4    *xdb.Searcher
	v6    *xdb.Searcher
	cache map[string]string
	// tempFiles 内置库释放出的临时文件，Close 时删除。
	tempFiles []string
}

// Load 加载 v4/v6 库并构造定位器；文件全部缺失或损坏时返回降级实例并告警，不返回错误。
func Load(v4Path, v6Path string, logger *slog.Logger) *Locator {
	l := &Locator{cache: make(map[string]string, cacheLimit)}

	v4, ok4 := l.openSide("v4", v4Path, builtinV4, xdb.IPv4, logger)
	if ok4 {
		l.v4 = v4
	}
	v6, ok6 := l.openSide("v6", v6Path, builtinV6, xdb.IPv6, logger)
	if ok6 {
		l.v6 = v6
	}

	if l.v4 == nil && l.v6 == nil {
		warnf(logger, "未加载到任何 IP 库文件（log.ipdb_v4 / log.ipdb_v6），归属地留空")
		return l
	}
	infof(logger, fmt.Sprintf("IP 归属地库已加载: v4=%v, v6=%v", l.v4 != nil, l.v6 != nil))
	return l
}

// openSide 加载单侧库：外部文件优先，缺失时释放内置库到临时文件；两者均失败返回 false。
func (l *Locator) openSide(tag, extPath, builtinName string, version *xdb.Version, logger *slog.Logger) (*xdb.Searcher, bool) {
	source := ""
	path := strings.TrimSpace(extPath)
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			infof(logger, fmt.Sprintf("%s IP 库文件不存在: %s，回退使用内置库", tag, absPath(path)))
			path = ""
		} else {
			source = absPath(path)
		}
	}

	if path == "" {
		tmp, err := l.extractBuiltin(builtinName)
		if err != nil {
			warnf(logger, fmt.Sprintf("%s IP 库既无外部文件也无内置资源 %s，%s 归属地留空: %v",
				tag, builtinName, tag, err))
			return nil, false
		}
		l.tempFiles = append(l.tempFiles, tmp)
		path = tmp
		source = "embed:" + builtinName + "（已释放到 " + tmp + "）"
	}

	searcher, err := newSearcher(version, path)
	if err != nil {
		warnf(logger, fmt.Sprintf("%s IP 库文件加载失败，%s 归属地留空: %v", tag, tag, err))
		return nil, false
	}
	infof(logger, fmt.Sprintf("%s IP 归属地库已加载: %s", tag, source))
	return searcher, true
}

// newSearcher 优先用向量索引打开（仅索引进内存）；索引读取失败时回退纯文件检索。
func newSearcher(version *xdb.Version, path string) (*xdb.Searcher, error) {
	if vIndex, err := xdb.LoadVectorIndexFromFile(path); err == nil {
		return xdb.NewWithVectorIndex(version, path, vIndex)
	}
	return xdb.NewWithFileOnly(version, path)
}

// extractBuiltin 把内置库写入临时文件（xdb 的向量索引模式需要可随机读取的文件）。
func (l *Locator) extractBuiltin(name string) (string, error) {
	data, err := builtinFS.ReadFile(name)
	if err != nil {
		return "", err
	}
	pattern := "ip2region-" + strings.TrimSuffix(filepath.Base(name), ".xdb") + "-*.xdb"
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// Available 库是否可用（v4/v6 任意一个已加载）。
func (l *Locator) Available() bool {
	return l != nil && (l.v4 != nil || l.v6 != nil)
}

// Locate 解析 IP 归属地为「国家 省份 城市」。
// 库不可用、地址非法或库中无记录时返回空串；内网地址返回 PrivateLabel。
func (l *Locator) Locate(ip string) string {
	if l == nil || (l.v4 == nil && l.v6 == nil) {
		return ""
	}
	key := strings.TrimSpace(ip)
	if key == "" {
		return ""
	}
	if IsPrivate(key) {
		return PrivateLabel
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if cached, ok := l.cache[key]; ok {
		return cached
	}
	location := l.search(key)
	// 达上限后仅查询不缓存，避免异常流量撑爆内存
	if len(l.cache) < cacheLimit {
		l.cache[key] = location
	}
	return location
}

// search 按 IP 版本选择对应库检索；未加载的版本直接返回空串。
func (l *Locator) search(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	searcher := l.v6
	if parsed.To4() != nil {
		searcher = l.v4
	}
	if searcher == nil {
		return ""
	}
	region, err := searcher.Search(ip)
	if err != nil {
		return ""
	}
	return Format(region)
}

// Close 关闭检索器并清理内置库释放的临时文件。
func (l *Locator) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.v4 != nil {
		l.v4.Close()
		l.v4 = nil
	}
	if l.v6 != nil {
		l.v6.Close()
		l.v6 = nil
	}
	for _, path := range l.tempFiles {
		_ = os.Remove(path)
	}
	l.tempFiles = nil
	l.cache = make(map[string]string)
}

// Format 把「国家|区域|省份|城市|ISP」整理为「国家 省份 城市」：
// 跳过 0 占位符与空段，并合并相邻重复段（如「上海 上海」）。
func Format(region string) string {
	if strings.TrimSpace(region) == "" {
		return ""
	}
	parts := strings.Split(region, "|")
	var b strings.Builder
	last := ""
	for _, idx := range regionIdx {
		if idx >= len(parts) {
			break
		}
		v := strings.TrimSpace(parts[idx])
		if v == "" || v == "0" || v == last {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(v)
		last = v
	}
	return b.String()
}

// IsPrivate 识别内网 / 环回 / 链路本地地址（IPv4 + IPv6），命中后无需检索库。
func IsPrivate(ip string) bool {
	lower := strings.ToLower(ip)
	// IPv6：环回（含展开写法）、ULA fc00::/7、链路本地 fe80::/10
	switch lower {
	case "::", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	if strings.HasPrefix(lower, "fc") || strings.HasPrefix(lower, "fd") || strings.HasPrefix(lower, "fe80") {
		return true
	}

	// IPv4 私有段；非点分四段（如公网 IPv6）交由 v6 库检索
	seg := strings.Split(ip, ".")
	if len(seg) != 4 {
		return false
	}
	a, err1 := strconv.Atoi(seg[0])
	b, err2 := strconv.Atoi(seg[1])
	if err1 != nil || err2 != nil || a > 255 || b > 255 {
		return false
	}
	return a == 10 || // 10.0.0.0/8
		(a == 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
		(a == 192 && b == 168) || // 192.168.0.0/16
		a == 127 || a == 0 || // 环回 / 本网络
		(a == 169 && b == 254) // 链路本地
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

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

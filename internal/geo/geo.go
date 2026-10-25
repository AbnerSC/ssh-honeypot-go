// Package geo 基于 ip2region xdb 离线库解析 IP 归属地，
// 供攻击日志（sessions/auth_attempts/...）与 Web 审计日志记录「国家 省份 城市」。
//
// 库文件：仅使用二进制内置的 xdb（go:embed），不读取外部文件、不释放临时文件；
// 内置资源随二进制打包，镜像无需挂载 db 卷。
//
// 内存策略：只把向量索引（约 512KB/库）读入内存，数据段通过 embed 文件的
// Seek+Read 按需读取，避免 46MB（v4 约 10MB + v6 约 36MB）整库入堆；
// 查询另有进程内结果缓存。库不可用时降级：Locate 恒返回空串，不影响蜜罐运行。
package geo

import (
	"embed"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// 内置库：随二进制打包，唯一数据来源。
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
	// probeV4 / probeV6 启动自检探针：公网地址在库中必有记录，
	// 解析报错说明库与版本不匹配（如把 v6 库当 v4 用），直接停用该侧避免运行期静默返回空。
	probeV4 = "1.1.1.1"
	probeV6 = "2001:4860:4860::8888"
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
}

// Load 打开内置 v4/v6 库并构造定位器；单侧加载失败仅告警并降级，不返回错误。
func Load(logger *slog.Logger) *Locator {
	l := &Locator{cache: make(map[string]string, cacheLimit)}

	if s, err := openBuiltin(builtinV4, xdb.IPv4, probeV4); err != nil {
		warnf(logger, "v4 IP 归属地库不可用，v4 归属地留空: "+err.Error())
	} else {
		l.v4 = s
	}
	if s, err := openBuiltin(builtinV6, xdb.IPv6, probeV6); err != nil {
		warnf(logger, "v6 IP 归属地库不可用，v6 归属地留空: "+err.Error())
	} else {
		l.v6 = s
	}

	if l.v4 == nil && l.v6 == nil {
		warnf(logger, "内置 IP 归属地库均不可用，归属地留空")
		return l
	}
	infof(logger, fmt.Sprintf("内置 IP 归属地库已加载（仅向量索引常驻内存，数据段按需读取）: v4=%v, v6=%v",
		l.v4 != nil, l.v6 != nil))
	return l
}

// openBuiltin 打开内置库：只把向量索引（512KB）读入内存，
// 数据段由 embed 文件直接 Seek+Read，既不落临时文件也不整库入堆。
func openBuiltin(name string, version *xdb.Version, probe string) (*xdb.Searcher, error) {
	f, err := builtinFS.Open(name)
	if err != nil {
		return nil, fmt.Errorf("打开内置库 %s 失败: %w", name, err)
	}
	// embed 的 fs.File 实现支持随机读取，可直接作为 xdb 的数据源
	reader, ok := f.(io.ReadSeekCloser)
	if !ok {
		_ = f.Close()
		return nil, fmt.Errorf("内置库 %s 不支持随机读取", name)
	}

	vIndex, err := xdb.LoadVectorIndex(reader)
	if err != nil {
		_ = reader.Close()
		return nil, fmt.Errorf("读取内置库 %s 向量索引失败: %w", name, err)
	}
	searcher := xdb.INewSearcher(version, reader, vIndex, nil)
	// 自检：探针地址解析报错说明库与版本不匹配，关闭后该侧降级
	if _, err := searcher.Search(probe); err != nil {
		searcher.Close()
		return nil, fmt.Errorf("内置库 %s 自检失败（%s）: %w", name, probe, err)
	}
	return searcher, nil
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

// Close 关闭检索器并释放缓存。
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

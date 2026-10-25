package cmd

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// maxSleepSeconds sleep 命令的延迟上限（秒），防止超长 sleep 永久占用会话。
const maxSleepSeconds = 120

// simulateLatency 按命令类型模拟真实执行耗时，让响应节奏接近真实主机。
func (p *Processor) simulateLatency(name string, args []string) {
	if !p.latency {
		return
	}
	ms := latencyMillis(name, args)
	if ms <= 0 {
		return
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// between 返回 [min, max] 内的随机整数。
func between(min, max int64) int64 {
	if max <= min {
		return min
	}
	return min + rand.Int64N(max-min+1)
}

// latencyMillis 按命令类型给出模拟耗时（毫秒），区间随机以避免节奏过于机械。
func latencyMillis(name string, args []string) int64 {
	// 基线抖动：shell 解析 + 终端 IO 的自然延迟
	jitter := between(15, 80)
	var base int64
	switch name {
	// 网络连接超时类：真实 TCP 超时需要等待数秒
	case "ssh", "scp", "sftp", "ftp", "telnet":
		base = between(8_000, 15_000)
	// 反弹 shell / 外连挂起类：模拟长时间等待回连
	case "nc", "ncat", "netcat", "socat":
		base = between(20_000, 40_000)
	// 网络探测类
	case "ping", "ping6":
		base = between(3_500, 5_500) // 默认 4 包、每包间隔 1 秒
	case "traceroute", "tracepath", "mtr":
		base = between(2_500, 6_000)
	case "dig", "nslookup", "host":
		base = between(150, 600)
	// 下载 / 传输类
	case "wget", "curl":
		base = between(1_500, 4_500)
	case "rsync":
		base = between(2_000, 6_000)
	// 包管理 / 编译安装类
	case "apt", "apt-get", "aptitude", "yum", "dnf":
		base = between(2_000, 6_000)
	case "dpkg", "rpm", "snap", "flatpak":
		base = between(800, 2_500)
	case "gcc", "cc", "g++", "make", "cmake":
		base = between(1_500, 5_000)
	case "pip", "pip3", "npm", "yarn", "cargo", "go":
		base = between(1_500, 5_000)
	// 磁盘重操作类
	case "tar", "unzip", "zip", "gzip", "gunzip", "bzip2", "xz":
		base = between(600, 2_500)
	case "dd":
		base = between(1_200, 4_000)
	case "mkfs", "mkswap", "fsck":
		base = between(1_500, 4_500)
	case "sync":
		base = between(500, 2_000)
	// 系统管理 / 认证类
	case "systemctl", "service":
		base = between(350, 1_200)
	case "su", "sudo", "passwd", "chpasswd", "visudo", "pkexec":
		base = between(400, 1_000)
	case "reboot", "shutdown", "halt", "poweroff":
		base = between(2_500, 5_000)
	case "journalctl", "dmesg", "lsof", "lspci", "lsusb", "lsmod":
		base = between(200, 800)
	case "useradd", "adduser", "usermod", "deluser", "userdel":
		base = between(200, 600)
	// 解释器一行式脚本执行
	case "python", "python3", "perl", "php", "ruby", "lua", "node", "java":
		base = between(250, 1_000)
	// 扫描 / 遍历类
	case "find", "grep", "egrep", "fgrep", "zgrep", "locate":
		base = between(120, 700)
	case "du", "df", "free", "ps", "top", "htop", "vmstat", "iostat":
		base = between(60, 350)
	// sleep：按参数真实等待
	case "sleep":
		base = sleepArgMillis(args)
	// 即时返回的内建命令几乎无延迟
	case "exit", "logout", "quit", "true", "false", "cd", "pwd", "echo",
		"whoami", "id", "history", "help", "clear", "tty":
		base = 0
	// 其余按普通快速命令处理
	default:
		base = between(20, 250)
	}
	return jitter + base
}

// sleepArgMillis 解析 sleep 参数并返回应等待的毫秒数（上限 maxSleepSeconds 秒）。
func sleepArgMillis(args []string) int64 {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		raw := strings.TrimRight(a, "smhd")
		sec, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			break
		}
		mul := 1.0
		switch {
		case strings.HasSuffix(a, "m"):
			mul = 60
		case strings.HasSuffix(a, "h"):
			mul = 3600
		case strings.HasSuffix(a, "d"):
			mul = 86400
		}
		ms := int64(sec * mul * 1000)
		if limit := int64(maxSleepSeconds) * 1000; ms > limit {
			return limit
		}
		return ms
	}
	return between(500, 1_500)
}

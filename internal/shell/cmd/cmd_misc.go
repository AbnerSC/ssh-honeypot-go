package cmd

import (
	"encoding/base64"
	"math/rand/v2"
	"strconv"
	"strings"

	"ssh-honeypot-go/internal/fakeenv"
	"ssh-honeypot-go/internal/shell"
)

// echo 回显参数（-n 不换行，支持 \n / \t 转义）。
func (p *Processor) echo(args []string) shell.Output {
	newline := true
	parts := args
	if len(parts) > 0 && parts[0] == "-n" {
		newline = false
		parts = parts[1:]
	}
	s := strings.Join(parts, " ")
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\t", "\t")
	if !newline {
		return shell.Output{Text: s, NoNewline: true}
	}
	return shell.Output{Text: s}
}

// su 提权：蜜罐直接放行，仅记录提权尝试。
func (p *Processor) su(st *shell.Session, args []string) string {
	target := "root"
	if len(args) > 0 {
		target = args[0]
	}
	p.logCommand(st, "[提权尝试] su "+target)
	if target == "root" && st.Username != "root" {
		st.Username = "root"
		st.HomeDir = "/root"
		st.Cwd = "/root"
	}
	return ""
}

// kill kill/killall/pkill：校验 PID 形态后假装成功。
func (p *Processor) kill(args []string) string {
	pids := nonFlags(args)
	if len(pids) == 0 {
		return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ..."
	}
	for _, pid := range pids {
		if !isAllDigits(pid) {
			return "kill: " + pid + ": arguments must be process or job IDs"
		}
	}
	// 蜜罐内无真实进程，假装成功
	return ""
}

// sbinCmds which 时走 /usr/sbin 的命令清单。
var sbinCmds = map[string]bool{
	"ifconfig": true, "ip": true, "iptables": true, "reboot": true, "shutdown": true,
	"sshd": true, "fdisk": true, "mkfs": true, "service": true, "init": true,
	"useradd": true, "userdel": true,
}

// which which/whereis 输出命令路径。
func (p *Processor) which(args []string) string {
	names := nonFlags(args)
	if len(names) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, n := range names {
		if sbinCmds[n] {
			sb.WriteString("/usr/sbin/" + n + "\n")
		} else {
			sb.WriteString("/usr/bin/" + n + "\n")
		}
	}
	return stripTrailing(sb.String())
}

// typeCmd type 输出命令类型。
func (p *Processor) typeCmd(args []string) string {
	if len(args) == 0 {
		return ""
	}
	n := args[0]
	return n + " is /usr/bin/" + n
}

// base64Cmd base64 编解码（无文件参数时视为读 stdin，静默返回）。
func (p *Processor) base64Cmd(st *shell.Session, args []string) string {
	decode := hasArg(args, "-d") || hasArg(args, "--decode")
	files := nonFlags(args)
	if len(files) == 0 {
		return ""
	}
	content := ""
	for _, f := range files {
		if st.FS.Resolve(st.Cwd, f) == nil {
			return "base64: " + f + ": No such file or directory"
		}
		content, _ = st.FS.ReadFile(st.Cwd, f)
	}
	if decode {
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(content), ""))
		if err != nil {
			return "base64: invalid input"
		}
		return string(raw)
	}
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// sumCmd md5sum/sha*sum：返回对应算法的空串哈希（假的但格式一致）。
func (p *Processor) sumCmd(st *shell.Session, name string, args []string) string {
	files := nonFlags(args)
	if len(files) == 0 {
		return name + ": no files to hash"
	}
	hash := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	switch name {
	case "md5sum":
		hash = "d41d8cd98f00b204e9800998ecf8427e"
	case "sha1sum":
		hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	case "sha256sum":
		hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	var sb strings.Builder
	for _, f := range files {
		if st.FS.Resolve(st.Cwd, f) == nil {
			sb.WriteString(name + ": " + f + ": No such file or directory\n")
			continue
		}
		sb.WriteString(hash + "  " + f + "\n")
	}
	return stripTrailing(sb.String())
}

// openssl 输出：version 走本地常量，其余交 AI。
func (p *Processor) openssl(st *shell.Session, cmdline string, args []string) string {
	if len(args) > 0 && args[0] == "version" {
		return "OpenSSL " + fakeenv.OpenSSL + " 15 Mar 2022 (Library: OpenSSL " + fakeenv.OpenSSL + " 15 Mar 2022)"
	}
	return p.aiFallbackSilent(st, cmdline)
}

// useradd adduser 后门账号：记录不创建。
func (p *Processor) useradd(st *shell.Session, args []string) string {
	name := firstNonFlag(args)
	if name == "" {
		return "useradd: missing operand"
	}
	p.logCommand(st, "[后门账号] useradd "+strings.Join(args, " "))
	return ""
}

// getent 查询系统数据库（passwd/hosts 本地伪造，其余交 AI）。
func (p *Processor) getent(st *shell.Session, cmdline string, args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "passwd":
		user := "root"
		if len(args) > 1 {
			user = args[1]
		}
		if user == "root" {
			return "root:x:0:0:root:/root:/bin/bash"
		}
		return user + ":x:1000:1000:" + user + ":/home/" + user + ":/bin/bash"
	case "hosts":
		if len(args) > 1 {
			return fakeenv.WANIP + "     " + args[1]
		}
	}
	return p.aiFallbackSilent(st, cmdline)
}

// iptablesText iptables -L 输出。
const iptablesText = "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n\n" +
	"Chain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n\n" +
	"Chain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination"

// iptables 防火墙规则：-L 列出，其余静默。
func (p *Processor) iptables(args []string) string {
	if hasArg(args, "-L") || hasArg(args, "--list") {
		return iptablesText
	}
	return ""
}

// ufwText ufw status 输出。
const ufwText = "Status: active\n\nTo                         Action      From\n" +
	"--                         ------      ----\n" +
	"22/tcp                     ALLOW       Anywhere\n" +
	"80/tcp                     ALLOW       Anywhere\n" +
	"22/tcp (v6)                ALLOW       Anywhere (v6)\n" +
	"80/tcp (v6)                ALLOW       Anywhere (v6)"

// ufw 防火墙：status 本地伪造，其余交 AI。
func (p *Processor) ufw(st *shell.Session, cmdline string, args []string) string {
	if len(args) > 0 && args[0] == "status" {
		return ufwText
	}
	return p.aiFallbackSilent(st, cmdline)
}

// aliasCmd alias 列表。
func (p *Processor) aliasCmd(args []string) string {
	if len(args) == 0 {
		return "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'"
	}
	return ""
}

// dd 磁盘操作：记录危险行为，返回伪造统计。
func (p *Processor) dd(st *shell.Session, args []string) string {
	p.logCommand(st, "[危险操作] dd "+strings.Join(args, " "))
	return "4+0 records in\n4+0 records out\n2048 bytes (2.0 kB, 2.0 KiB) copied, 0.00052 s, 3.9 MB/s"
}

// maxSeqLines seq 单次最多输出的行数：200000 行约 1.4MB，既避免内存被滥用，
// 又不会像旧实现那样在 seq 1 50000 时静默输出空串（真实 GNU seq 不会）。
const maxSeqLines = 200000

// seqCmd 生成数字序列，语义对齐 GNU seq：
//
//	seq LAST | seq FIRST LAST | seq FIRST INCREMENT LAST
//
// 支持 -w/--equal-width（等宽补零）与 -s/--separator（分隔符），整数与小数均可。
func (p *Processor) seqCmd(args []string) string {
	equalWidth, sep := false, "\n"
	nums := make([]string, 0, 3)
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-w" || a == "--equal-width":
			equalWidth = true
		case a == "-s" || a == "--separator":
			if i+1 >= len(args) {
				return "seq: option requires an argument -- 's'"
			}
			sep = args[i+1]
			i++
		case strings.HasPrefix(a, "--separator="):
			sep = strings.TrimPrefix(a, "--separator=")
		case strings.HasPrefix(a, "-s") && len(a) > 2:
			sep = a[2:]
		default:
			nums = append(nums, a)
		}
	}
	if len(nums) == 0 {
		return "seq: missing operand"
	}
	if len(nums) > 3 {
		return "seq: extra operand '" + nums[3] + "'"
	}

	vals := make([]float64, len(nums))
	decimals := 0
	for i, s := range nums {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return "seq: invalid floating point argument: '" + s + "'"
		}
		vals[i] = v
		if d := seqDecimals(s); d > decimals {
			decimals = d
		}
	}

	first, step, last := 1.0, 1.0, vals[0]
	switch len(vals) {
	case 2:
		first, last = vals[0], vals[1]
	case 3:
		first, step, last = vals[0], vals[1], vals[2]
	}
	if step == 0 || (step > 0 && first > last) || (step < 0 && first < last) {
		return ""
	}

	lines := make([]string, 0, 16)
	for v := first; len(lines) < maxSeqLines; v += step {
		if step > 0 && v > last+1e-9 {
			break
		}
		if step < 0 && v < last-1e-9 {
			break
		}
		// -0 统一显示为 0，避免出现 "-0" 这种真实 seq 不会有的输出
		s := strconv.FormatFloat(v, 'f', decimals, 64)
		if strings.HasPrefix(s, "-") && strings.Trim(strings.TrimPrefix(s, "-"), "0.") == "" {
			s = s[1:]
		}
		lines = append(lines, s)
	}
	if len(lines) == 0 {
		return ""
	}
	if equalWidth {
		width := 0
		for _, s := range lines {
			if w := len(strings.TrimPrefix(s, "-")); w > width {
				width = w
			}
		}
		for i, s := range lines {
			neg := strings.HasPrefix(s, "-")
			pad := width - len(strings.TrimPrefix(s, "-"))
			if pad <= 0 {
				continue
			}
			zero := strings.Repeat("0", pad)
			if neg {
				lines[i] = "-" + zero + s[1:]
			} else {
				lines[i] = zero + s
			}
		}
	}
	return strings.Join(lines, sep)
}

// seqDecimals 返回数字字面量的小数位数（用于按输入精度格式化输出）。
func seqDecimals(s string) int {
	if strings.ContainsAny(s, "eE") {
		return 0
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return len(s) - i - 1
	}
	return 0
}

// strace 输出系统调用跟踪（伪造）。
func (p *Processor) strace(args []string) string {
	target := firstNonFlag(args)
	if target == "" {
		return "strace: Must have at least one command"
	}
	return "execve(\"/usr/bin/" + target + "\", [\"" + target + "\"], 0x7ffd...) = 0\n+++ exited with 0 +++"
}

// lddText 动态库依赖。
const lddText = "\tlinux-vdso.so.1 (0x00007ffd5b3c2000)\n" +
	"\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2c8a400000)\n" +
	"\t/lib64/ld-linux-x86-64.so.2 (0x00007f2c8a6a1000)"

// ldd 输出动态库依赖（伪造）。
func (p *Processor) ldd(args []string) string {
	if firstNonFlag(args) == "" {
		return "ldd: missing file arguments"
	}
	return lddText
}

// fileCmd file 判断文件类型。
func (p *Processor) fileCmd(st *shell.Session, args []string) string {
	target := firstNonFlag(args)
	if target == "" {
		return "Usage: file [OPTION...] [FILE...]"
	}
	node := st.FS.Resolve(st.Cwd, target)
	if node == nil {
		return target + ": cannot open `" + target + "' (No such file or directory)"
	}
	if node.Dir {
		return target + ": directory"
	}
	content, _ := st.FS.ReadFile(st.Cwd, target)
	if strings.HasPrefix(content, "#!") {
		return target + ": POSIX shell script, ASCII text executable"
	}
	if strings.HasSuffix(node.Name, ".sh") {
		return target + ": Bourne-Again shell script, ASCII text executable"
	}
	return target + ": ASCII text"
}

// pathCmd realpath/dirname/basename/readlink。
func (p *Processor) pathCmd(st *shell.Session, name string, args []string) string {
	path := firstNonFlag(args)
	if path == "" {
		return name + ": missing operand"
	}
	slash := strings.LastIndexByte(path, '/')
	switch name {
	case "dirname":
		switch {
		case slash < 0:
			return "."
		case slash == 0:
			return "/"
		default:
			return path[:slash]
		}
	case "basename":
		if slash >= 0 {
			return path[slash+1:]
		}
		return path
	case "readlink":
		return ""
	default: // realpath：返回规范化后的绝对路径
		return st.FS.Normalize(st.Cwd, path)
	}
}

// mktemp 创建临时文件并返回路径。
func (p *Processor) mktemp(st *shell.Session, args []string) string {
	tmpl := "/tmp/tmp.XXXXXXXXXX"
	if len(args) > 0 {
		tmpl = args[0]
	}
	if !strings.Contains(tmpl, "/") {
		tmpl = "/tmp/" + tmpl
	}
	xCount := 0
	for i := len(tmpl) - 1; i >= 0 && tmpl[i] == 'X'; i-- {
		xCount++
	}
	if xCount < 3 {
		return "mktemp: too few X's in template '" + tmpl + "'"
	}
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	var randPart strings.Builder
	for i := 0; i < xCount; i++ {
		randPart.WriteByte(chars[rand.IntN(len(chars))])
	}
	abs := st.FS.Normalize(st.Cwd, tmpl[:len(tmpl)-xCount]+randPart.String())
	// 父目录存在才落地假文件
	if i := strings.LastIndexByte(abs, '/'); i > 0 && st.FS.Resolve("/", abs[:i]) != nil {
		st.FS.Touch("/", abs, st.Username)
	}
	return abs
}

// lsbRelease lsb_release 输出（-a 全量，其余交 AI）。
func (p *Processor) lsbRelease(st *shell.Session, cmdline string, args []string) string {
	if hasArg(args, "-a") || hasArg(args, "--all") {
		return "Distributor ID:\tUbuntu\nDescription:\t" + fakeenv.OSDesc +
			"\nRelease:\t" + fakeenv.OSRelease + "\nCodename:\t" + fakeenv.OSCodename
	}
	return p.aiFallbackSilent(st, cmdline)
}

// neofetch 系统信息概览。
func (p *Processor) neofetch() string {
	return "            .-/+oossssoo+/-.               root@" + p.hostname + "\n" +
		"        `:+ssssssssssssssssss+:`           ------------\n" +
		"      -+ssssssssssssssssssyyssss+-         OS: " + fakeenv.OSDesc + " " + fakeenv.Arch + "\n" +
		"     /ssssssssssssssssssdMMMNysssso.       Kernel: " + fakeenv.Kernel + "\n" +
		"    +sssssssssshdmmNNmmyNMMMMhssssss/      Uptime: 47 days, 3 hours\n" +
		"   .osssssshdmmNNMNNNMMMMNMMMMdssssssso    Shell: bash 5.1.16\n" +
		"  ossss+MMMNMMMNMMMMMMMMMMMMMMMN+sssssss   CPU: Intel Xeon Platinum 8375C (4) @ 2.90GHz\n" +
		"  ssss/MMMMMMMMMMMMMMMMMMMMMMMMMM+ssssss   Memory: 2816MiB / 7970MiB"
}

// initCmd init 6/0：记录危险操作并断开连接（模拟重启/关机）。
func (p *Processor) initCmd(st *shell.Session, args []string) shell.Output {
	if len(args) > 0 && (args[0] == "0" || args[0] == "6") {
		p.logCommand(st, "[危险操作] init "+args[0])
		return exitOutput()
	}
	return shell.Output{}
}

// 各类静态输出常量（与 Java 版逐字一致）。
const (
	lspciText = "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)\n" +
		"00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n" +
		"00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n" +
		"00:03.0 Ethernet controller: Microsoft Corporation Hyper-V virtual NIC"
	lsmemText = "RANGE                                  SIZE  STATE REMOVABLE  BLOCK\n" +
		"0x0000000000000000-0x000000007fffffff   2G online       yes 0-15\n\n" +
		"Memory block size:       128M\nTotal online memory:       8G\nTotal offline memory:      0B"
	lsmodText = "Module                  Size  Used by\n" +
		"ipv6                  520192  24\nnf_conntrack_netlink    49152  0\nxfrm_algo              16384  1"
	fsckText    = "/dev/sda1: clean, 131245/5242880 files, 1531422/20971264 blocks"
	swaponText  = "NAME      TYPE      SIZE USED PRIO\n/dev/sda2 partition   2G   0B -2"
	passwdError = "passwd: Authentication token manipulation error\npasswd: password unchanged"
)

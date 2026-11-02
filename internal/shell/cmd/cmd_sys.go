package cmd

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"ssh-honeypot-go/internal/fakeenv"
	"ssh-honeypot-go/internal/shell"
)

// helpText `help` 内建命令的输出。
const helpText = "GNU bash, version " + fakeenv.BashVersion + " (x86_64-pc-linux-gnu)\n" +
	"These shell commands are defined internally.  Type `help' to see this list.\n" +
	"cd ls cat head tail wc echo pwd whoami id uname hostname ps kill clear history exit\n" +
	"cp mv rm mkdir touch chmod chown ln stat du df free top netstat ping wget curl crontab\n" +
	"systemctl service journalctl docker kubectl mysql base64 md5sum tar unzip find grep"

// whoami 输出当前登录用户。
func (p *Processor) whoami(st *shell.Session) string {
	return st.Username
}

// id 输出 uid/gid 信息。
func (p *Processor) id(st *shell.Session) string {
	if st.Username == "root" {
		return "uid=0(root) gid=0(root) groups=0(root)"
	}
	return "uid=1000(" + st.Username + ") gid=1000(" + st.Username +
		") groups=1000(" + st.Username + "),27(sudo)"
}

// groups 输出用户所属组。
func (p *Processor) groups(st *shell.Session) string {
	if st.Username == "root" {
		return "root"
	}
	return st.Username + " sudo"
}

// uname 输出内核与主机信息（支持常用单字母选项）。
func (p *Processor) uname(args []string) string {
	flag := ""
	if len(args) > 0 {
		flag = args[0]
	}
	switch flag {
	case "-a":
		return "Linux " + p.hostname + " " + fakeenv.Kernel + " " + fakeenv.KernelBuild +
			" " + fakeenv.Arch + " " + fakeenv.Arch + " " + fakeenv.Arch + " GNU/Linux"
	case "-r":
		return fakeenv.Kernel
	case "-m":
		return fakeenv.Arch
	case "-n":
		return p.hostname
	case "-s":
		return "Linux"
	case "-v":
		return fakeenv.KernelBuild
	case "-o":
		return "GNU/Linux"
	default:
		return "Linux"
	}
}

// hostnameCmd hostname / hostnamectl 输出（支持 -I / -i / -f）。
func (p *Processor) hostnameCmd(args []string) string {
	if hasArg(args, "-I") || hasArg(args, "--all-ip-addresses") {
		return fakeenv.Eth0IP
	}
	if hasArg(args, "-i") {
		return fakeenv.Eth0IP
	}
	if hasArg(args, "-f") {
		return p.hostname + ".internal"
	}
	return p.hostname
}

// w who/w 输出当前登录会话。
func (p *Processor) w(st *shell.Session) string {
	now := time.Now()
	return " " + now.Format(layoutTimeHMS) +
		" up " + fakeenv.Uptime + ",  1 user,  load average: 0.08, 0.03, 0.01\n" +
		"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
		st.Username + "   pts/0    " + st.IP + "     " +
		now.Format(layoutTimeHM) +
		"    0.00s  0.02s  0.00s w"
}

// uptime 输出运行时间与随机负载。
func (p *Processor) uptime() string {
	load := 0.01 + rand.Float64()*0.29
	return " " + time.Now().Format(layoutTimeHMS) +
		" up " + fakeenv.Uptime + ",  1 user,  load average: " +
		strconv.FormatFloat(load, 'f', 2, 64) + ", " +
		strconv.FormatFloat(load*0.8, 'f', 2, 64) + ", " +
		strconv.FormatFloat(load*0.6, 'f', 2, 64)
}

// psTextAux ps aux 风格的进程列表。
const psTextAux = "root           1  0.0  0.2 167892 11824 ?        Ss   Jun24   2:14 /sbin/init\n" +
	"root         412  0.0  0.1  72300  6236 ?        Ss   Jun24   0:32 /usr/sbin/sshd -D\n" +
	"root         519  0.0  0.4 388920 21432 ?        Ssl  Jun24   5:47 /usr/bin/mysqld\n" +
	"www-data     803  0.0  0.3 245112 16028 ?        S    Jun24   1:02 nginx: worker process\n" +
	"root        1102  0.0  0.1  21788  6512 ?        Ss   Jun24   0:18 /usr/sbin/cron -f\n" +
	"root       21841  0.0  0.1  13524  7944 ?        Ss   06:25   0:00 sshd: root@pts/0\n" +
	"root       21850  0.0  0.0   9056  4628 pts/0    Ss   06:25   0:00 -bash"

// psTextBrief 默认 ps 的精简输出。
const psTextBrief = "21850 pts/0    00:00:00 bash\n" +
	"21901 pts/0    00:00:00 ps"

// ps 输出进程列表（含 a/x/e 选项时用 aux 格式）。
func (p *Processor) ps(args []string) string {
	aux := false
	for _, a := range args {
		if strings.ContainsAny(a, "axe") {
			aux = true
			break
		}
	}
	if aux {
		return "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" + psTextAux
	}
	return "    PID TTY          TIME CMD\n" + psTextBrief
}

// top 输出系统概览。
func (p *Processor) top() string {
	return "top - " + time.Now().Format(layoutTimeHMS) +
		" up " + fakeenv.Uptime + ",  1 user,  load average: 0.08, 0.03, 0.01\n" +
		"Tasks:  97 total,   1 running,  96 sleeping,   0 stopped,   0 zombie\n" +
		"%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st"
}

// history 输出命令历史（行号从 1 开始）。
func (p *Processor) history(st *shell.Session) string {
	var sb strings.Builder
	for i, cmdline := range st.History {
		sb.WriteString(padHistory(i+1) + "  " + cmdline + "\n")
	}
	return stripTrailing(sb.String())
}

// padHistory 行号右对齐到 5 位（history 的 %5d）。
func padHistory(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 5 {
		s = " " + s
	}
	return s
}

// env 输出环境变量（env/printenv/set/export 复用）。
func (p *Processor) env(st *shell.Session) string {
	return "SHELL=/bin/bash\nUSER=" + st.Username + "\nHOME=" + st.HomeDir +
		"\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"HOSTNAME=" + p.hostname + "\nTERM=xterm\nLANG=en_US.UTF-8\nPWD=" + st.Cwd
}

// df 输出磁盘占用，-h 用人类可读单位。
func (p *Processor) df(args []string) string {
	if hasShort(args, 'h') {
		return "Filesystem      Size  Used  Avail  Use%  Mounted on\n" +
			fakeenv.DiskRootDev + "       79G   31G   44G    42%   /\n" +
			"tmpfs           3.9G  0     3.9G   0%    /dev/shm\n" +
			fakeenv.DiskDataDev + "       99G   18G   76G    19%   /data"
	}
	return "Filesystem      1K-blocks     Used       Available  Use%   Mounted on\n" +
		fakeenv.DiskRootDev + "       82559280      32471164   45875896   42%    /\n" +
		"tmpfs           4080572       0          4080572    0%     /dev/shm\n" +
		fakeenv.DiskDataDev + "       103080232     18495632   79342184   19%    /data"
}

// free 输出内存占用。
func (p *Processor) free(args []string) string {
	if hasShort(args, 'h') {
		return "               total        used        free      shared   buff/cache    available\n" +
			"Mem:       " + fakeenv.MemTotalH + "       2.7Gi       2.3Gi        12Mi        2.8Gi        5.1Gi\n" +
			"Swap:      " + fakeenv.SwapTotalH + "          0B       " + fakeenv.SwapTotalH
	}
	return "                            total        used        free      shared    buff/cache   available\n" +
		"Mem:      8161148     2816532     2415688       12460       2928928     5341560\n" +
		"Swap:     2097148           0     2097148"
}

// vmstatText vmstat 输出。
const vmstatText = "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n" +
	" r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n" +
	" 1  0      0 2415688 102400 2928928    0    0    12    45  187  412  1  1 98  0  0"

// iostat 输出平均 CPU 占用。
func (p *Processor) iostat() string {
	return "Linux " + fakeenv.Kernel + " (" + p.hostname + ") \t08/11/26 \t_" + fakeenv.Arch + "_\t(" +
		strconv.Itoa(fakeenv.CPUCount) + " CPU)\n\n" +
		"avg-cpu:  %user   %nice %system %iowait  %steal   %idle\n" +
		"           1.26    0.01    0.68    0.19    0.00   97.85"
}

// dateCmd date 输出：支持 +FORMAT（C 风格格式串），默认 ctime 格式。
func (p *Processor) dateCmd(args []string) string {
	now := time.Now()
	if len(args) > 0 && strings.HasPrefix(args[0], "+") {
		return formatDate(now, args[0][1:])
	}
	return now.Format(layoutCTime)
}

// formatDate 把 C 风格日期格式串（date +%Y-%m-%d）转成实际输出。
func formatDate(now time.Time, format string) string {
	var sb strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			sb.WriteByte(format[i])
			continue
		}
		i++
		switch format[i] {
		case 'Y':
			sb.WriteString(now.Format("2006"))
		case 'y':
			sb.WriteString(now.Format("06"))
		case 'm':
			sb.WriteString(now.Format("01"))
		case 'd':
			sb.WriteString(now.Format("02"))
		case 'e':
			sb.WriteString(now.Format("_2"))
		case 'H':
			sb.WriteString(now.Format("15"))
		case 'M':
			sb.WriteString(now.Format("04"))
		case 'S':
			sb.WriteString(now.Format("05"))
		case 'j':
			sb.WriteString(now.Format("002"))
		case 'A':
			sb.WriteString(now.Format("Monday"))
		case 'a':
			sb.WriteString(now.Format("Mon"))
		case 'B':
			sb.WriteString(now.Format("January"))
		case 'b':
			sb.WriteString(now.Format("Jan"))
		case 'F':
			sb.WriteString(now.Format("2006-01-02"))
		case 'T':
			sb.WriteString(now.Format("15:04:05"))
		case 's':
			sb.WriteString(strconv.FormatInt(now.Unix(), 10))
		case 'z':
			sb.WriteString(now.Format("-0700"))
		case 'Z':
			sb.WriteString(now.Format("MST"))
		case 'N':
			sb.WriteString(now.Format(".000000000"))
		case '%':
			sb.WriteByte('%')
		default:
			sb.WriteByte('%')
			sb.WriteByte(format[i])
		}
	}
	return sb.String()
}

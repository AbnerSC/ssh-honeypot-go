// Package cmd 伪 Shell 命令解释器：接收攻击者输入的一行命令，返回以假乱真的输出；
// 所有危险行为仅记录不执行。
//
// 命令族按文件拆分（cmd_fs.go / cmd_sys.go / cmd_net.go / cmd_dev.go / cmd_pkg.go /
// cmd_misc.go），本文件只负责输入预处理与路由，与 Java 版 CommandProcessor 的分层一致。
package cmd

import (
	"strconv"
	"strings"

	"ssh-honeypot-go/internal/attacklog"
	"ssh-honeypot-go/internal/fakeenv"
	"ssh-honeypot-go/internal/shell"
)

// seqSeparators 命令序列分隔符（; 、&& 与 ||）。
//
// `||` 与 `;` 同样归一为命令序列：蜜罐不区分退出码，依次执行比把 "||" 当参数
// 传给命令更接近真实行为（`ls /nope || echo hi` 不会出现 "ls: cannot access '||'"）。
var seqSeparators = strings.NewReplacer("&&", "\x00", "||", "\x00", ";", "\x00")

// Processor 伪 Shell 命令解释器。
type Processor struct {
	events   *attacklog.Logger
	hostname string
	// ai 大模型命令仿真客户端，nil 表示未启用（未知命令回退 command not found）。
	ai AIClient
	// latency 是否模拟命令执行耗时；单元测试可关闭以加快速度。
	latency bool
}

// New 构造命令解释器。events 可为 nil（单元测试）。
func New(events *attacklog.Logger, hostname string) *Processor {
	return &Processor{events: events, hostname: hostname, latency: true}
}

// Execute 执行一行输入（可能包含 ;、&&、| 等组合），返回输出。
func (p *Processor) Execute(st *shell.Session, line string) shell.Output {
	line = strings.TrimSpace(line)
	if line == "" {
		return shell.Output{}
	}
	st.AppendHistory(line)
	if p.events != nil {
		p.events.Command(st.ID, st.IP, st.Username, line)
	}

	var out strings.Builder
	// 先按 ; / && / || 拆分成命令序列（蜜罐场景下足够）
	for _, segment := range splitNul(seqSeparators.Replace(line)) {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		res := p.runPipeline(st, segment)
		if res.Exit {
			return shell.Output{Exit: true}
		}
		if res.NoNewline {
			out.WriteString(res.Text)
			continue
		}
		if res.Text == "" {
			continue
		}
		out.WriteString(res.Text)
		if !strings.HasSuffix(res.Text, "\n") {
			out.WriteByte('\n')
		}
	}
	return shell.Output{Text: out.String()}
}

// runPipeline 执行一段管道：左侧命令的输出作为右侧过滤器的标准输入。
//
// 下游是未知命令（或需要真实程序的过滤器）时保留上游输出，与旧的「忽略管道后续」
// 行为一致，避免直接回空串而穿帮。
func (p *Processor) runPipeline(st *shell.Session, segment string) shell.Output {
	stages := splitPipeline(segment)
	// 管道里的 ls 按非终端语义一行一个名字（真实 ls 检测到 stdout 非 tty 也会这样）
	res := p.runSingle(st, stages[0], len(stages) > 1)
	if len(stages) == 1 || res.Exit {
		return res
	}
	text := res.Text
	for i, stage := range stages[1:] {
		next, ok := p.applyFilter(st, stage, text)
		if !ok {
			if i == 0 {
				return res
			}
			break
		}
		text = next
	}
	return shell.Output{Text: text}
}

// runSingle 执行单条命令（已拆分序列与管道）。piped 表示 stdout 接入管道。
func (p *Processor) runSingle(st *shell.Session, cmd string, piped bool) shell.Output {
	// 重定向：> / >> 写文件，2> 属于 stderr 只剥离，>/dev/null 丢弃输出
	red := splitRedirects(cmd)
	if strings.TrimSpace(red.rest) != "" {
		cmd = strings.TrimSpace(red.rest)
	}

	// 变量展开只作用于分词：dispatch 仍拿原始命令文本（AI 提示词更接近用户输入）
	tokens := tokenize(expandVars(st, p.hostname, cmd))
	if len(tokens) == 0 {
		return shell.Output{}
	}
	name := tokens[0]
	args := tokens[1:]

	// sudo 前缀：剥掉继续执行
	if name == "sudo" {
		if len(args) == 0 {
			return shell.Output{Text: "usage: sudo command ..."}
		}
		if p.events != nil {
			p.events.Command(st.ID, st.IP, st.Username, "[sudo] "+strings.Join(args, " "))
		}
		return p.runSingle(st, strings.Join(args, " "), piped)
	}

	// 模拟命令执行耗时，让响应节奏接近真实主机，降低被识破的概率
	p.simulateLatency(name, args)

	res := p.dispatch(st, name, args, cmd, piped)
	if res.Exit {
		return res
	}
	if red.stderrDrop {
		res.Text = dropStderr(name, res.Text)
	}
	if red.drop {
		return shell.Output{}
	}
	if red.file != "" {
		text := res.Text
		if !res.NoNewline && text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		p.writeRedirect(st, red.file, text, red.append)
		return shell.Output{}
	}
	return res
}

// dispatch 命令路由：本地能伪造的命令走本地实现，其余按「已安装」语义交 AI 回退。
func (p *Processor) dispatch(st *shell.Session, name string, args []string, cmdline string, piped bool) shell.Output {
	switch name {
	case "exit", "logout", "quit":
		return exitOutput()

		// 文件系统
	case "help":
		return text(helpText)
	case "pwd":
		return text(st.Cwd)
	case "cd":
		return text(p.cd(st, args))
	case "ls", "dir", "ll":
		return text(p.ls(st, args, piped))
	case "cat", "more", "less":
		return text(p.cat(st, args))
	case "head":
		return text(p.headTail(st, args, false))
	case "tail":
		return text(p.headTail(st, args, true))
	case "wc":
		return text(p.wc(st, args))
	case "touch":
		return text(p.touch(st, args))
	case "mkdir":
		return text(p.mkdir(st, args))
	case "rm", "rmdir":
		return text(p.rm(st, args))
	case "cp":
		return text(p.cp(st, args))
	case "mv":
		return text(p.mv(st, args))
	case "chmod":
		return text(p.chmod(st, args))
	case "chown", "chgrp":
		return text(p.chown(st, args))
	case "ln":
		return text(p.ln(st, args))
	case "stat":
		return text(p.stat(st, args))
	case "du":
		return text(p.du(st, args))
	case "grep", "egrep", "fgrep", "zgrep":
		return text(p.grep(st, args))
	case "find":
		return text(p.find(st, args))
	case "file":
		return text(p.fileCmd(st, args))
	case "realpath", "dirname", "basename", "readlink":
		return text(p.pathCmd(st, name, args))
	case "mktemp":
		return text(p.mktemp(st, args))
	case "cmp":
		return text(p.aiFallbackSilent(st, cmdline))
	case "sort", "uniq", "cut", "tr", "tee", "paste", "nl", "column", "expand":
		return text("") // 文本过滤器：成功时本无输出

		// 系统信息
	case "echo":
		return p.echo(args)
	case "whoami":
		return text(p.whoami(st))
	case "id":
		return text(p.id(st))
	case "groups":
		return text(p.groups(st))
	case "uname":
		return text(p.uname(args))
	case "hostname", "hostnamectl":
		return text(p.hostnameCmd(args))
	case "who", "w":
		return text(p.w(st))
	case "last":
		return text("root     pts/0        203.0.113.44     Mon Aug 11 06:25   still logged in")
	case "uptime":
		return text(p.uptime())
	case "ps":
		return text(p.ps(args))
	case "top", "htop":
		return text(p.top())
	case "history":
		return text(p.history(st))
	case "env", "printenv", "set", "export":
		return text(p.env(st))
	case "date":
		return text(p.dateCmd(args))
	case "df":
		return text(p.df(args))
	case "free":
		return text(p.free(args))
	case "vmstat":
		return text(vmstatText)
	case "iostat":
		return text(p.iostat())
	case "clear":
		return text("\x1b[H\x1b[2J\x1b[3J")
	case "nproc":
		return text(strconv.Itoa(fakeenv.CPUCount))
	case "lscpu":
		return text(p.lscpu())
	case "lsmem":
		return text(lsmemText)
	case "lspci":
		return text(lspciText)
	case "lsmod":
		return text(lsmodText)
	case "lsusb":
		return text(p.aiFallbackSilent(st, cmdline)) // 设备列表输出交 AI 仿真
	case "modprobe", "swapoff", "sync", "yes", "watch", "timeout", "parallel", "visudo", "xargs":
		return text("")
	case "tty":
		return text("/dev/pts/0")
	case "stty":
		return text("")
	case "reset":
		return text("\x1bc")
	case "true", "false", "sleep", "test", "[":
		return text("")
	case "dmesg":
		return text("dmesg: read kernel buffer failed: Operation not permitted")
	case "fsck":
		return text(fsckText)
	case "swapon":
		return text(swaponText)
	case "at":
		return text("at: can't open /var/run/atd.pid")
	case "busybox":
		return text("BusyBox " + fakeenv.Busybox + " (Ubuntu 1:1.35.0-17ubuntu1) multi-call binary.")
	case "strace", "ltrace":
		return text(p.strace(args))
	case "ldd":
		return text(p.ldd(args))
	case "seq":
		return text(p.seqCmd(args))
	case "dd":
		return text(p.dd(st, args))

		// 网络
	case "ifconfig":
		return text(p.ifconfig())
	case "ip":
		return text(p.ipCmd(st, cmdline, args))
	case "netstat", "ss":
		return text(netstatText)
	case "ping", "ping6":
		return text(p.ping(args))
	case "traceroute", "tracepath", "mtr":
		return text(p.traceroute(args))
	case "dig":
		return text(p.dig(args))
	case "nslookup", "host":
		return text(p.nslookup(args))
	case "arp":
		return text(arpText)
	case "route":
		return text(routeText)
	case "wget":
		return text(p.download(st, args, false))
	case "curl":
		return text(p.download(st, args, true))
	case "ssh", "scp", "sftp", "ftp", "telnet":
		return text(p.remoteTimeout(name, args))
	case "nc", "ncat", "netcat", "socat":
		return text("") // 反弹 shell：静默挂起，仅记录命令
	case "iptables":
		return text(p.iptables(args))
	case "ufw":
		return text(p.ufw(st, cmdline, args))
	case "firewall-cmd":
		return text("success")

		// 进程与权限
	case "kill", "killall", "pkill":
		return text(p.kill(args))
	case "su":
		return text(p.su(st, args))
	case "sudo":
		return text("") // 入口已递归剥离，此处兼容 sudo -i 等重复命中
	case "passwd":
		return text(passwdError)
	case "chpasswd":
		return text("")
	case "adduser", "useradd":
		return text(p.useradd(st, args))
	case "usermod", "deluser", "userdel":
		return text("")
	case "getent":
		return text(p.getent(st, cmdline, args))
	case "which", "whereis":
		return text(p.which(args))
	case "type":
		return text(p.typeCmd(args))
	case "command", "hash", "unalias":
		return text("")
	case "alias":
		return text(p.aliasCmd(args))
	case "man":
		// 与 Java 版一致：取首个参数（含 -k 等选项）
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		return text("No manual entry for " + name)

		// 包管理与服务
	case "apt", "apt-get", "aptitude":
		return text(p.apt(args))
	case "yum", "dnf":
		return text(p.yum(args))
	case "dpkg", "rpm":
		return text(p.dpkg(args))
	case "snap", "flatpak":
		return text(p.aiFallbackSilent(st, cmdline))
	case "systemctl":
		return text(p.systemctl(st, args))
	case "service":
		return text(p.service(args))
	case "journalctl":
		return text(p.journalctl())
	case "crontab":
		return text(p.crontab(st, cmdline, args))
	case "tar":
		return text(p.tar(st, args))
	case "gzip", "gunzip", "bzip2", "xz":
		return text("")
	case "unzip":
		return text(p.unzip(st, args))
	case "zip", "rsync":
		return text(p.aiFallbackSilent(st, cmdline))
	case "mount":
		return text(mountText)
	case "umount":
		return text("umount: " + lastArg(args, "") + ": not mounted.")
	case "lsblk":
		return text(lsblkText)
	case "fdisk", "parted":
		return text(fdiskText)
	case "lsof":
		return text(lsofText)
	case "reboot", "shutdown", "halt", "poweroff":
		p.logCommand(st, "[危险操作] "+name)
		return exitOutput() // 模拟系统重启导致连接断开
	case "init":
		return p.initCmd(st, args)

		// 开发工具链
	case "python", "python3":
		return text(p.python(st, cmdline, args))
	case "perl", "php", "ruby", "lua", "node":
		return text(p.interpreter(st, cmdline, name, args))
	case "gcc", "cc", "g++", "make", "cmake", "go", "cargo", "rustc",
		"pip", "pip3", "npm", "yarn", "mvn", "gradle", "composer", "gem", "javac", "git":
		return text(p.devToolOrAi(st, cmdline, name, args))
	case "java":
		return text(p.javaCmd(st, cmdline, args))
	case "docker":
		return text(p.docker(st, cmdline, args))
	case "kubectl":
		return text(p.kubectl(st, cmdline, args))
	case "mysql", "mariadb":
		if v, ok := devToolVersion(name, args); ok {
			return text(v)
		}
		return text("ERROR 1045 (28000): Access denied for user '" + dbClientArgs(args) + "'@'localhost' (using password: YES)")
	case "psql":
		if v, ok := devToolVersion(name, args); ok {
			return text(v)
		}
		return text("psql: error: connection to server at \"localhost\" (127.0.0.1), port 5432 failed: Connection refused")
	case "redis-cli":
		if v, ok := devToolVersion(name, args); ok {
			return text(v)
		}
		return text("Could not connect to Redis at 127.0.0.1:6379: Connection refused")
	case "sqlite3":
		if v, ok := devToolVersion(name, args); ok {
			return text(v)
		}
		if len(args) == 0 {
			return text("") // 无参进交互：静默挂起
		}
		return text(p.aiFallbackSilent(st, cmdline))
	case "lsb_release":
		return text(p.lsbRelease(st, cmdline, args))
	case "neofetch":
		return text(p.neofetch())
	case "base64":
		return text(p.base64Cmd(st, args))
	case "md5sum", "sha1sum", "sha256sum", "sha512sum":
		return text(p.sumCmd(st, name, args))
	case "openssl":
		return text(p.openssl(st, cmdline, args))

		// 解释器/编辑器：交互式挂起或交 AI
	case "bash", "sh", "zsh", "dash", "ksh", "screen", "tmux",
		"vi", "vim", "nano", "emacs", "ed",
		"exec", "nohup", "disown", "bg", "fg", "jobs":
		return text("")
	case "awk", "sed", "diff", "locate", "finger", "fortune", "cowsay", "sl",
		"mkfs", "mkswap", "pkexec", "chroot", "gdb", "objdump", "strings", "readelf",
		"bc", "dc", "expr", "od", "xxd", "hexdump", "iconv", "dos2unix", "unix2dos",
		"source", ".", "eval":
		return text(p.aiFallbackSilent(st, cmdline))
	}
	return text(p.aiFallback(st, cmdline, name))
}

// writeRedirect 把输出写入虚拟文件（> 覆盖，>> 追加），路径不可写或超出容量上限时
// 只留下一行取证日志：攻击者持续写入不可能无限占内存。
func (p *Processor) writeRedirect(st *shell.Session, path, text string, appendMode bool) {
	ok := false
	if appendMode {
		// 必须走 Append：先读全文再覆盖写会让 `cat f >> f` 指数放大
		ok = st.FS.Append(st.Cwd, path, st.Username, text)
	} else {
		ok = st.FS.Write(st.Cwd, path, st.Username, text)
	}
	if !ok {
		// 写失败时攻击者看不到内容，仅留日志便于取证
		if p.events != nil {
			p.events.Command(st.ID, st.IP, st.Username, "[重定向失败] "+path)
		}
	}
}

// commandNotFound 未知命令的 bash 报错（与 Java 版逐字一致）。
func commandNotFound(name string) string {
	return "-bash: " + name + ": command not found"
}

// splitNul 按 \x00 切分（seqSeparators 已把 ; 与 && 归一为 NUL）。
func splitNul(s string) []string {
	return strings.Split(s, "\x00")
}

// tokenize 简单分词：支持单双引号。
func tokenize(cmd string) []string {
	tokens := make([]string, 0, 8)
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// expandVars 展开环境变量：$VAR 与 ${VAR}，单引号内不展开、双引号内展开，
// 与 bash 一致（`echo '$HOME'` 输出字面量，`echo "$HOME"` 输出路径）。
func expandVars(st *shell.Session, hostname, cmd string) string {
	if !strings.ContainsRune(cmd, '$') {
		return cmd
	}
	var sb strings.Builder
	sb.Grow(len(cmd) + 16)
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote == '\'' {
			sb.WriteByte(c)
			if c == '\'' {
				quote = 0
			}
			continue
		}
		switch {
		case c == '\'':
			quote = '\''
			sb.WriteByte(c)
		case c == '"':
			if quote == '"' {
				quote = 0
			} else {
				quote = '"'
			}
			sb.WriteByte(c)
		case c == '\\' && i+1 < len(cmd):
			sb.WriteByte(c)
			i++
			sb.WriteByte(cmd[i])
		case c == '$':
			name, n := scanVarName(cmd[i:])
			if name == "" {
				sb.WriteByte(c)
				continue
			}
			sb.WriteString(lookupVar(st, hostname, name))
			i += n - 1
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// scanVarName 解析 $ 开头的变量名，返回名字与消耗的字节数；不认识的写法返回空。
func scanVarName(s string) (string, int) {
	if len(s) < 2 || s[0] != '$' {
		return "", 0
	}
	if s[1] == '{' {
		end := strings.IndexByte(s[2:], '}')
		if end < 0 {
			return "", 0
		}
		name := s[2 : 2+end]
		// ${VAR:-default} 这类参数展开不处理，保留原文以免输出意外内容
		if name == "" || strings.ContainsAny(name, ":-=+#%/!?") {
			return "", 0
		}
		return name, 2 + end + 1
	}
	switch c := s[1]; c {
	case '?', '$', '#', '!', '@', '*', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return string(c), 2
	}
	i := 1
	for i < len(s) && isVarChar(s[i]) {
		i++
	}
	if i == 1 {
		return "", 0
	}
	return s[1:i], i
}

// isVarChar 变量名字符：字母、数字、下划线。
func isVarChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// lookupVar 内置环境变量取值，与 env 命令的输出口径一致；未定义变量按 bash 语义展开为空串。
func lookupVar(st *shell.Session, hostname, name string) string {
	uid := "1000"
	if st.Username == "root" {
		uid = "0"
	}
	switch name {
	case "HOME":
		return st.HomeDir
	case "USER", "LOGNAME":
		return st.Username
	case "SHELL":
		return "/bin/bash"
	case "PATH":
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "PWD":
		return st.Cwd
	case "OLDPWD":
		return st.HomeDir
	case "HOSTNAME":
		return hostname
	case "TERM":
		return "xterm"
	case "LANG":
		return "en_US.UTF-8"
	case "UID", "EUID":
		return uid
	case "PPID", "SHLVL":
		return "1"
	case "HOSTTYPE":
		return "x86_64"
	case "MACHTYPE":
		return "x86_64-pc-linux-gnu"
	case "OSTYPE":
		return "linux-gnu"
	case "?":
		return "0"
	case "$":
		return "21873"
	case "#":
		return "0"
	case "0":
		return "-bash"
	}
	return ""
}

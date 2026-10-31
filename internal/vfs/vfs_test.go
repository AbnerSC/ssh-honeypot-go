package vfs

import (
	"strconv"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	fs := New("svr01")
	cases := []struct{ cwd, path, want string }{
		{"/root", "", "/root"},
		{"/root", ".", "/root"},
		{"/root", "..", "/"},
		{"/root", "../etc", "/etc"},
		{"/root", "/etc/ssh/..", "/etc"},
		{"/root", "a/./b//c", "/root/a/b/c"},
		{"/home/admin", "../../..", "/"},
		{"/", "/", "/"},
	}
	for _, c := range cases {
		if got := fs.Normalize(c.cwd, c.path); got != c.want {
			t.Errorf("Normalize(%q,%q)=%q, want %q", c.cwd, c.path, got, c.want)
		}
	}
}

func TestResolveFixedTree(t *testing.T) {
	fs := New("svr01")
	if n := fs.Resolve("/root", "/etc/passwd"); n == nil || n.Dir {
		t.Fatal("/etc/passwd 应存在且为文件")
	}
	if n := fs.Resolve("/root", "../etc"); n == nil || !n.Dir {
		t.Fatal("/etc 应存在且为目录")
	}
	if n := fs.Resolve("/", "/nope"); n != nil {
		t.Fatal("不存在的路径应返回 nil")
	}
	// 诱饵文件内容与主机名同源
	host, ok := fs.ReadFile("/", "/etc/hostname")
	if !ok || host != "svr01\n" {
		t.Fatalf("/etc/hostname=%q, ok=%v", host, ok)
	}
	passwd, ok := fs.ReadFile("/", "/etc/passwd")
	if !ok || !strings.Contains(passwd, "admin:x:1000:1000") {
		t.Fatalf("/etc/passwd 内容不符合预期: %q", passwd)
	}
}

func TestEnsureHome(t *testing.T) {
	fs := New("svr01")
	if n := fs.EnsureHome("root"); n != nil {
		t.Fatal("root 不应创建 /home/root")
	}
	home := fs.EnsureHome("ubuntu")
	if home == nil || !home.Dir {
		t.Fatal("应创建 /home/ubuntu")
	}
	if got := fs.Resolve("/", "/home/ubuntu"); got != home {
		t.Fatal("/home/ubuntu 应可解析到同一节点")
	}
	// 重复调用幂等
	if again := fs.EnsureHome("ubuntu"); again != home {
		t.Fatal("重复 EnsureHome 不应重建目录")
	}
}

func TestFileOperations(t *testing.T) {
	fs := New("svr01")

	if !fs.Touch("/root", "a.txt", "root") {
		t.Fatal("touch 应成功")
	}
	if fs.Touch("/root", "a.txt", "root") {
		t.Fatal("同名文件已存在时 touch 应失败")
	}
	if !fs.Write("/root", "a.txt", "root", "hello") {
		t.Fatal("write 应覆盖已有文件")
	}
	if got, _ := fs.ReadFile("/root", "a.txt"); got != "hello" {
		t.Fatalf("内容=%q", got)
	}
	if !fs.Mkdir("/root", "sub", "root") {
		t.Fatal("mkdir 应成功")
	}
	if !fs.Move("/root", "a.txt", "sub/b.txt") {
		t.Fatal("mv 到子目录应成功")
	}
	if _, ok := fs.ReadFile("/root", "a.txt"); ok {
		t.Fatal("mv 后原路径应不存在")
	}
	if got, _ := fs.ReadFile("/root", "sub/b.txt"); got != "hello" {
		t.Fatalf("mv 后内容=%q", got)
	}
	if !fs.Copy("/root", "sub/b.txt", "c.txt") {
		t.Fatal("cp 应成功")
	}
	if !fs.Write("/root", "c.txt", "root", "changed") {
		t.Fatal("覆盖 c.txt 失败")
	}
	if !fs.Write("/root", "sub/b.txt", "root", "hello") {
		t.Fatal("覆盖 sub/b.txt 失败")
	}
	if got, _ := fs.ReadFile("/root", "c.txt"); got != "changed" {
		t.Fatalf("cp 后应为独立副本，实际=%q", got)
	}
	if !fs.Remove("/root", "c.txt") {
		t.Fatal("rm 应成功")
	}
	if _, ok := fs.ReadFile("/root", "c.txt"); ok {
		t.Fatal("rm 后文件应不存在")
	}
	if fs.Remove("/", "/") {
		t.Fatal("不应允许删除根目录")
	}
	if fs.Move("/root", "missing", "x") {
		t.Fatal("mv 不存在的源应失败")
	}
}

func TestCanAccess(t *testing.T) {
	fs := New("svr01")
	shadow := fs.Resolve("/", "/etc/shadow")
	if shadow == nil {
		t.Fatal("/etc/shadow 缺失")
	}
	if !shadow.CanAccess("root", 'r') {
		t.Fatal("root 应无视权限位")
	}
	if shadow.CanAccess("admin", 'r') {
		t.Fatal("other 类用户不应可读 0640 文件")
	}
	passwd := fs.Resolve("/", "/etc/passwd")
	if !passwd.CanAccess("admin", 'r') {
		t.Fatal("other 类用户应可读 0644 文件")
	}
	if passwd.CanAccess("admin", 'w') {
		t.Fatal("other 类用户不应可写 0644 文件")
	}
	adminHome := fs.Resolve("/", "/home/admin")
	if !adminHome.CanAccess("admin", 'r') {
		t.Fatal("属主应可读自己的目录")
	}
}

func TestLsLong(t *testing.T) {
	fs := New("svr01")
	node := fs.Resolve("/", "/etc/passwd")
	line := fs.LsLong(node)
	if !strings.HasPrefix(line, "-rw-r--r--  1 root     root") {
		t.Fatalf("ls -l 行格式不符: %q", line)
	}
	if !strings.HasSuffix(line, " passwd") {
		t.Fatalf("ls -l 行缺少文件名: %q", line)
	}
	dirLine := fs.LsLong(fs.Resolve("/", "/etc"))
	if !strings.HasPrefix(dirLine, "drwxr-xr-x") {
		t.Fatalf("目录行应以 d 开头: %q", dirLine)
	}
	// 链接数 = 2 + 子目录数（/etc 含 ssh 一个子目录）
	if !strings.Contains(dirLine, " 3 ") {
		t.Fatalf("目录链接数应为 3: %q", dirLine)
	}
}

func TestChildrenOf(t *testing.T) {
	fs := New("svr01")
	etc := fs.Resolve("/", "/etc")
	kids := fs.ChildrenOf(etc)
	if len(kids) < 8 {
		t.Fatalf("/etc 子节点过少: %d", len(kids))
	}
	for i := 1; i < len(kids); i++ {
		if kids[i-1].Name >= kids[i].Name {
			t.Fatal("子节点应按名称升序")
		}
	}
	if fs.ChildrenOf(nil) != nil {
		t.Fatal("nil 节点应返回 nil")
	}
}

// TestWriteSizeLimits 写入量必须与攻击者输入解耦：单文件与全库都有硬上限，
// 否则 `seq 1 100000000 > /tmp/a` 一条命令就能把蜜罐内存吃光（OOM 属致命错误，recover 兜不住）。
func TestWriteSizeLimits(t *testing.T) {
	fs := New("svr01")

	// 单文件超过 maxFileBytes：拒绝写入，且原内容保持不变
	if !fs.Write("/root", "a.txt", "root", "seed") {
		t.Fatal("首次写入应成功")
	}
	if fs.Write("/root", "a.txt", "root", strings.Repeat("x", maxFileBytes+1)) {
		t.Fatal("超过单文件上限的写入应被拒绝")
	}
	if got, _ := fs.ReadFile("/root", "a.txt"); got != "seed" {
		t.Fatalf("被拒绝的写入不应改动原内容，当前 %d 字节", len(got))
	}

	// 恰好等于上限应允许，且删除后额度可回收
	if !fs.Write("/root", "big.txt", "root", strings.Repeat("y", maxFileBytes)) {
		t.Fatal("等于单文件上限的写入应成功")
	}
	if !fs.Remove("/root", "big.txt") {
		t.Fatal("删除大文件应成功")
	}

	// 总量超过 maxTotalBytes：逐个写入直到被拒
	chunk := strings.Repeat("z", maxFileBytes)
	attempts := maxTotalBytes/maxFileBytes + 4
	written := 0
	for i := 0; i < attempts; i++ {
		if !fs.Write("/root", "f"+strconv.Itoa(i), "root", chunk) {
			break
		}
		written++
	}
	if written == 0 || written >= attempts {
		t.Fatalf("总量上限未生效：成功写入 %d 次", written)
	}

	// 删除后额度回收，可以继续写入
	if !fs.Remove("/root", "f0") {
		t.Fatal("删除应成功")
	}
	if !fs.Write("/root", "again.txt", "root", chunk) {
		t.Fatal("删除后额度应被回收")
	}
}

// TestAppendSelfLimit `cat f >> f` 必须被容量上限截断，不能指数放大。
func TestAppendSelfLimit(t *testing.T) {
	fs := New("svr01")
	if !fs.Write("/tmp", "f", "root", strings.Repeat("a", 1024)) {
		t.Fatal("准备种子文件失败")
	}

	rejected := false
	for i := 0; i < 40; i++ {
		content, _ := fs.ReadFile("/tmp", "f")
		if !fs.Append("/tmp", "f", "root", content) {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("自我追加 40 次仍未触及上限，说明上限未生效")
	}
	if got, _ := fs.ReadFile("/tmp", "f"); len(got) != maxFileBytes {
		t.Fatalf("文件应在上限处停住，实际 %d 字节，期望 %d", len(got), maxFileBytes)
	}
}

// TestCopyRespectsTotalLimit 深拷贝同样占用总量配额：复制不能绕过写入上限。
func TestCopyRespectsTotalLimit(t *testing.T) {
	fs := New("svr01")
	chunk := strings.Repeat("c", maxFileBytes)
	if !fs.Write("/tmp", "src", "root", chunk) {
		t.Fatal("写入源文件失败")
	}
	copies := 0
	for i := 0; i < maxTotalBytes/maxFileBytes+2; i++ {
		if !fs.Copy("/tmp", "src", "copy"+strconv.Itoa(i)) {
			break
		}
		copies++
	}
	if copies >= maxTotalBytes/maxFileBytes+2 {
		t.Fatalf("复制绕过了总量上限，成功 %d 次", copies)
	}
}

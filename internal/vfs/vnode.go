// Package vfs 内存虚拟文件系统：攻击者看到的全部文件都只存在于内存中，
// 永远不会触碰真实磁盘。
//
// 单个 FS 实例由 main 创建后注入所有协议，保持「跨会话共享同一台机器」的语义；
// 因此所有读写都必须在 FS 的读写锁下进行（Node 自身不加锁）。
package vfs

import (
	"fmt"
	"time"
)

// lsDateLayout `ls -l` 的日期列格式，对应 Java 版的 "MMM dd HH:mm"（ENGLISH）。
const lsDateLayout = "Jan 02 15:04"

// Node 虚拟文件系统节点（文件或目录）。
type Node struct {
	// Name 节点名；根节点为空串。
	Name string
	// Dir 是否为目录。
	Dir bool
	// Owner / Group 属主与属组（本蜜罐中两者相同）。
	Owner string
	Group string
	// Perms 权限位，例如 "rw-r--r--" / "rwxr-xr-x"（不含类型字符）。
	Perms string
	// MTime 修改时间，用于 `ls -l` / `stat` 输出。
	MTime time.Time

	content string
	// sizeHint 空内容时的展示大小：可执行文件伪造为 128 字节（对应 Java 版 content==null 的 128），
	// 避免 `ls -l /bin` 里一片 0 字节而穿帮。
	sizeHint int
	children map[string]*Node
}

// newDir 创建目录节点（mtime 取 30 天前，模拟长期未变的系统目录）。
func newDir(name, perms, owner string) *Node {
	return &Node{
		Name:     name,
		Dir:      true,
		Perms:    perms,
		Owner:    owner,
		Group:    owner,
		MTime:    time.Now().AddDate(0, 0, -30),
		children: make(map[string]*Node),
	}
}

// newFile 创建文件节点（mtime 取 7 天前）。
func newFile(name, perms, owner, content string) *Node {
	return &Node{
		Name:    name,
		Perms:   perms,
		Owner:   owner,
		Group:   owner,
		MTime:   time.Now().AddDate(0, 0, -7),
		content: content,
	}
}

// newExec 创建可执行文件节点（空内容，mtime 取 60 天前）。
func newExec(name, owner string) *Node {
	n := newFile(name, "rwxr-xr-x", owner, "")
	n.MTime = time.Now().AddDate(0, 0, -60)
	n.sizeHint = 128
	return n
}

// Add 挂载子节点并返回自身，便于链式构造。
func (n *Node) Add(child *Node) *Node {
	if n.children == nil {
		n.children = make(map[string]*Node)
	}
	n.children[child.Name] = child
	return n
}

// Child 按名查找直接子节点，不存在返回 nil。
func (n *Node) Child(name string) *Node {
	return n.children[name]
}

// Children 返回子节点表（只读用途）。
//
// 调用方必须持有 FS 的读锁；命令处理器请优先使用 FS.ChildrenOf 获取快照。
func (n *Node) Children() map[string]*Node {
	return n.children
}

// Content 文件内容；目录返回空串。
func (n *Node) Content() string {
	return n.content
}

// Size 文件字节数（UTF-8 字节数）；目录固定 4096。
// 不修改节点，可在读锁下并发调用。
func (n *Node) Size() int {
	if n.Dir {
		return 4096
	}
	if n.content == "" && n.sizeHint > 0 {
		return n.sizeHint
	}
	return len(n.content)
}

// CanAccess 判断 user 对节点是否拥有指定权限位（perm 取 'r'/'w'/'x'）。
// 规则与 Linux 一致：root 绕过权限检查；否则按 owner / group / other 三类判断。
func (n *Node) CanAccess(user string, perm byte) bool {
	if user == "root" {
		return true
	}
	idx := 6 // other
	if user == n.Owner {
		idx = 0
	} else if user == n.Group {
		idx = 3
	}
	offset := 2
	switch perm {
	case 'r':
		offset = 0
	case 'w':
		offset = 1
	}
	return n.Perms[idx+offset] != '-'
}

// LsLong 生成 `ls -l` 单行展示。
func (n *Node) LsLong() string {
	typeChar := "-"
	if n.Dir {
		typeChar = "d"
	}
	links := 1
	if n.Dir {
		sub := 0
		for _, c := range n.children {
			if c.Dir {
				sub++
			}
		}
		links = 2 + sub
	}
	return fmt.Sprintf("%s%s %2d %-8s %-8s %8d %s %s",
		typeChar, n.Perms, links, n.Owner, n.Group, n.Size(),
		n.MTime.Format(lsDateLayout), n.Name)
}

// clone 深拷贝节点（文件复制内容，目录递归复制），newName 为重命名后的名字。
func (n *Node) clone(newName string) *Node {
	if n.Dir {
		cp := newDir(newName, n.Perms, n.Owner)
		for _, c := range n.children {
			cp.Add(c.clone(c.Name))
		}
		return cp
	}
	cp := newFile(newName, n.Perms, n.Owner, n.content)
	cp.sizeHint = n.sizeHint
	cp.MTime = n.MTime
	return cp
}

package shell

import (
	"regexp"
	"strings"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/vfs"
)

// Session 单个攻击会话的状态：登录用户、当前目录、命令历史。
//
// 每个连接一份，互不干扰（文件系统树是共享的，模拟多人攻击同一台机器）。
type Session struct {
	// ID 会话编号，与日志中的 session 字段一致。
	ID string
	// IP 来源 IP，用于日志。
	IP string
	// FS 共享的内存虚拟文件系统。
	FS *vfs.FS
	// Hostname 伪装主机名，用于提示符（如 root@svr01:~#）。
	Hostname string
	// Username 清洗后的登录用户名。
	Username string
	// Cwd 当前工作目录（绝对路径）。
	Cwd string
	// History 已执行的命令，供 history 命令与会话归档使用。
	History []string
	// HomeDir 用户主目录绝对路径，root 为 /root，普通用户为 /home/<username>。
	HomeDir string
}

// userNameCleaner 用户名清洗：仅保留常规 Linux 用户名字符。
var userNameCleaner = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// NewSession 构造会话状态。
//
// 用户名清洗是必需的：攻击者可提交任意字符串作用户名，未清洗的路径分隔符/控制字符
// 会污染提示符与 /home 目录结构。普通用户登录后自动创建 /home/<username>。
func NewSession(sessionID, ip, username string, fs *vfs.FS, hostname string) *Session {
	user := SanitizeUser(username)
	st := &Session{
		ID:       sessionID,
		IP:       ip,
		FS:       fs,
		Hostname: hostname,
		Username: user,
	}
	if user == "root" {
		st.HomeDir = "/root"
	} else {
		st.HomeDir = "/home/" + user
		fs.EnsureHome(user)
	}
	st.Cwd = st.HomeDir
	return st
}

// SanitizeUser 用户名清洗：仅保留常规 Linux 用户名字符，其余替换为下划线；
// 清洗后为空回退 nobody。
func SanitizeUser(name string) string {
	s := strings.TrimSpace(userNameCleaner.ReplaceAllString(name, "_"))
	if s == "" {
		return "nobody"
	}
	return s
}

// Prompt 提示符，如 `root@svr01:~#`、`admin@svr01:/var/www$`。
func (s *Session) Prompt() string {
	dir := s.Cwd
	if dir == s.HomeDir {
		dir = "~"
	} else if len(dir) > len(s.HomeDir) && dir[:len(s.HomeDir)] == s.HomeDir && dir[len(s.HomeDir)] == '/' {
		dir = "~" + dir[len(s.HomeDir):]
	}
	if s.Username == "root" {
		return s.Username + "@" + s.Hostname + ":" + dir + "# "
	}
	return s.Username + "@" + s.Hostname + ":" + dir + "$ "
}

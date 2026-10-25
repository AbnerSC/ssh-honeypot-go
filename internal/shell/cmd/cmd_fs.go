package cmd

import (
	"regexp"
	"strconv"
	"strings"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/shell"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/vfs"
)

// chmodModeOctal / chmodModeSymbolic chmod 模式校验（对应 Java 的两个正则）。
var (
	chmodModeOctal    = regexp.MustCompile(`^[0-7]{3,4}$`)
	chmodModeSymbolic = regexp.MustCompile(`^[ugoa]*[-+=][rwxXst]*$`)
)

// cd 切换目录：校验存在性、目录类型与执行权限。
func (p *Processor) cd(st *shell.Session, args []string) string {
	target := st.HomeDir
	if len(args) > 0 {
		target = args[0]
	}
	if target == "~" {
		target = st.HomeDir
	}
	node := st.FS.Resolve(st.Cwd, target)
	if node == nil {
		return "-bash: cd: " + target + ": No such file or directory"
	}
	if !node.Dir {
		return "-bash: cd: " + target + ": Not a directory"
	}
	if !node.CanAccess(st.Username, 'x') {
		return "-bash: cd: " + target + ": Permission denied"
	}
	st.Cwd = st.FS.Normalize(st.Cwd, target)
	return ""
}

// ls 列出目录内容，支持 -l / -a。
//
// piped 为真时按非终端语义拼接：真实 ls 检测到 stdout 不是 tty 会一行一个名字，
// 否则 `ls | head -3` 永远只能截到同一行（假 shell 的典型破绽）。
func (p *Processor) ls(st *shell.Session, args []string, piped bool) string {
	longFmt := hasShort(args, 'l')
	showAll := hasShort(args, 'a')
	path := firstNonFlag(args)
	if path == "" {
		path = st.Cwd
	}
	node := st.FS.Resolve(st.Cwd, path)
	if node == nil {
		return "ls: cannot access '" + path + "': No such file or directory"
	}
	if !node.Dir {
		if longFmt {
			return st.FS.LsLong(node)
		}
		return node.Name
	}

	children := st.FS.ChildrenOf(node)
	var sb strings.Builder
	if longFmt {
		sb.WriteString("total " + strconv.Itoa(len(children)*4) + "\n")
		if showAll {
			sb.WriteString("drwxr-xr-x  2 root     root     4096 Aug 11 06:25 .\n")
			sb.WriteString("drwxr-xr-x 20 root     root     4096 Aug  4 10:12 ..\n")
		}
		for _, c := range children {
			if showAll || !strings.HasPrefix(c.Name, ".") {
				sb.WriteString(st.FS.LsLong(c))
				sb.WriteByte('\n')
			}
		}
		return stripTrailing(sb.String())
	}

	names := make([]string, 0, len(children))
	for _, c := range children {
		if showAll || !strings.HasPrefix(c.Name, ".") {
			names = append(names, c.Name)
		}
	}
	if piped {
		return strings.Join(names, "\n")
	}
	return strings.Join(names, "  ")
}

// cat 输出文件内容（more/less 复用）。
func (p *Processor) cat(st *shell.Session, args []string) string {
	files := nonFlags(args)
	if len(files) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, f := range files {
		node := st.FS.Resolve(st.Cwd, f)
		if node == nil {
			sb.WriteString("cat: " + f + ": No such file or directory\n")
			continue
		}
		if node.Dir {
			sb.WriteString("cat: " + f + ": Is a directory\n")
			continue
		}
		content, _ := st.FS.ReadFile(st.Cwd, f)
		sb.WriteString(content)
		if !strings.HasSuffix(content, "\n") {
			sb.WriteByte('\n')
		}
	}
	return stripTrailing(sb.String())
}

// headTail head/tail：支持 -n N 与 -N，默认 10 行。
func (p *Processor) headTail(st *shell.Session, args []string, isTail bool) string {
	n := 10
	files := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			files = append(files, a)
			continue
		}
		if (a == "-n" || a == "--lines") && i+1 < len(args) {
			i++
			if v, err := strconv.Atoi(args[i]); err == nil && v >= 0 {
				n = v
			}
			continue
		}
		num := strings.TrimPrefix(strings.TrimPrefix(a, "-n"), "-")
		if num != "" && isAllDigits(num) {
			if v, err := strconv.Atoi(num); err == nil {
				n = v
			}
		}
	}
	if len(files) == 0 {
		return ""
	}

	cmdName := "head"
	if isTail {
		cmdName = "tail"
	}
	var sb strings.Builder
	for _, f := range files {
		node := st.FS.Resolve(st.Cwd, f)
		if node == nil {
			sb.WriteString(cmdName + ": cannot open '" + f + "' for reading: No such file or directory\n")
			continue
		}
		if node.Dir {
			sb.WriteString(cmdName + ": cannot open '" + f + "' for reading: Is a directory\n")
			continue
		}
		content, _ := st.FS.ReadFile(st.Cwd, f)
		lines := splitLines(content)
		pick := make([]string, 0, n)
		for i := 0; i < len(lines); i++ {
			keep := i < n
			if isTail {
				keep = i >= len(lines)-n
			}
			if keep && lines[i] != "" {
				pick = append(pick, lines[i])
			}
		}
		sb.WriteString(strings.Join(pick, "\n"))
		if len(pick) > 0 {
			sb.WriteByte('\n')
		}
	}
	return stripTrailing(sb.String())
}

// isAllDigits 判断是否为纯数字串。
func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// wc 统计行数/单词数/字节数；与 GNU wc 一致：无选项输出三列，指定 -l/-w/-c/-m 时只输出对应列。
func (p *Processor) wc(st *shell.Session, args []string) string {
	files := nonFlags(args)
	if len(files) == 0 {
		return "0 0 0"
	}
	var sb strings.Builder
	var total [4]int
	shown := 0
	for _, f := range files {
		node := st.FS.Resolve(st.Cwd, f)
		content, ok := st.FS.ReadFile(st.Cwd, f)
		if node == nil || node.Dir || !ok {
			sb.WriteString("wc: " + f + ": No such file or directory\n")
			continue
		}
		counts := wcCounts(content)
		for i := range total {
			total[i] += counts[i]
		}
		sb.WriteString(wcValues(counts, args) + " " + f + "\n")
		shown++
	}
	if shown > 1 { // 多文件时 GNU wc 额外输出 total 行
		sb.WriteString(wcValues(total, args) + " total\n")
	}
	return stripTrailing(sb.String())
}

// padLeft 右对齐到 7 位（wc 的 %7d）。
func padLeft(n int) string {
	return padLeftStr(strconv.Itoa(n))
}

// stat 展示文件元信息。
func (p *Processor) stat(st *shell.Session, args []string) string {
	files := nonFlags(args)
	if len(files) == 0 {
		return "stat: missing operand"
	}
	f := files[0]
	node := st.FS.Resolve(st.Cwd, f)
	if node == nil {
		return "stat: cannot statx '" + f + "': No such file or directory"
	}
	abs := st.FS.Normalize(st.Cwd, f)
	size := node.Size()
	kind, access := "regular file", "0644/-rw-r--r--"
	if node.Dir {
		kind, access = "directory", "0755/drwxr-xr-x"
	}
	mtime := node.MTime.Format(layoutStatTime)
	return "  File: " + f + "\n" +
		"  Size: " + strconv.Itoa(size) + "       \tBlocks: " + strconv.Itoa(size/512+8) + "    IO Block: 4096   " + kind + "\n" +
		"Access: (" + access + ")  Uid: (" + uidOf(node.Owner) + "/" + node.Owner + ")   Gid: (" + uidOf(node.Group) + "/" + node.Group + ")\n" +
		"Access: " + mtime + "\nModify: " + mtime + "\nChange: " + mtime +
		"\n Birth: " + mtime + "  (path=" + abs + ")"
}

// uidOf 属主名转 uid 展示（root 为 0，其余按普通用户 1000）。
func uidOf(name string) string {
	if name == "root" {
		return "0"
	}
	return "1000"
}

// du 统计目录占用。
func (p *Processor) du(st *shell.Session, args []string) string {
	path := firstNonFlag(args)
	if path == "" {
		path = "."
	}
	node := st.FS.Resolve(st.Cwd, path)
	if node == nil {
		return "du: cannot access '" + path + "': No such file or directory"
	}
	human := hasShort(args, 'h')
	var sb strings.Builder
	duWalk(st.FS, st.FS.Normalize(st.Cwd, path), node, human, &sb)
	return stripTrailing(sb.String())
}

// duWalk 递归输出各层目录占用（与 Java 版一致：每个子节点固定累加 4KB）。
func duWalk(fs *vfs.FS, path string, node *vfs.Node, human bool, sb *strings.Builder) {
	kb := int64(4)
	if !node.Dir {
		kb = int64(node.Size() / 1024)
		if kb < 1 {
			kb = 1
		}
	} else {
		for _, c := range fs.ChildrenOf(node) {
			childPath := path + "/" + c.Name
			if path == "/" {
				childPath = "/" + c.Name
			}
			duWalk(fs, childPath, c, human, sb)
			kb += 4
		}
	}
	size := strconv.FormatInt(kb, 10)
	if human {
		size = humanSize(kb * 1024)
	}
	shown := path
	if shown == "" {
		shown = "/"
	}
	sb.WriteString(size + "\t" + shown + "\n")
}

// touch 创建空文件（已存在则保持原样，与 Java 版一致返回失败）。
func (p *Processor) touch(st *shell.Session, args []string) string {
	for _, f := range args {
		if strings.HasPrefix(f, "-") {
			continue
		}
		if st.FS.Resolve(st.Cwd, f) != nil {
			continue // 已存在：更新时间戳，无需返回错误
		}
		if !st.FS.Touch(st.Cwd, f, st.Username) {
			return "touch: cannot touch '" + f + "': No such file or directory"
		}
	}
	return ""
}

// mkdir 创建目录，支持 -p。
func (p *Processor) mkdir(st *shell.Session, args []string) string {
	parents := hasShort(args, 'p')
	for _, f := range args {
		if strings.HasPrefix(f, "-") {
			continue
		}
		existing := st.FS.Resolve(st.Cwd, f)
		if existing != nil {
			if parents && existing.Dir {
				continue // mkdir -p 对已存在目录静默成功
			}
			return "mkdir: cannot create directory '" + f + "': File exists"
		}
		var ok bool
		if parents {
			ok = mkdirs(st, f)
		} else {
			ok = st.FS.Mkdir(st.Cwd, f, st.Username)
		}
		if !ok {
			return "mkdir: cannot create directory '" + f + "': No such file or directory"
		}
	}
	return ""
}

// mkdirs mkdir -p：逐级创建缺失的中间目录。
func mkdirs(st *shell.Session, path string) bool {
	abs := st.FS.Normalize(st.Cwd, path)
	cur := ""
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if part == "" {
			continue
		}
		cur += "/" + part
		node := st.FS.Resolve("/", cur)
		if node == nil {
			if !st.FS.Mkdir("/", cur, st.Username) {
				return false
			}
		} else if !node.Dir {
			return false
		}
	}
	return true
}

// rm 删除文件/目录（-r 递归），危险路径仅记录不执行。
func (p *Processor) rm(st *shell.Session, args []string) string {
	files := nonFlags(args)
	recursive := hasShort(args, 'r')
	if len(files) == 0 {
		return "rm: missing operand"
	}
	for _, f := range files {
		switch f {
		case "/", "/*", "~/*", "*":
			p.logCommand(st, "[危险操作] rm "+strings.Join(args, " "))
			continue // 假装成功，实际不动
		}
		node := st.FS.Resolve(st.Cwd, f)
		if node != nil && node.Dir && !recursive {
			return "rm: cannot remove '" + f + "': Is a directory"
		}
		if !st.FS.Remove(st.Cwd, f) {
			return "rm: cannot remove '" + f + "': No such file or directory"
		}
	}
	return ""
}

// cp 复制文件或目录。
func (p *Processor) cp(st *shell.Session, args []string) string {
	operands := nonFlags(args)
	if len(operands) < 2 {
		first := ""
		if len(operands) > 0 {
			first = operands[0]
		}
		return "cp: missing destination file operand after '" + first + "'"
	}
	src, dst := operands[len(operands)-2], operands[len(operands)-1]
	srcNode := st.FS.Resolve(st.Cwd, src)
	if srcNode == nil {
		return "cp: cannot stat '" + src + "': No such file or directory"
	}
	if srcNode.Dir && !hasShort(args, 'r') && !hasShort(args, 'R') && !hasShort(args, 'a') {
		return "cp: -r not specified; omitting directory '" + src + "'"
	}
	if !st.FS.Copy(st.Cwd, src, dst) {
		return "cp: cannot copy '" + src + "' to '" + dst + "'"
	}
	return ""
}

// mv 移动或重命名。
func (p *Processor) mv(st *shell.Session, args []string) string {
	operands := nonFlags(args)
	if len(operands) < 2 {
		first := ""
		if len(operands) > 0 {
			first = operands[0]
		}
		return "mv: missing destination file operand after '" + first + "'"
	}
	src, dst := operands[len(operands)-2], operands[len(operands)-1]
	if st.FS.Resolve(st.Cwd, src) == nil {
		return "mv: cannot stat '" + src + "': No such file or directory"
	}
	if !st.FS.Move(st.Cwd, src, dst) {
		return "mv: cannot move '" + src + "' to '" + dst + "'"
	}
	return ""
}

// chmod 修改权限：仅校验模式与目标存在性，不真正改变权限位。
func (p *Processor) chmod(st *shell.Session, args []string) string {
	operands := nonFlags(args)
	if len(operands) < 2 {
		return "chmod: missing operand"
	}
	mode := operands[0]
	if !chmodModeOctal.MatchString(mode) && !chmodModeSymbolic.MatchString(mode) {
		return "chmod: invalid mode: '" + mode + "'"
	}
	for _, f := range operands[1:] {
		if st.FS.Resolve(st.Cwd, f) == nil {
			return "chmod: cannot access '" + f + "': No such file or directory"
		}
	}
	return ""
}

// chown chgrp 修改属主：仅校验目标存在性。
func (p *Processor) chown(st *shell.Session, args []string) string {
	operands := nonFlags(args)
	if len(operands) < 2 {
		return "chown: missing operand"
	}
	for _, f := range operands[1:] {
		if st.FS.Resolve(st.Cwd, f) == nil {
			return "chown: cannot access '" + f + "': No such file or directory"
		}
	}
	return ""
}

// ln 创建链接：仅校验源存在性。
func (p *Processor) ln(st *shell.Session, args []string) string {
	operands := nonFlags(args)
	if len(operands) < 2 {
		return "ln: missing file operand"
	}
	if st.FS.Resolve(st.Cwd, operands[0]) == nil {
		return "ln: failed to create symbolic link '" + operands[len(operands)-1] + "': No such file or directory"
	}
	return ""
}

// grep 按子串匹配文件内容（支持 -v / -c）。
func (p *Processor) grep(st *shell.Session, args []string) string {
	operands := nonFlags(args)
	if len(operands) == 0 {
		return "Usage: grep [OPTION]... PATTERNS [FILE]..."
	}
	pattern := operands[0]
	if len(operands) < 2 {
		return "" // 从 stdin 读，蜜罐里没有
	}
	invert := hasArg(args, "-v") || hasArg(args, "--invert-match")
	count := hasArg(args, "-c") || hasArg(args, "--count")
	multi := len(operands) > 2

	var sb strings.Builder
	for _, f := range operands[1:] {
		node := st.FS.Resolve(st.Cwd, f)
		if node == nil {
			sb.WriteString("grep: " + f + ": No such file or directory\n")
			continue
		}
		if node.Dir {
			sb.WriteString("grep: " + f + ": Is a directory\n")
			continue
		}
		content, _ := st.FS.ReadFile(st.Cwd, f)
		matched := make([]string, 0, 8)
		for _, line := range splitLines(content) {
			hit := strings.Contains(line, pattern)
			if hit != invert && line != "" {
				matched = append(matched, line)
			}
		}
		prefix := ""
		if multi {
			prefix = f + ":"
		}
		if count {
			sb.WriteString(prefix + strconv.Itoa(len(matched)) + "\n")
			continue
		}
		for _, m := range matched {
			sb.WriteString(prefix + m + "\n")
		}
	}
	return stripTrailing(sb.String())
}

// find 列出目录树（最多两层，避免输出爆炸）。
func (p *Processor) find(st *shell.Session, args []string) string {
	base := st.Cwd
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		base = args[0]
	}
	node := st.FS.Resolve(st.Cwd, base)
	if node == nil {
		return "find: '" + base + "': No such file or directory"
	}
	var sb strings.Builder
	collectPaths(st.FS, st.FS.Normalize(st.Cwd, base), node, &sb, 0)
	return sb.String()
}

// collectPaths 先序输出路径（depth < 2 时继续下钻）。
func collectPaths(fs *vfs.FS, path string, node *vfs.Node, sb *strings.Builder, depth int) {
	shown := path
	if shown == "" {
		shown = "/"
	}
	sb.WriteString(shown + "\n")
	if !node.Dir || depth >= 2 {
		return
	}
	prefix := path
	if prefix == "/" {
		prefix = ""
	}
	for _, c := range fs.ChildrenOf(node) {
		collectPaths(fs, prefix+"/"+c.Name, c, sb, depth+1)
	}
}

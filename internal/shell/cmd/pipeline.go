// 管道、重定向与文本过滤器。
//
// 真实 bash 把左侧命令的 stdout 接到右侧命令的 stdin；早期实现（含 Java 版）直接丢弃
// 管道右侧，`ps aux | head -3` 会打印全量进程、`cat /etc/passwd | grep root` 会打印
// 整个文件，攻击者一眼即可看出是假 shell。这里补上常见行过滤器，其余命令保持
// 「忽略下游、保留上游输出」的降级行为，避免出现空输出之类的穿帮。
package cmd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"ssh-honeypot-go/internal/shell"
)

// redirection 一行命令中的输出重定向解析结果。
type redirection struct {
	// rest 去掉重定向片段后剩下的命令。
	rest string
	// file 输出目标文件；空串表示没有文件重定向。
	file string
	// append 是否 >> 追加写。
	append bool
	// drop 是否丢弃输出（>/dev/null）。
	drop bool
	// stderrDrop 是否丢弃标准错误（2> 重定向到文件或 /dev/null）。
	stderrDrop bool
}

// splitRedirects 剥离输出重定向：>、>>、1>、2>、2>&1、&> 与 /dev/null 全部识别，
// 引号内的 > 原样保留（echo "a > b" 不当作重定向）。
//
// 2> 只影响 stderr：蜜罐命令把错误与正常输出放在同一个文本里，因此 2> 仅做剥离，
// 保证 `cat /etc/shadow 2>/dev/null` 不会把 "2>/dev/null" 当文件名。
func splitRedirects(cmd string) redirection {
	var red redirection
	var rest []byte
	var quote byte
	for i := 0; i < len(cmd); {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			rest = append(rest, c)
			i++
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			rest = append(rest, c)
			i++
			continue
		}
		isRedirect := c == '>' || (c == '&' && i+1 < len(cmd) && cmd[i+1] == '>')
		if !isRedirect {
			rest = append(rest, c)
			i++
			continue
		}

		// fd 前缀：2> 只重定向 stderr，&> 同时重定向 stdout/stderr
		fd := "1"
		opStart := i
		if c == '&' {
			fd = "&"
			opStart = i + 1
		} else {
			j := len(rest)
			for j > 0 && rest[j-1] >= '0' && rest[j-1] <= '9' {
				j--
			}
			if j < len(rest) {
				fd = string(rest[j:])
				rest = rest[:j]
			}
		}

		appendMode := opStart+1 < len(cmd) && cmd[opStart+1] == '>'
		j := opStart + 1
		if appendMode {
			j++
		}
		for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
			j++
		}
		k := j
		for k < len(cmd) && cmd[k] != ' ' && cmd[k] != '\t' {
			k++
		}
		target := cmd[j:k]

		switch {
		case target == "":
			rest = append(rest, cmd[i:k]...)
		case target == "&1" || target == "&2":
			// 合并输出：对蜜罐输出无影响
		case target == "/dev/null":
			if fd != "2" {
				red.drop = true
			} else {
				red.stderrDrop = true
			}
		case fd == "2":
			// stderr 重定向到文件：错误信息不应再出现在终端
			red.stderrDrop = true
		default:
			if red.file == "" {
				red.file, red.append = target, appendMode
			}
		}
		i = k
	}
	red.rest = string(rest)
	return red
}

// stderrHints 典型错误信息特征：命中则认为是 stderr（2> 重定向时丢弃）。
var stderrHints = []string{
	"No such file or directory", "Permission denied", "Is a directory",
	"cannot access", "cannot open", "cannot stat", "cannot create",
	"invalid option", "unrecognized option", "missing operand",
	"command not found", "Operation not permitted", "No space left",
}

// dropStderr 丢弃输出中的错误行（模拟 2>/dev/null 与 2>file）。
func dropStderr(name, out string) string {
	if out == "" {
		return out
	}
	lines := splitLines(out)
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		isErr := strings.HasPrefix(line, name+":")
		if !isErr {
			for _, hint := range stderrHints {
				if strings.Contains(line, hint) {
					isErr = true
					break
				}
			}
		}
		if !isErr {
			kept = append(kept, line)
		}
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n")
}

// splitPipeline 按未加引号的单个 | 拆分管道（|| 已在 Execute 里归一为命令序列）。
func splitPipeline(segment string) []string {
	parts := make([]string, 0, 3)
	start := 0
	var quote byte
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '|':
			parts = append(parts, segment[start:i])
			start = i + 1
		}
	}
	return append(parts, segment[start:])
}

// applyFilter 执行管道下游的过滤器；ok=false 表示该命令不支持读 stdin，
// 调用方保留上游输出（降级为旧行为）。
func (p *Processor) applyFilter(st *shell.Session, stage, stdin string) (string, bool) {
	red := splitRedirects(stage)
	tokens := tokenize(expandVars(st, p.hostname, strings.TrimSpace(red.rest)))
	if len(tokens) == 0 {
		return stdin, true
	}
	out, ok := filterOutput(st, tokens[0], tokens[1:], stdin)
	if !ok {
		return stdin, false
	}
	if red.drop {
		return "", true
	}
	if red.file != "" {
		p.writeRedirect(st, red.file, out+"\n", red.append)
		return "", true
	}
	return out, true
}

// filterOutput 文本过滤器实现；ok=false 表示不认识的命令。
func filterOutput(st *shell.Session, name string, args []string, in string) (string, bool) {
	switch name {
	case "cat", "more", "less", "column", "expand", "xargs", "fmt", "paste":
		return in, true
	case "tee":
		for _, f := range nonFlags(args) {
			st.FS.Write(st.Cwd, f, st.Username, in)
		}
		return in, true
	case "head":
		return headLines(in, filterCount(args, 10), false), true
	case "tail":
		return headLines(in, filterCount(args, 10), true), true
	case "wc":
		return wcStdin(in, args), true
	case "grep", "egrep", "fgrep", "zgrep":
		return grepStdin(in, args), true
	case "sort":
		return sortStdin(in, args), true
	case "uniq":
		return uniqStdin(in, args), true
	case "cut":
		return cutStdin(in, args), true
	case "tr":
		return trStdin(in, args), true
	case "nl":
		return nlStdin(in), true
	case "rev":
		return revStdin(in), true
	case "base64":
		return base64Stdin(in, args), true
	case "md5sum", "sha1sum", "sha256sum", "sha512sum":
		return sumStdin(name, in), true
	}
	return "", false
}

// inputLines 把 stdin 文本切成行（去掉尾部的单个换行）。
func inputLines(in string) []string {
	in = strings.TrimSuffix(in, "\n")
	if in == "" {
		return nil
	}
	return strings.Split(in, "\n")
}

// filterCount 解析 head/tail 的行数：-n N、--lines=N、-N，默认 10。
func filterCount(args []string, def int) int {
	n := def
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" || a == "--lines":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil && v >= 0 {
					n = v
				}
			}
		case strings.HasPrefix(a, "--lines="):
			if v, err := strconv.Atoi(strings.TrimPrefix(a, "--lines=")); err == nil && v >= 0 {
				n = v
			}
		case strings.HasPrefix(a, "-") && isAllDigits(strings.TrimPrefix(strings.TrimPrefix(a, "-n"), "-")):
			if v, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(a, "-n"), "-")); err == nil {
				n = v
			}
		}
	}
	return n
}

// headLines 取前 n 行（fromEnd=true 时取后 n 行）。
func headLines(in string, n int, fromEnd bool) string {
	lines := inputLines(in)
	if n < 0 {
		n = 0
	}
	if n > len(lines) {
		n = len(lines)
	}
	if fromEnd {
		lines = lines[len(lines)-n:]
	} else {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// wcStdin 统计 stdin 的行/词/字节/字符数。
func wcStdin(in string, args []string) string {
	return wcValues(wcCounts(in), args)
}

// wcCounts 统计文本的四项计数：行、词、字节、字符。
func wcCounts(in string) [4]int {
	lines := strings.Count(in, "\n")
	if in != "" && !strings.HasSuffix(in, "\n") {
		lines++
	}
	return [4]int{lines, len(strings.Fields(in)), len(in), utf8.RuneCountInString(in)}
}

// wcValues 按选项把计数渲染成一列或多列（多列右对齐 7 位，与 GNU wc 一致）。
func wcValues(counts [4]int, args []string) string {
	showL := hasShort(args, 'l') || hasArg(args, "--lines")
	showW := hasShort(args, 'w') || hasArg(args, "--words")
	showC := hasShort(args, 'c') || hasArg(args, "--bytes")
	showM := hasShort(args, 'm') || hasArg(args, "--chars")
	if !showL && !showW && !showC && !showM {
		showL, showW, showC = true, true, true
	}
	vals := make([]string, 0, 4)
	for i, on := range []bool{showL, showW, showC, showM} {
		if on {
			vals = append(vals, strconv.Itoa(counts[i]))
		}
	}
	if len(vals) > 1 {
		for i := range vals {
			vals[i] = padLeftStr(vals[i])
		}
	}
	return strings.Join(vals, " ")
}

// padLeftStr 右对齐到 7 位（wc 多列输出的格式）。
func padLeftStr(s string) string {
	for len(s) < 7 {
		s = " " + s
	}
	return s
}

// grepStdin 在 stdin 上按模式过滤（支持 -v/-c/-n/-i/-E）。
func grepStdin(in string, args []string) string {
	operands := nonFlags(args)
	if len(operands) == 0 {
		return ""
	}
	pattern := operands[0]
	invert := hasArg(args, "-v") || hasArg(args, "--invert-match")
	count := hasArg(args, "-c") || hasArg(args, "--count")
	number := hasArg(args, "-n") || hasArg(args, "--line-number")
	ignoreCase := hasArg(args, "-i") || hasArg(args, "--ignore-case")
	extended := hasArg(args, "-E") || hasArg(args, "--extended-regexp")

	// 保留首尾锚点：grep '^root' / grep 'bash$' 在 bot 脚本里很常见
	lead := strings.HasPrefix(pattern, "^")
	tail := strings.HasSuffix(pattern, "$") && len(pattern) > 1
	body := pattern
	if lead {
		body = body[1:]
	}
	if tail {
		body = body[:len(body)-1]
	}
	expr := regexp.QuoteMeta(body)
	if lead {
		expr = "^" + expr
	}
	if tail {
		expr += "$"
	}
	if extended {
		expr = pattern
	}
	if ignoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		re = nil
	}
	match := func(line string) bool {
		if re != nil {
			return re.MatchString(line)
		}
		if ignoreCase {
			return strings.Contains(strings.ToLower(line), strings.ToLower(pattern))
		}
		return strings.Contains(line, pattern)
	}

	matched := make([]string, 0, 8)
	for i, line := range inputLines(in) {
		if match(line) == invert || line == "" {
			continue
		}
		if number {
			line = strconv.Itoa(i+1) + ":" + line
		}
		matched = append(matched, line)
	}
	if count {
		return strconv.Itoa(len(matched))
	}
	return strings.Join(matched, "\n")
}

// sortStdin 排序 stdin（支持 -n/-r/-u）。
func sortStdin(in string, args []string) string {
	lines := inputLines(in)
	numeric := hasShort(args, 'n')
	if numeric {
		sort.SliceStable(lines, func(i, j int) bool {
			return leadingNumber(lines[i]) < leadingNumber(lines[j])
		})
	} else {
		sort.Strings(lines)
	}
	if hasShort(args, 'u') {
		uniq := lines[:0]
		for i, line := range lines {
			if i > 0 && line == lines[i-1] {
				continue
			}
			uniq = append(uniq, line)
		}
		lines = uniq
	}
	if hasShort(args, 'r') {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

// leadingNumber 取行首数值（sort -n 用，无法解析时为 0）。
func leadingNumber(line string) float64 {
	f := strings.Fields(line)
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return v
}

// uniqStdin 去重相邻重复行（支持 -c/-d/-u）。
func uniqStdin(in string, args []string) string {
	lines := inputLines(in)
	count := hasArg(args, "-c") || hasArg(args, "--count")
	onlyDup := hasArg(args, "-d") || hasArg(args, "--repeated")
	onlyUniq := hasArg(args, "-u") || hasArg(args, "--unique")

	var sb strings.Builder
	for i := 0; i < len(lines); {
		j := i + 1
		for j < len(lines) && lines[j] == lines[i] {
			j++
		}
		reps := j - i
		keep := true
		if onlyDup && reps < 2 {
			keep = false
		}
		if onlyUniq && reps > 1 {
			keep = false
		}
		if keep {
			if count {
				sb.WriteString(padLeftStr(strconv.Itoa(reps)) + " " + lines[i] + "\n")
			} else {
				sb.WriteString(lines[i] + "\n")
			}
		}
		i = j
	}
	return stripTrailing(sb.String())
}

// cutStdin 按分隔符取字段（-d 分隔符，-f 字段列表，支持 1,3 与 2-4）。
func cutStdin(in string, args []string) string {
	delim := "\t"
	fields := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--delimiter":
			if i+1 < len(args) {
				i++
				delim = args[i]
			}
		case "-f", "--fields":
			if i+1 < len(args) {
				i++
				fields = args[i]
			}
		}
	}
	if fields == "" || len(delim) == 0 {
		return in
	}
	delimRune := rune(delim[0])
	want := parseFieldList(fields)
	var sb strings.Builder
	for _, line := range inputLines(in) {
		parts := strings.Split(line, string(delimRune))
		out := make([]string, 0, len(parts))
		for idx, p := range parts {
			if want[idx+1] {
				out = append(out, p)
			}
		}
		sb.WriteString(strings.Join(out, string(delimRune)) + "\n")
	}
	return stripTrailing(sb.String())
}

// parseFieldList 解析 cut 的字段列表（"1,3"、"2-4"、"2-"）。
func parseFieldList(spec string) map[int]bool {
	want := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		if i := strings.IndexByte(part, '-'); i > 0 {
			lo, err1 := strconv.Atoi(part[:i])
			hi, err2 := strconv.Atoi(part[i+1:])
			if err1 != nil {
				continue
			}
			if err2 != nil || hi < lo {
				hi = lo + 64
			}
			for n := lo; n <= hi; n++ {
				want[n] = true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			want[n] = true
		}
	}
	return want
}

// trStdin 字符翻译/删除（支持 -d 删除、-s 压缩、a-z 区间与常用字符类）。
func trStdin(in string, args []string) string {
	operands := trOperands(args)
	if hasArg(args, "-d") || hasArg(args, "--delete") {
		if len(operands) == 0 {
			return in
		}
		drop := make(map[rune]bool)
		for _, r := range expandSet(operands[0]) {
			drop[r] = true
		}
		var sb strings.Builder
		for _, r := range in {
			if !drop[r] {
				sb.WriteRune(r)
			}
		}
		return sb.String()
	}
	if len(operands) < 2 {
		return in
	}
	from := expandSet(operands[0])
	to := expandSet(operands[1])
	if len(from) == 0 || len(to) == 0 {
		return in
	}
	table := make(map[rune]rune, len(from))
	for i, r := range from {
		table[r] = to[i%len(to)]
	}
	var sb strings.Builder
	for _, r := range in {
		if repl, ok := table[r]; ok {
			sb.WriteRune(repl)
			continue
		}
		sb.WriteRune(r)
	}
	out := sb.String()
	if hasArg(args, "-s") || hasArg(args, "--squeeze-repeats") {
		out = squeeze(out, to[len(to)-1])
	}
	return out
}

// squeeze 压缩连续重复字符。
func squeeze(in string, ch rune) string {
	var sb strings.Builder
	var prev rune
	first := true
	for _, r := range in {
		if !first && r == prev && r == ch {
			continue
		}
		sb.WriteRune(r)
		prev, first = r, false
	}
	return sb.String()
}

// trOperands 提取 tr 的字符集参数："-" 本身就是合法集合，不能用 nonFlags 过滤。
func trOperands(args []string) []string {
	out := make([]string, 0, 2)
	for _, a := range args {
		switch a {
		case "-d", "--delete", "-s", "--squeeze-repeats", "-c", "-C", "--complement", "-t", "--truncate-set1":
			continue
		}
		out = append(out, a)
	}
	return out
}

// expandSet 展开 tr 的字符集合：支持 a-z 区间与 [:space:] [:upper:] [:lower:] [:digit:]。
func expandSet(s string) []rune {
	s = unescape(s)
	const (
		lower = "abcdefghijklmnopqrstuvwxyz"
		upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digit = "0123456789"
		space = " \t\n\r\v\f"
	)
	out := make([]rune, 0, len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '[' && i+1 < len(runes) && runes[i+1] == ':' {
			if end := strings.Index(string(runes[i:]), ":]"); end > 0 {
				switch string(runes[i+2 : i+end]) {
				case "lower":
					out = append(out, []rune(lower)...)
				case "upper":
					out = append(out, []rune(upper)...)
				case "digit":
					out = append(out, []rune(digit)...)
				case "space":
					out = append(out, []rune(space)...)
				}
				i += end + 1
				continue
			}
		}
		if i+2 < len(runes) && runes[i+1] == '-' {
			for r := runes[i]; r <= runes[i+2]; r++ {
				out = append(out, r)
			}
			i += 2
			continue
		}
		out = append(out, runes[i])
	}
	return out
}

// unescape 处理 tr 集合里的反斜杠转义（\n、\t、\r、\\）。
func unescape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case 'r':
			sb.WriteByte('\r')
		case '\\':
			sb.WriteByte('\\')
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// nlStdin 给非空行加行号（格式与 nl 一致：6 位行号 + TAB）。
func nlStdin(in string) string {
	var sb strings.Builder
	n := 0
	for _, line := range inputLines(in) {
		if line == "" {
			sb.WriteString("\n")
			continue
		}
		n++
		sb.WriteString(padLeftStr(strconv.Itoa(n)) + "\t" + line + "\n")
	}
	return stripTrailing(sb.String())
}

// revStdin 反转每行字符。
func revStdin(in string) string {
	lines := inputLines(in)
	for i, line := range lines {
		runes := []rune(line)
		for a, b := 0, len(runes)-1; a < b; a, b = a+1, b-1 {
			runes[a], runes[b] = runes[b], runes[a]
		}
		lines[i] = string(runes)
	}
	return strings.Join(lines, "\n")
}

// base64Stdin base64 编解码 stdin。
func base64Stdin(in string, args []string) string {
	if hasArg(args, "-d") || hasArg(args, "--decode") {
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(in), ""))
		if err != nil {
			return "base64: invalid input"
		}
		return string(raw)
	}
	return base64.StdEncoding.EncodeToString([]byte(in))
}

// sumStdin 计算 stdin 的校验和（哈希值真实，格式与 coreutils 一致）。
func sumStdin(name, in string) string {
	data := []byte(in)
	switch name {
	case "md5sum":
		sum := md5.Sum(data)
		return hex.EncodeToString(sum[:]) + "  -"
	case "sha1sum":
		sum := sha1.Sum(data)
		return hex.EncodeToString(sum[:]) + "  -"
	case "sha256sum":
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]) + "  -"
	default:
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:]) + "  -"
	}
}

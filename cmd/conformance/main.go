// Command conformance 比对 Java 版（1.2.1）与 Go 版（2.0.0）的数据库结构与 HTTP 契约，
// 用于升级前自检、影子实例灰度与发版门禁。
//
// 用法：
//
//	conformance db-diff  -java <java库副本> -go <go库>
//	conformance api-diff -java <java控制台URL> -go <go控制台URL> [-user admin] [-pass <管理员口令>]
//
// db-diff 只读打开两侧数据库，不写入任何内容；api-diff 只调用只读接口
// （以及 login/logout 会话接口），不会修改业务数据。
//
// 退出码：0 一致；1 存在差异；2 用法或运行错误（如连不上、登录失败）。
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"ssh-honeypot-go/internal/conformance"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		printUsage(errOut)
		return 2
	}
	switch args[0] {
	case "db-diff", "db":
		return runDBDiff(args[1:], out, errOut)
	case "api-diff", "api":
		return runAPIDiff(args[1:], out, errOut)
	case "-h", "--help", "help":
		printUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "未知子命令：%s\n\n", args[0])
		printUsage(errOut)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `usage: conformance <子命令> [参数]

子命令:
  db-diff   比对两份 SQLite 库的表、列、索引与 user_version
            conformance db-diff -java db-java/database.db -go db-go/database.db
  api-diff  比对双栈 Web 控制台的响应结构（含未登录态）
            conformance api-diff -java http://127.0.0.1:8080 -go http://127.0.0.1:18080 \
                                 -user admin -pass '<管理员口令>'

退出码: 0 一致; 1 存在差异; 2 用法或运行错误
`)
}

func runDBDiff(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("db-diff", flag.ContinueOnError)
	fs.SetOutput(errOut)
	javaPath := fs.String("java", "", "Java 版数据库文件（副本，只读打开）")
	goPath := fs.String("go", "", "Go 版数据库文件（只读打开）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *javaPath == "" || *goPath == "" {
		fmt.Fprintln(errOut, "db-diff 需要同时指定 -java 与 -go 两个数据库文件")
		return 2
	}

	java, err := conformance.LoadSchema(*javaPath)
	if err != nil {
		fmt.Fprintf(errOut, "读取 Java 版数据库失败: %v\n", err)
		return 2
	}
	goSchema, err := conformance.LoadSchema(*goPath)
	if err != nil {
		fmt.Fprintf(errOut, "读取 Go 版数据库失败: %v\n", err)
		return 2
	}

	fmt.Fprintf(out, "Java: %s (user_version=%d)\n", java.Path, java.UserVersion)
	fmt.Fprintf(out, "Go  : %s (user_version=%d)\n", goSchema.Path, goSchema.UserVersion)
	fmt.Fprintln(out, "\n行数（仅参考，不参与判定）：")
	for _, line := range conformance.RowSummary(java, goSchema) {
		fmt.Fprintln(out, "  "+line)
	}

	diffs := conformance.Diff(java, goSchema)
	if len(diffs) == 0 {
		fmt.Fprintln(out, "\n结果: 结构一致，可原地升级")
		return 0
	}
	fmt.Fprintf(out, "\n差异 %d 处：\n", len(diffs))
	for _, d := range diffs {
		fmt.Fprintln(out, "  - "+d)
	}
	fmt.Fprintln(out, "\n结果: 存在差异，请先修复再升级")
	return 1
}

func runAPIDiff(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("api-diff", flag.ContinueOnError)
	fs.SetOutput(errOut)
	javaURL := fs.String("java", "", "Java 版控制台地址，如 http://127.0.0.1:8080")
	goURL := fs.String("go", "", "Go 版控制台地址，如 http://127.0.0.1:18080")
	user := fs.String("user", "admin", "两侧通用的管理员账号")
	pass := fs.String("pass", "", "管理员口令（两侧需一致）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *javaURL == "" || *goURL == "" || *pass == "" {
		fmt.Fprintln(errOut, "api-diff 需要 -java、-go、-pass（-user 默认 admin）")
		return 2
	}

	java, err := conformance.NewStack("java", *javaURL)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	goStack, err := conformance.NewStack("go", *goURL)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	fmt.Fprintf(out, "Java: %s\nGo  : %s\n\n", java.Base, goStack.Base)

	diffs, err := conformance.CompareAnonymous(java, goStack)
	if err != nil {
		fmt.Fprintf(errOut, "未登录态比对失败: %v\n", err)
		return 2
	}
	reportGroup(out, "未登录态 GET /api/me", diffs)

	if err := java.Login(*user, *pass); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 2
	}
	if err := goStack.Login(*user, *pass); err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return 2
	}
	fmt.Fprintf(out, "登录成功（%s），开始比对 %d 条只读接口\n\n", *user, len(conformance.ReadEndpoints))

	total := len(diffs)
	for _, ep := range conformance.ReadEndpoints {
		label := fmt.Sprintf("%-6s %-40s %s", ep.Method, ep.Path, ep.Desc)
		d, err := conformance.CompareEndpoint(java, goStack, ep)
		if err != nil {
			fmt.Fprintf(errOut, "%s 比对失败: %v\n", label, err)
			return 2
		}
		total += len(d)
		reportGroup(out, label, d)
	}

	fmt.Fprintf(out, "\n跳过写接口 %d 条（会改状态，需人工演练）：", len(conformance.MutatingEndpoints))
	for _, ep := range conformance.MutatingEndpoints {
		fmt.Fprintf(out, " %s", ep.Path)
	}
	fmt.Fprintln(out)
	if total == 0 {
		fmt.Fprintln(out, "结果: 接口契约一致")
		return 0
	}
	fmt.Fprintf(out, "结果: 存在 %d 处差异\n", total)
	return 1
}

// reportGroup 输出一条接口的比对结论：一致打 OK，差异逐条缩进列出。
func reportGroup(w io.Writer, label string, diffs []string) {
	if len(diffs) == 0 {
		fmt.Fprintf(w, "OK   %s\n", label)
		return
	}
	fmt.Fprintf(w, "DIFF %s\n", label)
	for _, d := range diffs {
		fmt.Fprintf(w, "     - %s\n", d)
	}
}

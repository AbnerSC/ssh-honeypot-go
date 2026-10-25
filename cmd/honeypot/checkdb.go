package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // 与生产同驱动，只读打开

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/config"
)

// checkDBTables 升级自检期望存在的表（MIGRATION-PLAN 附录 D，user_version=3）。
var checkDBTables = []string{
	"sessions",
	"auth_attempts",
	"commands",
	"downloads",
	"ip_locks",
	"sys_users",
	"sys_audit_log",
}

// checkDBSchemaVersion 期望的 PRAGMA user_version（与 Java 版 1.2.1 一致）。
const checkDBSchemaVersion = 3

// runCheckDB 只读自检数据库：版本号 + 7 张表行数，供升级前验证 Java 版数据可被 Go 版直接接续。
//
// 全程只读：DSN 使用 mode=ro + query_only，绝不建表、补列或写入任何内容。
func runCheckDB(cfg *config.Config, out io.Writer) int {
	path, err := filepath.Abs(cfg.Log.DB)
	if err != nil {
		fmt.Fprintf(out, "解析数据库路径失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "数据库: %s\n", path)
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(out, "数据库不可用: %v\n", err)
		return 1
	}

	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Fprintf(out, "打开数据库失败: %v\n", err)
		return 1
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		fmt.Fprintf(out, "连接数据库失败: %v\n", err)
		return 1
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		fmt.Fprintf(out, "读取 user_version 失败: %v\n", err)
		return 1
	}

	counts := make([]int64, len(checkDBTables))
	var missing []string
	for i, table := range checkDBTables {
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&counts[i]); err != nil {
			missing = append(missing, table)
		}
	}

	if len(missing) > 0 {
		fmt.Fprintf(out, "schema FAIL: 缺少表 %s\n", strings.Join(missing, ", "))
		return 1
	}
	if version != checkDBSchemaVersion {
		fmt.Fprintf(out, "schema OK 但 user_version=%d，期望 %d（Java 1.2.1 应为 3）\n",
			version, checkDBSchemaVersion)
	} else {
		fmt.Fprintf(out, "schema OK (user_version=%d)\n", version)
	}
	for i, table := range checkDBTables {
		fmt.Fprintf(out, "  %-16s %d\n", table, counts[i])
	}
	return 0
}

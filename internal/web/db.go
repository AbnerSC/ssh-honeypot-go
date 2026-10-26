package web

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，与蜜罐写入共用同一数据库文件
)

// 数据库连接策略（与 Java 版一致）：
//   - 查询走独立只读连接池（query_only 防御性禁写）；
//   - 写走单连接（sys_users / sys_audit_log 写入频率低），由 busy_timeout 吸收与蜜罐写入的锁竞争。
//
// 内存要点：页缓存是「每条连接一份」，且 modernc 驱动的 SQLite 页缓存/排序临时 B 树
// 不计入 Go 堆（只体现为进程 RSS）。实测百万级库下 8 连接 × 4MB 会把 RSS 从约 40MB 抬到 100MB+，
// 所以只读池收紧为 2 条连接、每连接 1MB：统计接口已走预聚合表，短查询用不到大缓存，
// 收紧后同样的并发扫描反而更快（大缓存互相挤占会引入抖动）。
//
// Web 不复用蜜罐写连接：store 的连接池上限为 1，且其连接级 PRAGMA 面向高频写入场景。
func openReadDB(path string) (*sql.DB, error) {
	return openSQLite(path, true)
}

// openWriteDB 打开 Web 侧写连接（用户表与审计表）。
func openWriteDB(path string) (*sql.DB, error) {
	return openSQLite(path, false)
}

// openSQLite 按 DSN 打开数据库；连接级 PRAGMA 写入 DSN，连接重建后自动生效。
func openSQLite(path string, readOnly bool) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("解析数据库路径 %s 失败: %w", path, err)
	}
	params := []string{
		// WAL 为数据库级持久设置：由写连接首先设定，随后的只读连接自动继承
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=busy_timeout(5000)",
		"_pragma=cache_size(-600)", // 写连接维持小缓存，降低常驻内存
	}
	if readOnly {
		params = []string{
			"_pragma=busy_timeout(5000)",
			"_pragma=query_only(1)",
			"_pragma=cache_size(-1024)", // 每连接约 1MB 页缓存：统计已走预聚合表，明细查询只回读少量页
		}
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(abs)+"?"+strings.Join(params, "&"))
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	if readOnly {
		db.SetMaxOpenConns(2)
		db.SetMaxIdleConns(2)
	} else {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}
	return db, nil
}

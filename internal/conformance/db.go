// Package conformance 提供 Java 版（1.2.1）与 Go 版的数据库与接口契约比对：
//
//   - db-diff  比对两份 SQLite 库的表、列、索引与 user_version（数据契约）
//   - api-diff 比对双栈 Web 控制台接口的响应结构（HTTP 契约）
//
// Go 版已是唯一实现，这两个命令只在把存量 Java 库搬到 Go 版时使用：
// 确认数据可以被 Go 版直接接续，之后不再需要逐版本比对。
//
// 两者都只比对「结构」而不比对取值：时间戳、计数、自增 ID 天然不同，
// 比对取值只会产生噪声；结构不一致才是会导致升级失败或前端空白的真问题。
// 命令入口见 cmd/conformance。
package conformance

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，与主程序同一驱动，比较口径一致
)

// Column 表的一列（对应 PRAGMA table_info）。
type Column struct {
	Name    string
	Type    string
	NotNull bool
	Default string
	PK      int
}

// Index 表的一个索引（对应 PRAGMA index_list + index_info）。
type Index struct {
	Name    string
	Unique  bool
	Columns []string
}

// Table 一张表的结构快照。
type Table struct {
	Name    string
	Columns []Column
	Indexes []Index
}

// Schema 一份数据库的结构快照。
type Schema struct {
	Path        string // 实际打开的文件路径（绝对路径）
	UserVersion int
	Tables      map[string]Table
	Rows        map[string]int64
}

// LoadSchema 以只读方式读取数据库结构，不做任何写入。
// 以 mode=ro 打开可避免误改 Java 版生产库，也保证文件不存在时直接报错而不是建空库。
func LoadSchema(path string) (*Schema, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("解析数据库路径 %s 失败: %w", path, err)
	}
	dsn := "file:" + filepath.ToSlash(abs) + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库 %s 失败: %w", path, err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("打开数据库 %s 失败: %w", path, err)
	}

	s := &Schema{Path: abs, Tables: map[string]Table{}, Rows: map[string]int64{}}
	if err := db.QueryRow("PRAGMA user_version").Scan(&s.UserVersion); err != nil {
		return nil, fmt.Errorf("读取 %s 的 user_version 失败: %w", path, err)
	}

	names, err := tableNames(db)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 的表清单失败: %w", path, err)
	}
	for _, name := range names {
		t, err := loadTable(db, name)
		if err != nil {
			return nil, fmt.Errorf("读取 %s 的表 %s 结构失败: %w", path, name, err)
		}
		s.Tables[name] = t

		var rows int64
		if err := db.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(name)).Scan(&rows); err != nil {
			return nil, fmt.Errorf("统计 %s 的表 %s 行数失败: %w", path, name, err)
		}
		s.Rows[name] = rows
	}
	return s, nil
}

// tableNames 列出业务表，跳过 SQLite 内部表（sqlite_sequence 等）。
func tableNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// loadTable 读取一张表的列（含顺序）与索引。
func loadTable(db *sql.DB, name string) (Table, error) {
	t := Table{Name: name}

	info, err := db.Query("PRAGMA table_info(" + quoteIdent(name) + ")")
	if err != nil {
		return t, err
	}
	defer info.Close()
	for info.Next() {
		var (
			cid     int
			col     Column
			dflt    sql.NullString
			notNull int
		)
		if err := info.Scan(&cid, &col.Name, &col.Type, &notNull, &dflt, &col.PK); err != nil {
			return t, err
		}
		col.NotNull = notNull != 0
		col.Default = dflt.String
		t.Columns = append(t.Columns, col)
	}
	if err := info.Err(); err != nil {
		return t, err
	}

	list, err := db.Query("PRAGMA index_list(" + quoteIdent(name) + ")")
	if err != nil {
		return t, err
	}
	defer list.Close()

	var indexNames []string
	unique := map[string]bool{}
	for list.Next() {
		var (
			seq, partial int
			idxName      string
			isUnique     int
			origin       string
		)
		if err := list.Scan(&seq, &idxName, &isUnique, &origin, &partial); err != nil {
			return t, err
		}
		indexNames = append(indexNames, idxName)
		unique[idxName] = isUnique != 0
	}
	if err := list.Err(); err != nil {
		return t, err
	}

	sort.Strings(indexNames)
	for _, idxName := range indexNames {
		idx, err := loadIndex(db, idxName)
		if err != nil {
			return t, err
		}
		idx.Unique = unique[idxName]
		t.Indexes = append(t.Indexes, idx)
	}
	return t, nil
}

// loadIndex 读取索引的列顺序。
func loadIndex(db *sql.DB, name string) (Index, error) {
	idx := Index{Name: name}
	rows, err := db.Query("PRAGMA index_info(" + quoteIdent(name) + ")")
	if err != nil {
		return idx, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			seqno, cid int
			colName    sql.NullString
		)
		if err := rows.Scan(&seqno, &cid, &colName); err != nil {
			return idx, err
		}
		// 表达式索引的列名为 NULL，用 cid 标记位置，保证两侧口径一致
		if colName.Valid {
			idx.Columns = append(idx.Columns, colName.String)
		} else {
			idx.Columns = append(idx.Columns, fmt.Sprintf("<expr:%d>", cid))
		}
	}
	return idx, rows.Err()
}

// ExtensionTables Go 版新增的扩展表（预聚合统计）。
// Java 版没有这些表，遍历时跳过：它们属于纯增量扩展，不参与结构契约。
var ExtensionTables = map[string]bool{
	"stats_daily":     true,
	"stats_ip_daily":  true,
	"stats_usernames": true,
	"stats_passwords": true,
	"stats_locations": true,
}

// RetiredIndexes Go 版已退役的索引（user_version 6 起迁移时 DROP）。
// 这些索引的数据已由聚合表接管，Go 版不再依赖它们；与存量 Java 库比对时
// 按「仅 Java 版存在」跳过，避免把正常退役报成结构差异。
var RetiredIndexes = map[string]bool{
	"idx_auth_password": true,
	"idx_auth_location": true,
}

// Diff 比对两份结构快照，返回人类可读的差异清单（空切片表示一致）。
// 行数不在差异范围内（数据量本就不同），由 RowSummary 单独输出。
func Diff(java, goSchema *Schema) []string {
	var diffs []string
	// Go 版自 user_version 4 起新增预聚合统计表，版本号允许高于 Java 版（由 Go 版自行迁移）；
	// 低于 Java 版则说明这份库比 Java 库还旧，无法直接接续迁移后的数据。
	if goSchema.UserVersion < java.UserVersion {
		diffs = append(diffs, fmt.Sprintf("user_version：java=%d go=%d（Go 版版本号低于 Java 版，无法接续）",
			java.UserVersion, goSchema.UserVersion))
	}

	for _, name := range unionTableNames(java, goSchema) {
		jt, jok := java.Tables[name]
		gt, gok := goSchema.Tables[name]
		switch {
		case !gok:
			diffs = append(diffs, "表 "+name+"：仅 Java 版存在")
		case !jok:
			if ExtensionTables[name] {
				continue
			}
			diffs = append(diffs, "表 "+name+"：仅 Go 版存在")
		default:
			diffs = append(diffs, diffTable(name, jt, gt)...)
		}
	}
	return diffs
}

func unionTableNames(a, b *Schema) []string {
	seen := map[string]struct{}{}
	for name := range a.Tables {
		seen[name] = struct{}{}
	}
	for name := range b.Tables {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func diffTable(name string, java, goTable Table) []string {
	var diffs []string

	// 列顺序参与比较：结构体扫描与 SELECT * 依赖列顺序
	jCols := make([]string, len(java.Columns))
	for i, c := range java.Columns {
		jCols[i] = c.Name
	}
	gCols := make([]string, len(goTable.Columns))
	for i, c := range goTable.Columns {
		gCols[i] = c.Name
	}
	if strings.Join(jCols, ",") != strings.Join(gCols, ",") {
		diffs = append(diffs, fmt.Sprintf("表 %s 列顺序不同：\n    java: %s\n    go  : %s",
			name, strings.Join(jCols, ", "), strings.Join(gCols, ", ")))
	}

	jMap := map[string]Column{}
	for _, c := range java.Columns {
		jMap[c.Name] = c
	}
	gMap := map[string]Column{}
	for _, c := range goTable.Columns {
		gMap[c.Name] = c
	}

	for _, cname := range unionKeys(jMap, gMap) {
		jc, jok := jMap[cname]
		gc, gok := gMap[cname]
		switch {
		case !gok:
			diffs = append(diffs, fmt.Sprintf("表 %s 列 %s：仅 Java 版存在", name, cname))
		case !jok:
			diffs = append(diffs, fmt.Sprintf("表 %s 列 %s：仅 Go 版存在", name, cname))
		default:
			if !strings.EqualFold(jc.Type, gc.Type) {
				diffs = append(diffs, fmt.Sprintf("表 %s 列 %s 类型不同：java=%s go=%s",
					name, cname, jc.Type, gc.Type))
			}
			if jc.NotNull != gc.NotNull {
				diffs = append(diffs, fmt.Sprintf("表 %s 列 %s NOT NULL 不同：java=%t go=%t",
					name, cname, jc.NotNull, gc.NotNull))
			}
			if jc.PK != gc.PK {
				diffs = append(diffs, fmt.Sprintf("表 %s 列 %s 主键序号不同：java=%d go=%d",
					name, cname, jc.PK, gc.PK))
			}
			if jc.Default != gc.Default {
				diffs = append(diffs, fmt.Sprintf("表 %s 列 %s 默认值不同：java=%q go=%q",
					name, cname, jc.Default, gc.Default))
			}
		}
	}

	jIdx := map[string]Index{}
	for _, idx := range java.Indexes {
		jIdx[idx.Name] = idx
	}
	gIdx := map[string]Index{}
	for _, idx := range goTable.Indexes {
		gIdx[idx.Name] = idx
	}
	for _, iname := range unionKeys(jIdx, gIdx) {
		ji, jok := jIdx[iname]
		gi, gok := gIdx[iname]
		switch {
		case !gok:
			if RetiredIndexes[iname] {
				continue
			}
			diffs = append(diffs, fmt.Sprintf("表 %s 索引 %s：仅 Java 版存在", name, iname))
		case !jok:
			diffs = append(diffs, fmt.Sprintf("表 %s 索引 %s：仅 Go 版存在", name, iname))
		default:
			if ji.Unique != gi.Unique {
				diffs = append(diffs, fmt.Sprintf("表 %s 索引 %s 唯一性不同：java=%t go=%t",
					name, iname, ji.Unique, gi.Unique))
			}
			if strings.Join(ji.Columns, ",") != strings.Join(gi.Columns, ",") {
				diffs = append(diffs, fmt.Sprintf("表 %s 索引 %s 列不同：java=(%s) go=(%s)",
					name, iname, strings.Join(ji.Columns, ", "), strings.Join(gi.Columns, ", ")))
			}
		}
	}
	return diffs
}

// RowSummary 输出两侧各表行数，仅作参考（不参与一致性判定）。
func RowSummary(java, goSchema *Schema) []string {
	lines := make([]string, 0, len(java.Tables))
	for _, name := range unionTableNames(java, goSchema) {
		jrows, jok := java.Rows[name]
		grows, gok := goSchema.Rows[name]
		switch {
		case !jok:
			lines = append(lines, fmt.Sprintf("%-18s java=-            go=%d", name, grows))
		case !gok:
			lines = append(lines, fmt.Sprintf("%-18s java=%d            go=-", name, jrows))
		default:
			lines = append(lines, fmt.Sprintf("%-18s java=%-12d go=%d", name, jrows, grows))
		}
	}
	return lines
}

func unionKeys[T any](a, b map[string]T) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// quoteIdent 给 SQLite 标识符加双引号并转义内部双引号。
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// 系统用户角色：admin 全部权限；viewer 仅查看日志统计与明细。
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// 首次部署自动创建的默认管理员（强制首次登录改密）。
//
// 初始口令必须自身满足强度策略（12 位、大写/小写/数字/符号四类），
// 否则部署后到首次登录之间的窗口里，默认口令本身就是一条公开的弱口令入口。
const (
	defaultAdminUsername = "admin"
	defaultAdminPassword = "Yx63rwpHMo#jZC"
)

// PBKDF2-HMAC-SHA256 参数，与 Java 版 UserRepository.Passwords 保持一致。
const (
	pbkdf2Iterations = 210_000
	pbkdf2SaltBytes  = 16
	pbkdf2KeyBytes   = 32 // 256 bit
	passwordPrefix   = "pbkdf2-sha256"
)

// tsLayout 系统表时间格式，与 Java 版 DateTimeFormatter 一致（秒级）。
const tsLayout = "2006-01-02 15:04:05"

// sqlCreateUsers 系统用户表（DDL 与 Java 版逐字一致）。
const sqlCreateUsers = `
CREATE TABLE IF NOT EXISTS sys_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,          -- 登录用户名
    password_hash TEXT    NOT NULL,                 -- PBKDF2 口令哈希
    role          TEXT    NOT NULL DEFAULT 'admin', -- admin / viewer
    status        INTEGER NOT NULL DEFAULT 1,       -- 1 启用 / 0 禁用
    must_change   INTEGER NOT NULL DEFAULT 0,       -- 1 下次登录强制改密
    created_at    TEXT    NOT NULL,
    last_login_at TEXT
)`

// User 对外输出的用户信息（绝不包含口令哈希）。
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Enabled     bool   `json:"enabled"`
	MustChange  bool   `json:"mustChange"`
	CreatedAt   string `json:"createdAt"`
	LastLoginAt string `json:"lastLoginAt,omitempty"`
}

// dbUser 内部用户记录：附带口令哈希，仅供登录校验。
type dbUser struct {
	User
	PasswordHash string
}

// UserRepo 系统用户仓库。
type UserRepo struct {
	db     *sql.DB
	logger *slog.Logger
}

// newUserRepo 建表并在库中无账号时创建默认管理员。
func newUserRepo(db *sql.DB, logger *slog.Logger) (*UserRepo, error) {
	r := &UserRepo{db: db, logger: logger}
	if _, err := db.Exec(sqlCreateUsers); err != nil {
		return nil, fmt.Errorf("初始化系统用户表失败: %w", err)
	}
	if err := r.bootstrapDefaultAdmin(); err != nil {
		return nil, err
	}
	return r, nil
}

// bootstrapDefaultAdmin 首次部署无任何账号时自动创建默认管理员（强制首次改密），避免控制台不可用。
func (r *UserRepo) bootstrapDefaultAdmin() error {
	var count int64
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM sys_users`).Scan(&count); err != nil {
		return fmt.Errorf("统计系统用户失败: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := r.create(defaultAdminUsername, defaultAdminPassword, RoleAdmin, true); err != nil {
		return fmt.Errorf("创建默认管理员失败: %w", err)
	}
	if r.logger != nil {
		r.logger.Warn("Web 控制台已创建默认管理员 " + defaultAdminUsername + "/" + defaultAdminPassword +
			"（首次登录强制修改密码），请尽快修改！")
	}
	return nil
}

// scanner 兼容 *sql.Row 与 *sql.Rows 的扫描接口。
type scanner interface {
	Scan(dest ...any) error
}

// scanUser 读取一行用户记录（列顺序固定）。
func scanUser(s scanner) (*dbUser, error) {
	var (
		u          dbUser
		status     int
		mustChange int
		lastLogin  sql.NullString
	)
	if err := s.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &status, &mustChange,
		&u.CreatedAt, &lastLogin); err != nil {
		return nil, err
	}
	u.Enabled = status == 1
	u.MustChange = mustChange == 1
	if lastLogin.Valid {
		u.LastLoginAt = lastLogin.String
	}
	return &u, nil
}

// findByUsername 按用户名查找（含口令哈希，仅供登录校验用）；不存在返回 nil。
func (r *UserRepo) findByUsername(username string) (*dbUser, error) {
	row := r.db.QueryRow(`SELECT id, username, password_hash, role, status, must_change, created_at, last_login_at
		FROM sys_users WHERE username = ?`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return u, nil
}

// findById 按 ID 查找（不含口令哈希）。
func (r *UserRepo) findById(id int64) (*User, error) {
	row := r.db.QueryRow(`SELECT id, username, password_hash, role, status, must_change, created_at, last_login_at
		FROM sys_users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return &u.User, nil
}

// list 账号列表（不含口令哈希）。
func (r *UserRepo) list() ([]User, error) {
	rows, err := r.db.Query(`SELECT id, username, password_hash, role, status, must_change, created_at, last_login_at
		FROM sys_users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	defer rows.Close()

	users := make([]User, 0, 8)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("读取用户记录失败: %w", err)
		}
		users = append(users, u.User)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取用户列表失败: %w", err)
	}
	return users, nil
}

// create 新建用户，返回自增 ID。
func (r *UserRepo) create(username, password, role string, mustChange bool) (int64, error) {
	res, err := r.db.Exec(`INSERT INTO sys_users(username, password_hash, role, status, must_change, created_at)
		VALUES(?,?,?,?,?,?)`,
		username, hashPassword(password), role, 1, boolToInt(mustChange), time.Now().Format(tsLayout))
	if err != nil {
		return 0, fmt.Errorf("创建用户失败: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("获取用户 ID 失败: %w", err)
	}
	return id, nil
}

// setStatus 启用/禁用用户。
func (r *UserRepo) setStatus(id int64, enabled bool) error {
	return r.exec(`UPDATE sys_users SET status = ? WHERE id = ?`, boolToInt(enabled), id)
}

// resetPassword 管理员重置口令（按需强制下次登录改密）。
func (r *UserRepo) resetPassword(id int64, newPassword string, mustChange bool) error {
	return r.exec(`UPDATE sys_users SET password_hash = ?, must_change = ? WHERE id = ?`,
		hashPassword(newPassword), boolToInt(mustChange), id)
}

// changePassword 自助改密并清除强制改密标记。
func (r *UserRepo) changePassword(id int64, newPassword string) error {
	return r.exec(`UPDATE sys_users SET password_hash = ?, must_change = 0 WHERE id = ?`,
		hashPassword(newPassword), id)
}

// delete 删除用户。
func (r *UserRepo) delete(id int64) error {
	return r.exec(`DELETE FROM sys_users WHERE id = ?`, id)
}

// countAdmins 统计启用状态的管理员数量（用于「至少保留一个管理员」校验）。
func (r *UserRepo) countAdmins() (int64, error) {
	var n int64
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM sys_users WHERE role = 'admin' AND status = 1`).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计管理员失败: %w", err)
	}
	return n, nil
}

// recordLogin 记录最近登录时间。
func (r *UserRepo) recordLogin(id int64) error {
	return r.exec(`UPDATE sys_users SET last_login_at = ? WHERE id = ?`, time.Now().Format(tsLayout), id)
}

func (r *UserRepo) exec(query string, args ...any) error {
	if _, err := r.db.Exec(query, args...); err != nil {
		return fmt.Errorf("更新用户表失败: %w", err)
	}
	return nil
}

// hashPassword 生成 pbkdf2-sha256$迭代次数$salt$hash（Base64 标准编码，与 Java 版一致）。
func hashPassword(password string) string {
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand 异常时用时间戳摘要兜底，保证仍可产生不可预测的盐
		sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(salt, sum[:pbkdf2SaltBytes])
	}
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyBytes, sha256.New)
	return passwordPrefix + "$" + strconv.Itoa(pbkdf2Iterations) + "$" +
		base64.StdEncoding.EncodeToString(salt) + "$" +
		base64.StdEncoding.EncodeToString(key)
}

// verifyPassword 校验口令；常数时间比较，防时序侧信道。
func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != passwordPrefix {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != pbkdf2KeyBytes {
		return false
	}
	actual := pbkdf2.Key([]byte(password), salt, iterations, pbkdf2KeyBytes, sha256.New)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

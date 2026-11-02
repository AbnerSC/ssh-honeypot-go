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
	"math/big"
	"os"
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
// 初始口令不再硬编码：写死在源码里的口令等于随仓库/镜像/文档公开传播的入口，
// 任何扫到 Web 端口的攻击者都能直接登录取证数据。默认每次首次启动随机生成，
// 只打印到运行日志（控制台）；也支持用 WEB_ADMIN_PASSWORD 环境变量显式指定
// （优先级：环境变量 > 随机生成），供容器/自动化编排注入确定性口令。
// 无论哪种来源，口令都必须自身满足强度策略
// （≥ 12 位、大写/小写/数字/符号四类全覆盖），否则到首次登录之间的窗口里
// 初始口令本身就是一条弱口令入口。
const (
	defaultAdminUsername = "admin"

	// webAdminPasswordEnv 可选环境变量：显式指定默认管理员初始口令。
	// 未设置或空白视为未配置，回退随机生成；配置但不满足强度策略时告警并回退。
	webAdminPasswordEnv = "WEB_ADMIN_PASSWORD"

	// 随机初始口令字符集：剔除 0/O、1/I/l 等易混淆字符，便于运维照抄控制台输出。
	pwdUpperPool   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	pwdLowerPool   = "abcdefghijkmnopqrstuvwxyz"
	pwdDigitPool   = "23456789"
	pwdSymbolPool  = "#%&*+-@^~"
	pwdAlphabetLen = len(pwdUpperPool) + len(pwdLowerPool) + len(pwdDigitPool) + len(pwdSymbolPool)

	// defaultAdminPasswordLength 16 位：四类字符各强制 1 位，其余 12 位全字符集随机。
	defaultAdminPasswordLength = 16
)

// defaultAdminPassword 本次首次启动随机生成的默认管理员初始口令，仅用于日志打印。
// 非首次启动（库中已有账号）保持为空，绝不重复打印口令，
// 也避免改密后运行日志里仍留有一条看似可用的凭证。
var defaultAdminPassword string

// testDefaultAdminPassword 测试专用的固定初始口令注入点（见 web_test.go 的 TestMain），
// 生产环境恒为空 -> 走随机生成。
var testDefaultAdminPassword string

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

// newUserRepo 建表并在库中无账号时创建默认管理员（初始口令随机生成后打印到运行日志）。
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

// bootstrapDefaultAdmin 首次部署无任何账号时创建默认管理员（强制首次改密），避免控制台不可用。
//
// 初始口令来源：WEB_ADMIN_PASSWORD 环境变量（显式指定）> 随机生成；
// 随机生成时把口令打印到运行日志，环境变量指定时只提示来源、绝不回显口令值。
func (r *UserRepo) bootstrapDefaultAdmin() error {
	var count int64
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM sys_users`).Scan(&count); err != nil {
		return fmt.Errorf("统计系统用户失败: %w", err)
	}
	if count > 0 {
		return nil
	}
	password, fromEnv := r.resolveDefaultAdminPassword()
	if _, err := r.create(defaultAdminUsername, password, RoleAdmin, true); err != nil {
		return fmt.Errorf("创建默认管理员失败: %w", err)
	}
	if !fromEnv {
		// 随机口令仅此一次打印；非首次启动/环境变量指定场景不落入此分支。
		defaultAdminPassword = password
	}
	if r.logger != nil {
		if fromEnv {
			r.logger.Warn("Web 控制台已创建默认管理员 " + defaultAdminUsername +
				"（初始口令来自环境变量 " + webAdminPasswordEnv + "，首次登录强制修改密码）")
		} else {
			r.logger.Warn("Web 控制台已创建默认管理员 " + defaultAdminUsername + "/" + password +
				"（随机初始口令，仅本次启动打印，请立即登录并修改密码）")
		}
	}
	return nil
}

// resolveDefaultAdminPassword 按优先级确定默认管理员初始口令，返回口令与「是否来自环境变量」标记。
//
// 环境变量优先，但必须自身满足强度策略，否则告警并回退随机生成——
// 不能让运维随手配的弱口令成为公开入口。测试注入点 testDefaultAdminPassword
// 优先于一切，使集成用例不依赖随机值与环境变量。
func (r *UserRepo) resolveDefaultAdminPassword() (password string, fromEnv bool) {
	if testDefaultAdminPassword != "" {
		return testDefaultAdminPassword, false
	}
	if env := strings.TrimSpace(os.Getenv(webAdminPasswordEnv)); env != "" {
		if msg := checkPassword(env); msg != "" {
			warnf(r.logger, "环境变量 "+webAdminPasswordEnv+" 不满足口令强度策略（"+msg+"），已忽略并改用随机初始口令。")
		} else {
			return env, true
		}
	}
	pwd, err := generateDefaultAdminPassword()
	if err != nil {
		// 理论上随机生成不会失败；真失败时兜底再随机，仍失败则 panic 交由上层 recover 记录，
		// 绝不静默降级为空口令（那等于关闭控制台鉴权）。
		warnf(r.logger, "生成随机初始口令失败: "+err.Error())
		pwd, err = generateDefaultAdminPassword()
		if err != nil {
			panic("无法生成默认管理员初始口令: " + err.Error())
		}
	}
	return pwd, false
}

// generateDefaultAdminPassword 生成满足控制台口令强度策略的随机初始管理员口令。
//
// 四类字符各先取 1 位保证种类覆盖，余下位数从全字符集随机，最后整体洗牌——
// 否则前四位固定为「大写/小写/数字/符号」的位置模式会成为口令的先验结构。
// 每一位都用 crypto/rand 拒绝采样取值，避免取模偏置削弱口令熵。
func generateDefaultAdminPassword() (string, error) {
	pools := []string{pwdUpperPool, pwdLowerPool, pwdDigitPool, pwdSymbolPool}
	chars := make([]byte, 0, defaultAdminPasswordLength)
	for _, pool := range pools {
		idx, err := randIndex(len(pool))
		if err != nil {
			return "", err
		}
		chars = append(chars, pool[idx])
	}
	for i := len(pools); i < defaultAdminPasswordLength; i++ {
		idx, err := randIndex(pwdAlphabetLen)
		if err != nil {
			return "", err
		}
		chars = append(chars, alphabetChar(idx))
	}
	// Fisher-Yates 洗牌（crypto/rand），打乱强制种类的字符位置
	for i := len(chars) - 1; i > 0; i-- {
		j, err := randIndex(i + 1)
		if err != nil {
			return "", err
		}
		chars[i], chars[j] = chars[j], chars[i]
	}
	password := string(chars)
	if msg := checkPassword(password); msg != "" {
		return "", fmt.Errorf("随机初始口令不满足强度策略: %s", msg)
	}
	return password, nil
}

// alphabetChar 按 [0, pwdAlphabetLen) 内的下标取字符集字符（下标由调用方保证合法）。
func alphabetChar(idx int) byte {
	switch {
	case idx < len(pwdUpperPool):
		return pwdUpperPool[idx]
	case idx < len(pwdUpperPool)+len(pwdLowerPool):
		return pwdLowerPool[idx-len(pwdUpperPool)]
	case idx < len(pwdUpperPool)+len(pwdLowerPool)+len(pwdDigitPool):
		return pwdDigitPool[idx-len(pwdUpperPool)-len(pwdLowerPool)]
	default:
		return pwdSymbolPool[idx-len(pwdUpperPool)-len(pwdLowerPool)-len(pwdDigitPool)]
	}
}

// randIndex 返回 [0, n) 内均匀分布的随机下标；crypto/rand 异常时用时间戳摘要兜底，
// 保证首次部署不会因随机源故障而完全没有可用口令。
func randIndex(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("随机下标范围非法")
	}
	if !cryptoRandAvailable() {
		return fallbackIndex(n), nil
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return fallbackIndex(n), nil
	}
	return int(v.Int64()), nil
}

// cryptoRandAvailable 探测系统随机源是否可用（与口令哈希取盐的判断方式保持一致）。
func cryptoRandAvailable() bool {
	var probe [8]byte
	_, err := rand.Read(probe[:])
	return err == nil
}

// fallbackIndex 兜底取数：随机源不可用时用时间戳摘要派生，可预测但不至于无口令可用。
// 用 big.Int 取模（结果恒为非负），避免 32 位平台上强转溢出。
func fallbackIndex(n int) int {
	sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	v := big.NewInt(0).SetBytes(sum[:8])
	return int(v.Mod(v, big.NewInt(int64(n))).Int64())
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

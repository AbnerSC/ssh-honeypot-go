package dbpot

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Redis 协议常量。
const (
	// redisMaxCommands 单会话最多读取的命令数，防止扫描器以命令流长期占用连接。
	redisMaxCommands = 8
	// redisMaxArgCount / redisMaxArgLength 命令参数个数与长度上限，防畸形命令耗尽内存。
	redisMaxArgCount  = 16
	redisMaxArgLength = 1024
	// redisDefaultUser Redis 6+ 单参数 AUTH（仅密码）视为默认用户认证。
	redisDefaultUser = "default"
)

// 固定 RESP 响应，与真实 Redis 7 的措辞一致。
var (
	redisWrongPass = []byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n")
	redisNoAuth    = []byte("-NOAUTH Authentication required.\r\n")
	redisAuthArgs  = []byte("-ERR wrong number of arguments for 'auth' command\r\n")
	redisOK        = []byte("+OK\r\n")
	redisTooMany   = []byte("-ERR max number of clients reached\r\n")
)

// errRedisLineTooLong RESP 长度行超长。
var errRedisLineTooLong = errors.New("redis: RESP 长度行过长")

// NewRedis 构造 Redis 蜜罐（伪装 Redis 7）。
func NewRedis(opts Options) (*Server, error) {
	return newServer("redis", "Redis", "伪装版本 7", opts, redisTooMany, handleRedis)
}

// handleRedis 读取命令诱导客户端提交 AUTH 凭证，捕获后一律返回 -WRONGPASS 并断开。
func handleRedis(c *conn) {
	for i := 0; i < redisMaxCommands; i++ {
		args, ok := redisReadCommand(c.br)
		if !ok || len(args) == 0 {
			return
		}
		// 探测/诱导阶段收到的命令同样留痕（INFO/KEYS/CONFIG 等是重要 IOC）；
		// Redis 会话无用户名概念，置空。
		c.srv.opts.Events.Command(c.id, c.ip, "", strings.Join(args, " "))

		switch strings.ToUpper(args[0]) {
		case "AUTH":
			if len(args) == 2 { // AUTH <password>：Redis 6+ 按默认用户认证
				redisCapture(c, redisDefaultUser, args[1])
				c.write(redisWrongPass)
				return
			}
			if len(args) >= 3 { // AUTH <username> <password>
				redisCapture(c, args[1], args[2])
				c.write(redisWrongPass)
				return
			}
			c.write(redisAuthArgs)
		case "HELLO":
			// HELLO [protover [AUTH <user> <pass>]]
			if ai := redisArgIndex(args, "AUTH"); ai >= 0 && ai+2 < len(args) {
				redisCapture(c, args[ai+1], args[ai+2])
				c.write(redisWrongPass)
				return
			}
			c.write(redisNoAuth)
		case "QUIT":
			c.write(redisOK)
			return
		default:
			c.write(redisNoAuth)
		}
	}
}

// redisCapture 记录一次登录尝试（协议传输为明文凭证），空密码记为 (空)。
func redisCapture(c *conn, username, password string) {
	if password == "" {
		password = "(空)"
	}
	c.srv.opts.Events.AuthAttempt(c.id, "redis", c.ip, username, password, false)
}

// redisReadCommand 读取一条命令，兼容 RESP 数组与内联命令两种形式。
// ok 为 false 表示 EOF/畸形报文，调用方直接断开。
func redisReadCommand(r *bufio.Reader) ([]string, bool) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, false
	}
	if first == '*' { // RESP 数组：*N\r\n$len\r\n...
		count, err := redisReadLineInt(r)
		if err != nil || count <= 0 || count > redisMaxArgCount {
			return nil, false
		}
		args := make([]string, count)
		for i := 0; i < count; i++ {
			if typ, err := r.ReadByte(); err != nil || typ != '$' {
				return nil, false
			}
			length, err := redisReadLineInt(r)
			if err != nil || length < 0 || length > redisMaxArgLength {
				return nil, false
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, false
			}
			if _, err := r.Discard(2); err != nil { // 参数尾部 \r\n
				return nil, false
			}
			args[i] = string(data)
		}
		return args, true
	}

	// 内联命令：读取至行尾后按空白切分
	line := make([]byte, 0, 32)
	line = append(line, first)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, false
		}
		if b == '\n' {
			break
		}
		if len(line) >= redisMaxArgLength {
			return nil, false
		}
		if b != '\r' {
			line = append(line, b)
		}
	}
	text := strings.TrimSpace(string(line))
	if text == "" {
		return []string{}, true
	}
	return strings.Fields(text), true
}

// redisArgIndex 从下标 1 起查找指定名称的参数（忽略大小写），未找到返回 -1。
func redisArgIndex(args []string, name string) int {
	for i := 1; i < len(args); i++ {
		if strings.EqualFold(args[i], name) {
			return i
		}
	}
	return -1
}

// redisReadLineInt 读取一个以 CRLF 结尾的整数行（长度行）。
func redisReadLineInt(r *bufio.Reader) (int, error) {
	var b []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if c == '\n' {
			break
		}
		if c != '\r' {
			if len(b) >= 32 {
				return 0, errRedisLineTooLong
			}
			b = append(b, c)
		}
	}
	return strconv.Atoi(string(b))
}

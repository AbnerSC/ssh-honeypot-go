package dbpot

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// MySQL 协议常量。
const (
	// mysqlServerVersion 握手包中展示的伪造版本号。
	mysqlServerVersion = "8.4.0"
	// mysqlAuthPlugin 声明认证插件：兼容性最好，绝大多数客户端与扫描器均支持。
	mysqlAuthPlugin = "mysql_native_password"
	// mysqlSaltLen 认证盐长度（mysql_native_password 协议要求 20 字节）。
	mysqlSaltLen = 20

	mysqlClientProtocol41       uint32 = 0x00000200
	mysqlClientSecureConnection uint32 = 0x00008000
	mysqlClientPluginAuth       uint32 = 0x00080000
	mysqlClientPluginAuthLenenc uint32 = 0x00200000

	mysqlErrAccessDenied   = 1045
	mysqlStateAccessDenied = "28000"
	// mysqlMaxPacket 可接受的最大包长度，防超大报文耗尽内存。
	mysqlMaxPacket = 0x10000
)

// mysqlTooMany 连接数超限响应（ERROR 1040 / SQLSTATE 08004），构造一次复用。
var mysqlTooMany = mysqlPacket(
	mysqlErrBody(1040, "08004", "Too many connections"), 0)

// NewMySQL 构造 MySQL 蜜罐（伪装 MySQL 8.4）。
func NewMySQL(opts Options) (*Server, error) {
	return newServer("mysql", "MySQL", "伪装版本 8.4", opts, mysqlTooMany, handleMySQL)
}

// handleMySQL 下发握手包捕获登录凭证，无论凭证是什么一律返回 1045 后断开。
func handleMySQL(c *conn) {
	c.write(mysqlPacket(mysqlHandshake(mysqlRandomSalt()), 0))

	payload, err := mysqlReadPacket(c.br)
	if err != nil {
		// 扫描器未发送登录报文或客户端提前断开：静默忽略，不发错误包
		return
	}

	user, authHex, ok := mysqlParseResponse(payload)
	usingPassword := false
	if ok {
		usingPassword = authHex != ""
		password := authHex
		if !usingPassword {
			// MySQL 协议传输的是密码散列，记录十六进制认证数据；空认证数据表示未输入密码
			password = "(空)"
		}
		c.srv.opts.Events.AuthAttempt(c.id, "mysql", c.ip, user, password, false)
	} else {
		user = "unknown"
	}

	c.write(mysqlPacket(mysqlAccessDenied(user, c.ip, usingPassword), 2))
}

// mysqlPacket 拼接 3 字节小端长度 + 1 字节序号的包头。
func mysqlPacket(payload []byte, seq byte) []byte {
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

// mysqlErrBody 构造 ERR 包主体：0xFF + 错误码（小端）+ '#' + SQLSTATE + 消息。
func mysqlErrBody(code int, sqlstate, msg string) []byte {
	b := make([]byte, 0, 16+len(msg))
	b = append(b, 0xFF, byte(code), byte(code>>8), '#')
	b = append(b, sqlstate...)
	b = append(b, msg...)
	return b
}

// mysqlHandshake 构造 HandshakeV10 握手包。
// 不声明 CLIENT_SSL，避免诱导客户端发起 TLS 升级。
func mysqlHandshake(salt []byte) []byte {
	caps := mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientPluginAuth
	b := make([]byte, 0, 128)
	b = append(b, 0x0A)                   // 协议版本 10（HandshakeV10）
	b = append(b, mysqlServerVersion...)  // 服务器版本
	b = append(b, 0x00)                   // 版本号 NUL 终止
	b = append(b, 0x00, 0x00, 0x01, 0x2A) // 线程 ID（伪造）
	b = append(b, salt[:8]...)            // auth-plugin-data 第 1 部分（8 字节）
	b = append(b, 0x00)                   // 填充字节
	b = append(b, byte(caps), byte(caps>>8))
	b = append(b, 0x2D)       // 字符集 utf8mb4_0900_ai_ci
	b = append(b, 0x02, 0x00) // 状态标志 SERVER_STATUS_AUTOCOMMIT
	b = append(b, byte(caps>>16), byte(caps>>24))
	b = append(b, byte(len(salt)+1)) // auth-plugin-data 总长度（含终止符）
	b = append(b, make([]byte, 10)...)
	b = append(b, salt[8:]...) // 第 2 部分（12 字节）
	b = append(b, 0x00)        // 第 2 部分 NUL 终止
	b = append(b, mysqlAuthPlugin...)
	b = append(b, 0x00) // 插件名 NUL 终止
	return b
}

// mysqlRandomSalt 生成每连接随机认证盐。固定盐可被客户端两次连接比对识破，是典型蜜罐指纹。
func mysqlRandomSalt() []byte {
	salt := make([]byte, mysqlSaltLen)
	if _, err := rand.Read(salt); err != nil {
		// 熵源异常时退化为固定盐：宁可留下指纹也不能中断服务
		for i := range salt {
			salt[i] = byte(i * 7)
		}
	}
	return salt
}

// mysqlReadPacket 读取一个完整包并返回负载；长度非法时返回空负载（与 Java 版一致）。
func mysqlReadPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length <= 0 || length > mysqlMaxPacket {
		return []byte{}, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// mysqlParseResponse 解析 HandshakeResponse41，提取用户名与认证数据（十六进制）。
// 报文过短或非 4.1+ 协议时 ok 为 false。
func mysqlParseResponse(p []byte) (user, authHex string, ok bool) {
	if len(p) < 32 { // 头部固定 32 字节（能力 4 + 最大包长 4 + 字符集 1 + 保留 23）
		return "", "", false
	}
	caps := binary.LittleEndian.Uint32(p[:4])
	if caps&mysqlClientProtocol41 == 0 {
		return "", "", false
	}

	pos := 32
	nul := bytes.IndexByte(p[pos:], 0)
	if nul < 0 {
		return "", "", false
	}
	end := pos + nul
	if end-pos > 512 { // 用户名长度上限，防止畸形报文放大内存
		end = pos + 512
	}
	user = string(p[pos:end])
	pos += nul + 1

	var authLen int
	switch {
	case caps&mysqlClientPluginAuthLenenc != 0, caps&mysqlClientSecureConnection != 0:
		if pos >= len(p) {
			return "", "", false
		}
		authLen = int(p[pos])
		pos++
	default: // 兼容 3.23 风格：NUL 终止
		if e := bytes.IndexByte(p[pos:], 0); e >= 0 {
			authLen = e
		} else {
			authLen = len(p) - pos
		}
	}
	if authLen > len(p)-pos {
		authLen = len(p) - pos
	}
	if authLen < 0 {
		authLen = 0
	}
	return user, hex.EncodeToString(p[pos : pos+authLen]), true
}

// mysqlAccessDenied 构造 ERROR 1045 (28000) 错误包，用户名取自客户端实际提交的账号。
func mysqlAccessDenied(user, ip string, usingPassword bool) []byte {
	using := "NO"
	if usingPassword {
		using = "YES"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", user, ip, using)
	return mysqlErrBody(mysqlErrAccessDenied, mysqlStateAccessDenied, msg)
}

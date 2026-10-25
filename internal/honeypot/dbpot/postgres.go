package dbpot

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PostgreSQL 协议常量。
const (
	// pgProtocolV3 StartupMessage 的 3.0 协议版本号。
	pgProtocolV3 = 196608
	// pgSSLRequest 客户端请求 TLS 升级的请求码。
	pgSSLRequest = 80877103
	// pgMaxMessageLength 可接受的最大报文长度，防超大报文耗尽内存。
	pgMaxMessageLength = 0x10000
)

// pgTooMany 连接数超限响应（FATAL / SQLSTATE 53300），构造一次复用。
var pgTooMany = pgErrorPacket("53300", "sorry, too many clients already", "proc.c", "BackendStartup")

// NewPostgres 构造 PostgreSQL 蜜罐（伪装 PostgreSQL 17）。
func NewPostgres(opts Options) (*Server, error) {
	return newServer("postgresql", "PostgreSQL", "伪装版本 17", opts, pgTooMany, handlePostgres)
}

// handlePostgres 索取明文口令并捕获，无论凭证是什么一律返回 28P01 后断开。
func handlePostgres(c *conn) {
	user, ok := pgReadStartup(c.br, c.nc)
	if !ok {
		return // 非标准流量（取消请求/旧协议/缺用户名）：静默断开
	}

	// AuthenticationCleartextPassword：诱导客户端提交明文口令
	c.write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})

	password, err := pgReadPassword(c.br)
	if err != nil {
		return // 扫描器未提交口令或提前断开：静默忽略
	}
	if password == "" {
		password = "(空)"
	}
	c.srv.opts.Events.AuthAttempt(c.id, "postgresql", c.ip, user, password, false)

	c.write(pgErrorPacket("28P01",
		fmt.Sprintf("password authentication failed for user %q", user), "auth.c", "auth_failed"))
}

// pgReadStartup 读取启动阶段报文并返回 StartupMessage 中的用户名。
// 遇到 SSLRequest 先回 'N' 拒绝 TLS 后继续读取明文启动报文。
func pgReadStartup(r *bufio.Reader, w io.Writer) (string, bool) {
	body, err := pgReadMessage(r)
	if err != nil {
		return "", false
	}
	if len(body) == 4 {
		switch binary.BigEndian.Uint32(body) {
		case pgSSLRequest:
			// 不支持 SSL：客户端将以明文重新发送启动报文
			if _, err := w.Write([]byte{'N'}); err != nil {
				return "", false
			}
			if body, err = pgReadMessage(r); err != nil {
				return "", false
			}
		default:
			return "", false // CancelRequest / GSSENCRequest：静默断开
		}
	}
	if len(body) < 8 || binary.BigEndian.Uint32(body) != pgProtocolV3 {
		return "", false
	}

	// 参数区为 key\x00value\x00 序列，以单个 \x00 结束
	pos := 4
	for {
		keyEnd := bytes.IndexByte(body[pos:], 0)
		if keyEnd < 0 {
			return "", false
		}
		key := string(body[pos : pos+keyEnd])
		pos += keyEnd + 1

		valEnd := bytes.IndexByte(body[pos:], 0)
		if valEnd < 0 {
			return "", false
		}
		value := string(body[pos : pos+valEnd])
		pos += valEnd + 1

		if key == "user" {
			return value, true
		}
	}
}

// pgReadPassword 读取 PasswordMessage 并返回客户端提交的口令（剥离 NUL 终止符）。
func pgReadPassword(r *bufio.Reader) (string, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	body, err := pgReadMessage(r)
	if err != nil {
		return "", err
	}
	if typ != 'p' {
		return "", nil
	}
	if i := bytes.IndexByte(body, 0); i >= 0 {
		body = body[:i]
	}
	return string(body), nil
}

// pgReadMessage 读取一个启动阶段消息（无类型字节，4 字节长度含自身）。
func pgReadMessage(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(hdr[:]))
	if length < 4 || length > pgMaxMessageLength {
		return nil, errors.New("postgresql: 非法报文长度")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// pgErrorPacket 构造 ErrorResponse 完整协议帧（FATAL 级别）。
func pgErrorPacket(sqlstate, message, file, routine string) []byte {
	var b bytes.Buffer
	pgWriteField(&b, 'S', "FATAL")
	pgWriteField(&b, 'V', "FATAL")
	pgWriteField(&b, 'C', sqlstate)
	pgWriteField(&b, 'M', message)
	pgWriteField(&b, 'F', file)
	pgWriteField(&b, 'L', "327")
	pgWriteField(&b, 'R', routine)
	b.WriteByte(0) // 字段列表终止符

	payload := b.Bytes()
	pkt := make([]byte, 5+len(payload))
	pkt[0] = 'E' // ErrorResponse
	binary.BigEndian.PutUint32(pkt[1:], uint32(4+len(payload)))
	copy(pkt[5:], payload)
	return pkt
}

func pgWriteField(b *bytes.Buffer, code byte, value string) {
	b.WriteByte(code)
	b.WriteString(value)
	b.WriteByte(0)
}

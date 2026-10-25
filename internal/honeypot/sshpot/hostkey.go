package sshpot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// 默认与旧版 hostkey 位置：
//   - HostKeyPath 与 database.db 同目录，随 /app/db 卷持久化，容器重建不会导致指纹变化
//   - LegacyHostKeyPath 为 Java 1.2.x 的 /app/hostkey.ser，仅用于升级时接续
const (
	DefaultHostKeyPath       = "db/hostkey.ser"
	DefaultLegacyHostKeyPath = "hostkey.ser"
)

// loadOrCreateHostKey 按 plan 5.1 的五步顺序加载主机密钥：
//
//  1. 读新路径 db/hostkey.ser；
//  2. 不存在（或解析失败）时读旧路径 hostkey.ser，成功后复制到新路径，旧文件保留不删除，
//     便于回滚到 Java 版时继续使用同一指纹；
//  3. 两者都不可用：生成 ed25519 密钥写入新路径，权限 0600；
//  4. 文件存在但解析失败（Java 版 .ser 为 Java 序列化格式，Go 无法解析）：备份为
//     <路径>.bak 后按第 3 步处理，并打印醒目告警。
//
// 任何情况下都不使用临时密钥：否则指纹漂移且重启即变。
func loadOrCreateHostKey(path, legacyPath string, logger *slog.Logger) (ssh.Signer, error) {
	if signer, _, ok := tryLoadHostKey(path, logger); ok {
		return signer, nil
	}
	if signer, data, ok := tryLoadHostKey(legacyPath, logger); ok {
		if err := writeHostKey(path, data); err != nil {
			warnf(logger, fmt.Sprintf("旧 hostkey 复制到 %s 失败（本次仍使用旧密钥）: %v", path, err))
		} else {
			infof(logger, fmt.Sprintf("已从旧路径 %s 接续 hostkey 到 %s", legacyPath, path))
		}
		return signer, nil
	}

	signer, data, err := generateHostKey()
	if err != nil {
		return nil, err
	}
	if err := writeHostKey(path, data); err != nil {
		return nil, fmt.Errorf("生成 hostkey 后写入 %s 失败: %w", path, err)
	}
	infof(logger, fmt.Sprintf("已生成新的 ed25519 hostkey: %s（请确保 db 目录挂载持久化）", path))
	return signer, nil
}

// tryLoadHostKey 尝试读取并解析 hostkey；解析失败时备份为 <path>.bak。
func tryLoadHostKey(path string, logger *slog.Logger) (ssh.Signer, []byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			// 升级场景：Java 版以 root 运行时旧文件多为 root:600，容器用户 10001 无权读取，
			// 程序无法绕过权限，只能提示运维先放开权限，否则指纹会变化。
			warnf(logger, fmt.Sprintf("读取 hostkey %s 无权限（%v），本次将不使用该密钥；升级场景请先在宿主机执行 chown 10001:10001 %s 或 chmod 644 %s 后重启",
				path, err, path, path))
		} else if !os.IsNotExist(err) {
			warnf(logger, fmt.Sprintf("读取 hostkey %s 失败: %v", path, err))
		}
		return nil, nil, false
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		backup := path + ".bak"
		if rerr := os.Rename(path, backup); rerr != nil {
			warnf(logger, fmt.Sprintf("hostkey %s 解析失败（%v），备份到 %s 也失败: %v", path, err, backup, rerr))
		} else {
			warnf(logger, fmt.Sprintf("hostkey %s 解析失败（%v），已备份为 %s 并重新生成", path, err, backup))
		}
		return nil, nil, false
	}
	return signer, data, true
}

// generateHostKey 生成 ed25519 主机密钥，返回 signer 与其 PKCS#8 PEM 编码。
func generateHostKey() (ssh.Signer, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 ed25519 密钥失败: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("编码 ed25519 私钥失败: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("解析新生成的 hostkey 失败: %w", err)
	}
	return signer, data, nil
}

// writeHostKey 以 0600 权限落盘（目录不存在时创建）。
func writeHostKey(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

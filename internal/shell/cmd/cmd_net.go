package cmd

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"ssh-honeypot-go/internal/fakeenv"
	"ssh-honeypot-go/internal/shell"
)

// download wget/curl：典型恶意软件下载行为，重点记录 URL 并落地假文件。
//
// 选项必须与 URL 分开处理：`wget --version` 以前被当作下载 `--version` 记入
// downloads 表（Java 版同缺陷），既污染取证数据又露出"选项当 URL"的破绽。
func (p *Processor) download(st *shell.Session, args []string, isCurl bool) string {
	if v, ok := downloadMeta(args, isCurl); ok {
		return v
	}

	url := downloadURL(args)
	if url != "" {
		p.logDownload(st, url)
	}
	if url == "" {
		if isCurl {
			return "curl: no URL specified!"
		}
		return "wget: missing URL"
	}

	filename := "index.html"
	if i := strings.LastIndexByte(url, '/'); i >= 0 {
		if rest := url[i+1:]; rest != "" {
			filename = rest
		}
	}
	// -O /tmp/x（wget）与 -o /tmp/x（curl）指定保存路径，-P 指定目录
	saved := outputTarget(args, filename)
	if strings.HasSuffix(saved, "/") {
		saved += filename
	}
	// 在虚拟文件系统里「落地」一个假文件，让攻击者看到下载成功
	st.FS.Write(st.Cwd, saved, st.Username, "#!/bin/bash\n# binary payload placeholder\n")

	// -q / -s 静默模式：真实行为也是零输出
	if hasArg(args, "-q") || hasArg(args, "--quiet") || (isCurl && hasArg(args, "-s")) || hasArg(args, "--silent") {
		return ""
	}

	if isCurl {
		return "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n" +
			"                                 Dload  Upload   Total   Spent    Left  Speed\n" +
			"100  843k  100  843k    0     0  1287k      0 --:--:-- --:--:-- --:--:-- 1289k"
	}
	host := hostOf(url)
	now := time.Now()
	return "--" + now.Format(layoutDateTime) +
		"--  " + url + "\n" +
		"Resolving " + host + " (" + host + ")... " + fakeenv.WANIP + "\n" +
		"Connecting to " + host + " (" + host + ")|" + fakeenv.WANIP + "|:80... connected.\n" +
		"HTTP request sent, awaiting response... 200 OK\n" +
		"Length: 864512 (844K) [application/octet-stream]\n" +
		"Saving to: '" + saved + "'\n\n" +
		saved + "          100%[===================>] 844.25K  1.29MB/s    in 0.6s\n\n" +
		now.Format(layoutDateTime) +
		" (1.29 MB/s) - '" + saved + "' saved [864512/864512]"
}

// downloadURL 从参数里挑出下载 URL：优先 http(s)/ftp 前缀，其次含点的操作数；
// -O/-o/-P 的取值是本地路径，必须排除，否则 `wget -O /tmp/p.sh http://x/p.sh`
// 会把本地路径当成 URL。
func downloadURL(args []string) string {
	operands := nonFlags(args)
	for _, a := range operands {
		if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") || strings.HasPrefix(a, "ftp://") {
			return a
		}
	}
	skip := make(map[string]bool)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-O", "-o", "-P", "--output", "--output-document", "--directory-prefix":
			if i+1 < len(args) {
				skip[args[i+1]] = true
				i++
			}
		}
	}
	for _, a := range operands {
		if !skip[a] && strings.Contains(a, ".") {
			return a
		}
	}
	for i := len(operands) - 1; i >= 0; i-- {
		if !skip[operands[i]] {
			return operands[i]
		}
	}
	return ""
}

// downloadMeta 处理与下载无关的元信息开关（--version / --help），命中时 ok=true。
func downloadMeta(args []string, isCurl bool) (string, bool) {
	if hasArg(args, "--version") || hasArg(args, "-V") {
		if isCurl {
			return "curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0 OpenSSL/3.0.2 zlib/1.2.11 brotli/1.0.9 zstd/1.4.8 libidn2/2.3.2 libpsl/0.21.0 libssh/0.9.6 nghttp2/1.43.0 librtmp/2.3\n" +
				"Release-Date: 2022-01-05\n" +
				"Protocols: dict file ftp ftps gopher http https imap imaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smtp telnet tftp\n" +
				"Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO SSL TLS-SRP UnixSockets zstd", true
		}
		return "GNU Wget 1.21.2 built on linux-gnu.\n\n" +
			"-c, --continue            resume getting a partially-downloaded file.\n" +
			"    --progress=TYPE       select progress gauge type\n" +
			"-O, --output-document=FILE    write documents to FILE", true
	}
	if hasArg(args, "--help") || (isCurl && hasArg(args, "-h")) {
		if isCurl {
			return "Usage: curl [options...] <url>", true
		}
		return "GNU Wget 1.21.2, a non-interactive network retriever.\nUsage: wget [OPTION]... [URL]...", true
	}
	return "", false
}

// outputTarget 解析保存路径：-O/-o 指定文件，-P 指定目录（默认目录时拼上 URL 文件名）。
func outputTarget(args []string, filename string) string {
	out, dir := "", ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "--output-document" || a == "-o" || a == "--output":
			if i+1 < len(args) {
				i++
				out = args[i]
			}
		case a == "-P" || a == "--directory-prefix":
			if i+1 < len(args) {
				i++
				dir = args[i]
			}
		case strings.HasPrefix(a, "--output="):
			out = strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "--output-document="):
			out = strings.TrimPrefix(a, "--output-document=")
		case strings.HasPrefix(a, "--directory-prefix="):
			dir = strings.TrimPrefix(a, "--directory-prefix=")
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			out = a[2:]
		}
	}
	if out != "" {
		return out
	}
	if dir != "" {
		return strings.TrimSuffix(dir, "/") + "/" + filename
	}
	return filename
}

// hostOf 从 URL 提取主机名。
func hostOf(url string) string {
	h := url
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexByte(h, '/'); i > 0 {
		return h[:i]
	}
	return h
}

// ifconfig 输出网卡信息。
func (p *Processor) ifconfig() string {
	return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" +
		"        inet " + fakeenv.Eth0IP + "  netmask " + fakeenv.Eth0Netmask + "  broadcast " + fakeenv.Eth0Broadcast + "\n" +
		"        inet6 fe80::215:5dff:fe00:1a2b  prefixlen 64  scopeid 0x20<link>\n" +
		"        ether " + fakeenv.Eth0MAC + "  txqueuelen 1000  (Ethernet)\n" +
		"        RX packets 18492653  bytes 21412405712 (21.4 GB)\n" +
		"        RX errors 0  dropped 0  overruns 0  frame 0\n" +
		"        TX packets 15248931  bytes 8982341231 (8.9 GB)\n" +
		"        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n" +
		"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
		"        inet 127.0.0.1  netmask 255.0.0.0\n" +
		"        loop  txqueuelen 1000  (Local Loopback)"
}

// ipAddrText ip addr 输出。
const ipAddrText = "    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n" +
	"    inet 127.0.0.1/8 scope host lo\n" +
	"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n" +
	"    inet " + fakeenv.Eth0IP + "/24 brd " + fakeenv.Eth0Broadcast + " scope global eth0"

// ipCmd ip 命令：addr/route 本地伪造，其余交 AI。
func (p *Processor) ipCmd(st *shell.Session, cmdline string, args []string) string {
	if len(args) == 0 {
		return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"
	}
	switch args[0] {
	case "addr", "a":
		return ipAddrText
	case "route", "r":
		return "default via " + fakeenv.Gateway + " dev eth0 proto static\n" +
			"10.23.76.0/24 dev eth0 proto kernel scope link src " + fakeenv.Eth0IP
	}
	return p.aiFallbackSilent(st, cmdline)
}

// netstatText netstat/ss 输出。
const netstatText = "Active Internet connections (servers and established)\n" +
	"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
	"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" +
	"tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n" +
	"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n" +
	"tcp        0    288 " + fakeenv.Eth0IP + ":22          10.23.76.99:51220         ESTABLISHED\n" +
	"udp        0      0 0.0.0.0:68              0.0.0.0:*"

// ping 输出 100% 丢包（真实蜜罐/容器环境常见的对外探测结果）。
func (p *Processor) ping(args []string) string {
	host := firstNonFlag(args)
	if host == "" {
		return "ping: usage error: Destination address required"
	}
	return "PING " + host + " (" + fakeenv.WANIP + ") 56(84) bytes of data.\n" +
		"\n--- " + host + " ping statistics ---\n" +
		"4 packets transmitted, 0 received, 100% packet loss, time 3055ms"
}

// traceroute 输出两跳后超时。
func (p *Processor) traceroute(args []string) string {
	return "traceroute to " + firstNonFlag(args) + " (" + fakeenv.WANIP + "), 30 hops max\n" +
		" 1  " + fakeenv.Gateway + " (" + fakeenv.Gateway + ")  0.412 ms  0.389 ms  0.371 ms\n 2  * * *"
}

// dig 输出 DNS 查询结果。
func (p *Processor) dig(args []string) string {
	host := firstNonFlag(args)
	if host == "" {
		return "; <<>> DiG " + fakeenv.Dig + " <<>>\n;; global options: +cmd"
	}
	return "; <<>> DiG " + fakeenv.Dig + " <<>> " + host + "\n" +
		";; global options: +cmd\n" +
		";; Got answer:\n" +
		";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: " + strconv.Itoa(10000+rand.IntN(50000)) + "\n" +
		";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n" +
		";; QUESTION SECTION:\n;" + host + ".\t\t\t\tIN\tA\n\n" +
		";; ANSWER SECTION:\n" + host + ".\t\t54\tIN\tA\t" + fakeenv.WANIP + "\n\n" +
		";; Query time: " + strconv.Itoa(5+rand.IntN(40)) + " msec\n;; SERVER: " + fakeenv.DNS + "#53(" + fakeenv.DNS + ") (UDP)\n;; WHEN: " +
		time.Now().Format(layoutCTime) +
		"\n;; MSG SIZE  rcvd: 55"
}

// nslookup 输出 DNS 查询结果。
func (p *Processor) nslookup(args []string) string {
	host := firstNonFlag(args)
	if host == "" {
		return "> "
	}
	return "Server:\t\t" + fakeenv.DNS + "\nAddress:\t" + fakeenv.DNS + "#53\n\nNon-authoritative answer:\nName:\t" + host +
		"\nAddress: " + fakeenv.WANIP
}

// arpText arp 表。
const arpText = "Address                  HWtype  HWaddress           Flags Mask            Iface\n" +
	fakeenv.Gateway + "               ether   00:15:5d:00:1a:01   C                     eth0"

// routeText 路由表。
const routeText = "Kernel IP routing table\n" +
	"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n" +
	"default         _gateway        0.0.0.0         UG    100    0        0 eth0\n" +
	"10.23.76.0      0.0.0.0         255.255.255.0   U     100    0        0 eth0"

// remoteTimeout 外连类命令统一回连接超时（蜜罐不发起真实连接）。
func (p *Processor) remoteTimeout(name string, args []string) string {
	switch name {
	case "ssh":
		return "ssh: connect to host " + lastArg(args, "") + " port 22: Connection timed out"
	case "scp", "sftp":
		return name + ": connect to host " + lastArg(args, "") + " port 22: Connection timed out"
	default: // ftp / telnet
		return name + ": connect to address " + firstNonFlag(args) + ": Connection timed out"
	}
}

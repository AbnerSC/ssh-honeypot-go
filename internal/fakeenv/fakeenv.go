// Package fakeenv 蜜罐虚拟服务器环境画像：集中定义硬件、网络、系统与软件版本等「硬事实」。
//
// CommandProcessor 的本地命令输出与 AI 的 systemPrompt 都引用这里的常量，
// 保证攻击者用任意命令交叉验证（lscpu/free/ifconfig/dpkg -l/node -v ...）时口径一致，
// 不会因本地伪造输出与大模型仿真输出矛盾而识破蜜罐。
//
// 人设：一台全栈开发者的 Ubuntu 22.04 服务器，前后端/云原生开发工具链齐备；
// 渗透测试与流量分析类工具（nmap/hydra/sqlmap/tcpdump 等）未安装，
// 大模型对这些工具如实回 command not found，与蜜罐降级语义一致。
//
// 常量取值与 Java 版 org.open.scdm.honeypot.env.FakeEnv 逐字一致（硬契约）。
package fakeenv

import "strconv"

// 系统与内核

const (
	OSDesc      = "Ubuntu 22.04.3 LTS"
	OSRelease   = "22.04"
	OSCodename  = "jammy"
	Kernel      = "5.15.0-91-generic"
	KernelBuild = "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
	Arch        = "x86_64"
	BashVersion = "5.1.16(1)-release"
)

// 硬件

const (
	CPUModel   = "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz"
	CPUCount   = 4
	MemTotalH  = "7.8Gi"
	SwapTotalH = "2.0Gi"
	Uptime     = "47 days,  3:12"
	// DiskRootDev 根分区：80G 磁盘，已用 42%。
	DiskRootDev  = "/dev/sda1"
	DiskRootSize = "80G"
	// DiskDataDev 数据盘：100G 磁盘，挂载 /data，已用 19%。
	DiskDataDev  = "/dev/sdb1"
	DiskDataSize = "100G"
)

// 网络

const (
	Eth0IP        = "10.23.76.15"
	Eth0Netmask   = "255.255.255.0"
	Eth0Broadcast = "10.23.76.255"
	Eth0MAC       = "00:15:5d:00:1a:2b"
	// Gateway 网关：与 eth0 同网段（10.23.76.0/24），arp/route/traceroute 口径一致。
	Gateway = "10.23.76.1"
	DNS     = "10.0.0.2"
	// WANIP 所有外部域名统一解析到的地址（dig/nslookup/ping/wget/getent hosts 共用）。
	WANIP = "93.184.216.34"
	// ListenPorts 监听服务（netstat/ss/lsof 与 AI 口径一致）：sshd:22、nginx:80、mysqld:3306。
	ListenPorts = "sshd:22, nginx:80, mysqld:3306"
)

// 软件版本（本地命令输出与 AI 提示词共用）

const (
	Docker        = "24.0.7"
	DockerAPI     = "1.43"
	DockerCompose = "1.29.2"
	Git           = "2.34.1"
	Python        = "3.10.12"
	Pip           = "22.0.2+dfsg-1ubuntu0.4"
	Node          = "v20.11.0"
	Npm           = "10.2.4"
	Yarn          = "1.22.19"
	Go            = "go1.21.6"
	Rust          = "1.75.0"
	Cargo         = "cargo 1.75.0 (1d8b05cdd 2023-11-20)"
	Rustc         = "rustc 1.75.0 (82e1608df 2023-12-21)"
	Java          = "17.0.9"
	Maven         = "3.9.6"
	Gradle        = "8.5"
	PHP           = "8.1.2-1ubuntu2.14"
	Composer      = "2.6.6"
	Ruby          = "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233) [x86_64-linux-gnu]"
	Gem           = "3.3.5"
	Perl          = "v5.34.0"
	Lua           = "5.4.6"
	GCC           = "11.4.0"
	Make          = "4.3"
	CMake         = "3.22.1"
	Nginx         = "1.18.0"
	MySQL         = "8.0.35"
	OpenSSL       = "3.0.2"
	OpenSSH       = "8.9p1"
	Redis         = "6.0.16"
	Postgres      = "14.10"
	SQLite        = "3.37.2"
	Kubectl       = "v1.28.4"
	Apt           = "2.4.11"
	Busybox       = "v1.35.0"
	Dig           = "9.18.18-0ubuntu0.22.04.1-Ubuntu"
)

// AI 提示词用的软件清单

// Installed 已安装软件清单：全栈开发者工具链，大模型对这些命令仿真成功输出。
const Installed = "docker " + Docker + " (daemon running; one nginx:latest container named 'web', ID a1b2c3d4e5f6, up 3 weeks)" +
	", docker-compose " + DockerCompose +
	", git " + Git +
	", python3 " + Python + " with pip" +
	", node " + Node + " with npm " + Npm + " and yarn " + Yarn +
	", go " + Go +
	", rust " + Rust + " with cargo" +
	", openjdk " + Java + " with maven " + Maven + " and gradle " + Gradle +
	", php " + PHP + " with composer " + Composer +
	", ruby 3.0.2 with gem, perl 5.34, lua 5.4" +
	", gcc " + GCC + ", make " + Make + ", cmake " + CMake +
	", nginx " + Nginx +
	", mysql-server " + MySQL + " (running)" +
	", redis-server " + Redis + " (service stopped)" +
	", postgresql " + Postgres + " (service stopped)" +
	", sqlite3 " + SQLite +
	", kubectl " + Kubectl + " (installed, but no reachable cluster: most subcommands fail with connection refused)" +
	", openssh-server " + OpenSSH + ", openssl " + OpenSSL + ", snapd" +
	", curl, wget, vim, nano, jq, htop, tmux, screen" +
	", strace, ltrace, gdb, binutils" +
	", crontab, tar, zip, unzip, gzip, rsync, netcat (nc)"

// NotInstalled 未安装软件清单：渗透测试与流量分析工具，大模型对它们如实回 command not found。
const NotInstalled = "nmap, masscan, zmap, hydra, medusa, john, hashcat" +
	", sqlmap, nikto, gobuster, ffuf, dirb, wfuzz" +
	", tcpdump, tshark, wireshark, ettercap, arpspoof" +
	", metasploit, msfconsole, searchsploit, netcat variants beyond nc" +
	", flatpak, helm, terraform, ansible"

// FactsBlock 生成 systemPrompt 用的「Server facts」多行事实块。
//
// 全部由上述常量拼接，与 CommandProcessor 本地命令输出天然同源一致。
func FactsBlock() string {
	return "Server facts (keep every output strictly consistent with them):\n" +
		"- OS " + OSDesc + " (" + OSCodename + "), kernel " + Kernel + ", " + Arch + "; up " + Uptime + ".\n" +
		"- CPU " + strconv.Itoa(CPUCount) + "x " + CPUModel + ", " + MemTotalH + " RAM, " + SwapTotalH + " swap; " +
		DiskRootDev + " " + DiskRootSize + " on /, " + DiskDataDev + " " + DiskDataSize + " on /data.\n" +
		"- Network: eth0 " + Eth0IP + "/24 (MAC " + Eth0MAC + "), gateway " + Gateway + ", DNS " + DNS + "; " +
		"listening services: " + ListenPorts + "; every external hostname resolves to " + WANIP + ".\n" +
		"- Users: root(0), admin(1000), ubuntu(1001); sudo members: admin, ubuntu.\n" +
		"- Running processes: systemd, sshd, mysqld, nginx worker, cron.\n" +
		"- Installed: ALL standard Ubuntu/Linux utilities (coreutils, bash, util-linux, procps, iproute2, " +
		"findutils, grep, sed, awk, tar, gzip, curl, wget, git, ssh, sudo and similar) PLUS this full-stack " +
		"developer's toolchains: " + Installed + ". This list is illustrative, NOT exhaustive - treat any other " +
		"ordinary command-line tool, script or binary as present too.\n" +
		"- NOT installed (the ONLY commands that should ever yield 'command not found'): " + NotInstalled + ".\n"
}

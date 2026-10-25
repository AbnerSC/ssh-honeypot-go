package cmd

import (
	"regexp"
	"strings"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/fakeenv"
	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/shell"
)

// archiveExt 归档扩展名（解包时用于去掉后缀生成目录名）。
var archiveExt = regexp.MustCompile(`\.(tar(\.(gz|bz2|xz))?|tgz|zip)$`)

// apt 包管理输出（apt/apt-get/aptitude 复用）。
func (p *Processor) apt(args []string) string {
	if len(args) == 0 {
		return "apt " + fakeenv.Apt + " (amd64)"
	}
	if args[0] == "update" {
		return "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n" +
			"Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]\n" +
			"Get:3 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]\n" +
			"Fetched 229 kB in 1s (205 kB/s)\nReading package lists... Done"
	}
	return "Reading package lists... Done\nBuilding dependency tree... Done\n0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded."
}

// yum yum/dnf 输出。
func (p *Processor) yum(args []string) string {
	if len(args) == 0 {
		return "Loaded plugins: fastestmirror\nYou need to give some command"
	}
	return "Loaded plugins: fastestmirror\nLoading mirror speeds from cached hostfile\nNo packages marked for update"
}

// dpkg dpkg/rpm 输出（-l 列出已装包）。
func (p *Processor) dpkg(args []string) string {
	if len(args) > 0 && args[0] == "-l" {
		return "Desired=Unknown/Install/Remove/Purge/Hold\n" +
			"| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n" +
			"||/ Name           Version          Architecture Description\n" +
			"+++-==============-================-============-=================================\n" +
			"ii  bash           5.1-6ubuntu1     amd64        GNU Bourne Again SHell\n" +
			"ii  openssh-server 1:" + fakeenv.OpenSSH + "-3ubuntu0 amd64        secure shell (SSH) server\n" +
			"ii  mysql-server   " + fakeenv.MySQL + "-0ubuntu0. amd64        MySQL database server (metapackage)"
	}
	return "dpkg: error: need an action option"
}

// systemctl 服务管理输出；stop/disable 记录为危险操作。
func (p *Processor) systemctl(st *shell.Session, args []string) string {
	if len(args) == 0 || args[0] == "status" {
		unit := ""
		if len(args) > 1 {
			unit = args[len(args)-1]
		}
		if unit == "" {
			return ""
		}
		return "● " + unit + "\n     Loaded: loaded (/lib/systemd/system/" + unit + "; enabled; vendor preset: enabled)\n" +
			"     Active: active (running) since Mon 2026-06-24 06:13:02 UTC; 1 months 17 days ago\n" +
			"   Main PID: 519 (" + strings.ReplaceAll(unit, ".service", "") + ")\n" +
			"      Tasks: 12 (limit: 4662)\n     Memory: 45.2M\n        CPU: 1min 22.4s\n" +
			"     CGroup: /system.slice/" + unit
	}
	switch args[0] {
	case "list-units", "list":
		return "  UNIT                    LOAD   ACTIVE SUB     DESCRIPTION\n" +
			"  ssh.service             loaded active running OpenBSD Secure Shell server\n" +
			"  mysql.service           loaded active running MySQL Community Server\n" +
			"  nginx.service           loaded active running A high performance web server\n" +
			"  cron.service            loaded active running Regular background program processing daemon"
	case "is-active":
		return "active"
	case "is-enabled":
		return "enabled"
	case "daemon-reload", "start", "restart", "enable":
		return ""
	case "stop", "disable":
		p.logCommand(st, "[危险操作] systemctl "+strings.Join(args, " "))
		return ""
	}
	return ""
}

// service 服务管理输出。
func (p *Processor) service(args []string) string {
	if len(args) >= 2 && args[len(args)-1] == "status" {
		return " * " + args[0] + " is running"
	}
	return ""
}

// journalctl 输出内核与登录日志。
func (p *Processor) journalctl() string {
	return "-- Journal begins at Mon 2026-06-24 06:13:02 UTC, ends at " +
		time.Now().Format(layoutDateTime) + " UTC. --\n" +
		"Aug 11 06:25:01 " + p.hostname + " systemd[1]: Started Session 42 of user root.\n" +
		"Aug 11 06:25:03 " + p.hostname + " sshd[21841]: Accepted password for root from 203.0.113.44 port 51220 ssh2"
}

// crontab 定时任务输出（-l 列出，其余交 AI）。
func (p *Processor) crontab(st *shell.Session, cmdline string, args []string) string {
	if len(args) == 0 {
		return "usage error: file name must be specified for replace"
	}
	if args[0] == "-l" {
		return "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n" +
			"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )"
	}
	return p.aiFallbackSilent(st, cmdline)
}

// tar 打包/解包：只在虚拟文件系统里制造后果，不触碰真实文件。
func (p *Processor) tar(st *shell.Session, args []string) string {
	extract := hasShort(args, 'x')
	create := hasShort(args, 'c')
	operands := nonFlags(args)
	if !extract && !create {
		return "tar: You must specify one of the `-Acdtrux', `--delete' or `--test-label' options"
	}
	if len(operands) == 0 {
		return "tar: Cowardly refusing to create an empty archive"
	}
	archive := operands[0]
	if extract {
		// 假装解包成功：在 cwd 造一个同名目录（去掉扩展名）
		dirName := archiveExt.ReplaceAllString(archive, "")
		if dirName != "" && st.FS.Resolve(st.Cwd, dirName) == nil {
			st.FS.Mkdir(st.Cwd, dirName, st.Username)
		}
		return ""
	}
	// 打包：源文件必须存在（通配符除外）
	for _, src := range operands[1:] {
		if strings.Contains(src, "*") || src == "." {
			continue
		}
		if st.FS.Resolve(st.Cwd, src) == nil {
			return "tar: " + src + ": Cannot stat: No such file or directory\n" +
				"tar: Exiting with failure status due to previous errors"
		}
	}
	// 落地一个假归档文件
	st.FS.Write(st.Cwd, archive, st.Username, "\x1f\x8b\x08\x00(fake archive)")
	return ""
}

// unzip 解包输出。
func (p *Processor) unzip(st *shell.Session, args []string) string {
	file := firstNonFlag(args)
	if file == "" {
		return "UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.\n\n" +
			"Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]"
	}
	if st.FS.Resolve(st.Cwd, file) == nil {
		return "unzip:  cannot find or open " + file + ", " + file + ".zip or " + file + ".ZIP."
	}
	return "Archive:  " + file + "\n   creating: app/\n  inflating: app/main\n  inflating: app/README.md"
}

// mountText 挂载表。
const mountText = fakeenv.DiskRootDev + " on / type ext4 (rw,relatime,errors=remount-ro)\n" +
	"proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n" +
	"sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n" +
	"tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n" +
	fakeenv.DiskDataDev + " on /data type ext4 (rw,relatime)"

// lsblkText 块设备列表。
const lsblkText = "NAME    MAJ:MIN RM SIZE RO TYPE MOUNTPOINT\n" +
	"sda       8:0    0  " + fakeenv.DiskRootSize + "  0 disk\n" +
	"└─sda1    8:1    0  " + fakeenv.DiskRootSize + "  0 part /\n" +
	"sdb       8:16   0 " + fakeenv.DiskDataSize + "  0 disk\n" +
	"└─sdb1    8:17   0 " + fakeenv.DiskDataSize + "  0 part /data"

// lsofText 打开的文件列表。
const lsofText = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n" +
	"systemd     1 root  cwd    DIR    8,1     4096    2 /\n" +
	"sshd      412 root    3u  IPv4  21841      0t0  TCP *:22 (LISTEN)\n" +
	"mysqld    519 mysql  21u  IPv4  24132      0t0  TCP *:3306 (LISTEN)\n" +
	"nginx     803 www    6u  IPv4  22901      0t0  TCP *:80 (LISTEN)\n" +
	"bash    21850 root  cwd    DIR    8,1     4096  524289 /root"

// fdiskText 分区表。
const fdiskText = "Disk /dev/sda: 80 GiB, 85899345920 bytes, 167772160 sectors\n" +
	"Disk model: Virtio Block Dev\nUnits: sectors of 1 * 512 = 512 bytes\n\n" +
	"Device     Boot Start       End   Sectors Size Id Type\n" +
	fakeenv.DiskRootDev + "  *     2048 167772159 167770112  80G 83 Linux"

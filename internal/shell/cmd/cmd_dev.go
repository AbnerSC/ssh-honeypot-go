package cmd

import (
	"strconv"
	"strings"

	"ssh-honeypot-go/internal/fakeenv"
	"ssh-honeypot-go/internal/shell"
)

// isVersionQuery 是否包含版本查询参数。
func isVersionQuery(args []string) bool {
	for _, a := range args {
		switch a {
		case "-v", "-V", "--version", "version", "-version":
			return true
		}
	}
	return false
}

// devToolVersion 开发工具版本查询：输出与 FakeEnv 常量（AI 提示词同源）严格一致。
// 非版本查询返回 ok=false，由调用方继续处理。
func devToolVersion(name string, args []string) (string, bool) {
	if !isVersionQuery(args) {
		return "", false
	}
	switch name {
	case "git":
		return "git version " + fakeenv.Git, true
	case "python", "python3":
		return "Python " + fakeenv.Python, true
	case "pip", "pip3":
		return "pip " + fakeenv.Pip + " from /usr/lib/python3/dist-packages/pip (python 3.10)", true
	case "node":
		return fakeenv.Node, true
	case "npm":
		return fakeenv.Npm, true
	case "yarn":
		return fakeenv.Yarn, true
	case "go":
		return "go version " + fakeenv.Go + " linux/amd64", true
	case "cargo":
		return fakeenv.Cargo, true
	case "rustc":
		return fakeenv.Rustc, true
	case "javac":
		return "javac " + fakeenv.Java, true
	case "java":
		return "openjdk version \"" + fakeenv.Java + "\" 2023-10-17\n" +
			"OpenJDK Runtime Environment (build " + fakeenv.Java + "+9-Ubuntu-122.04)\n" +
			"OpenJDK 64-Bit Server VM (build " + fakeenv.Java + "+9-Ubuntu-122.04, mixed mode, sharing)", true
	case "mvn":
		return "Apache Maven " + fakeenv.Maven + " (bc0240f3c744dd6b6ec292087cd0f8173e3c8c47)\n" +
			"Maven home: /usr/share/maven\nJava version: " + fakeenv.Java +
			", vendor: Ubuntu, runtime: /usr/lib/jvm/java-17-openjdk-amd64\n" +
			"Default locale: en_US, platform encoding: UTF-8\n" +
			"OS name: \"linux\", version: \"" + fakeenv.Kernel + "\", arch: \"amd64\"", true
	case "gradle":
		return "Gradle " + fakeenv.Gradle + "\n\nBuild time:   2023-11-29 14:00:00 UTC\n" +
			"JVM:          " + fakeenv.Java + " (Ubuntu " + fakeenv.Java + "+9-Ubuntu-122.04)\n" +
			"OS:           Linux " + fakeenv.Kernel + " amd64", true
	case "php":
		return "PHP " + fakeenv.PHP + " (cli) (built: Nov  9 2023 15:16:18) ( NTS )\n" +
			"Copyright (c) The PHP Group\nZend Engine v4.1.2, Copyright (c) Zend Technologies", true
	case "composer":
		return "Composer version " + fakeenv.Composer + " 2023-12-08 14:14:57", true
	case "ruby":
		return fakeenv.Ruby, true
	case "gem":
		return fakeenv.Gem, true
	case "perl":
		return "This is perl 5, version 34, subversion 0 (" + fakeenv.Perl + ") built for x86_64-linux-gnu-thread-multi", true
	case "lua":
		return "Lua " + fakeenv.Lua + "  Copyright (C) 1994-2023 Lua.org, PUC-Rio", true
	case "gcc", "cc", "g++":
		return name + " (Ubuntu " + fakeenv.GCC + "-1ubuntu1~22.04) " + fakeenv.GCC + "\n" +
			"Copyright (C) 2021 Free Software Foundation, Inc.\n" +
			"This is free software; see the source for copying conditions.  There is NO\n" +
			"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.", true
	case "make":
		return "GNU Make " + fakeenv.Make + "\nBuilt for x86_64-pc-linux-gnu\n" +
			"Copyright (C) 1988-2022 Free Software Foundation, Inc.", true
	case "cmake":
		return "cmake version " + fakeenv.CMake + "\n\nCMake suite maintained and supported by Kitware (kitware.com/cmake).", true
	case "mysql", "mariadb":
		return "mysql  Ver 8.0.35-0ubuntu0.22.04.2 for Linux on x86_64 ((Ubuntu))", true
	case "psql":
		return "psql (PostgreSQL) " + fakeenv.Postgres + " (Ubuntu " + fakeenv.Postgres + "-0ubuntu0.22.04.1)", true
	case "redis-cli":
		return "redis-cli " + fakeenv.Redis, true
	case "sqlite3":
		return fakeenv.SQLite + " 2021-12-01 19:27:38 1f1c0102e6b2f4e1f4a1e0e6d0a1e2e3f4a5b6c7d8e9f0a1b2c3d4e5f6071829", true
	case "kubectl":
		return "Client Version: " + fakeenv.Kubectl + "\nKustomize Version: v5.0.4-0.20230601165947-6ce0bf390ce3", true
	case "docker-compose":
		return "Docker Compose version " + fakeenv.DockerCompose, true
	}
	return "", false
}

// devToolOrAi 开发工具统一入口：版本查询走本地常量，其余交 AI 仿真（不可用时空串）。
func (p *Processor) devToolOrAi(st *shell.Session, cmdline, name string, args []string) string {
	if v, ok := devToolVersion(name, args); ok {
		return v
	}
	return p.aiFallbackSilent(st, cmdline)
}

// interpreter 解释器类命令：版本查询 → 本地常量；无参 → 交互式静默挂起；其余交 AI。
func (p *Processor) interpreter(st *shell.Session, cmdline, name string, args []string) string {
	if v, ok := devToolVersion(name, args); ok {
		return v
	}
	if len(args) == 0 {
		return "" // 交互式解释器：静默挂起（真实终端行为）
	}
	return p.aiFallbackSilent(st, cmdline)
}

// python python/python3：重点记录 -c 一行式与脚本执行（常见反弹 shell 载荷）。
func (p *Processor) python(st *shell.Session, cmdline string, args []string) string {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			p.logCommand(st, "[可疑脚本] python -c "+args[i+1])
			return p.aiFallbackSilent(st, cmdline)
		}
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && strings.HasSuffix(args[0], ".py") {
		if st.FS.Resolve(st.Cwd, args[0]) == nil {
			return "python3: can't open file '" + args[0] + "': [Errno 2] No such file or directory"
		}
		p.logCommand(st, "[可疑脚本] python "+args[0])
		return p.aiFallbackSilent(st, cmdline)
	}
	if hasArg(args, "--version") || hasArg(args, "-V") {
		return "Python " + fakeenv.Python
	}
	return "" // 交互模式静默挂起
}

// javaCmd java：无参按 -version 处理；其余交 AI 仿真。
func (p *Processor) javaCmd(st *shell.Session, cmdline string, args []string) string {
	if len(args) == 0 {
		args = []string{"-version"}
	}
	if v, ok := devToolVersion("java", args); ok {
		return v
	}
	return p.aiFallbackSilent(st, cmdline)
}

// lscpu 输出 CPU 信息。
func (p *Processor) lscpu() string {
	return "Architecture:            " + fakeenv.Arch + "\n" +
		"  CPU op-mode(s):        32-bit, 64-bit\n" +
		"  Address sizes:         46 bits physical, 48 bits virtual\n" +
		"  Byte Order:            Little Endian\n" +
		"CPU(s):                  " + strconv.Itoa(fakeenv.CPUCount) + "\n" +
		"  On-line CPU(s) list:   0-3\n" +
		"Vendor ID:               GenuineIntel\n" +
		"  Model name:            " + fakeenv.CPUModel + "\n" +
		"    CPU family:          6\n" +
		"    Model:               106\n" +
		"    Thread(s) per core:  2\n" +
		"    Core(s) per socket:  2\n" +
		"    Socket(s):           1\n" +
		"    CPU max MHz:         2900.0000\n" +
		"Virtualization features:\n" +
		"  Hypervisor vendor:     Microsoft\n" +
		"  Virtualization type:   full"
}

// docker docker 常用子命令输出，其余交 AI。
func (p *Processor) docker(st *shell.Session, cmdline string, args []string) string {
	if len(args) == 0 {
		return "Usage:  docker [OPTIONS] COMMAND"
	}
	switch args[0] {
	case "ps", "container":
		return "CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS     NAMES\n" +
			"a1b2c3d4e5f6   nginx:latest   \"/docker-entrypoint.…\"   3 weeks ago    Up 3 weeks    80/tcp    web"
	case "images":
		return "REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\nnginx        latest    61395b4c586d   3 weeks ago    187MB"
	case "version":
		return "Client: Docker Engine - Community\n Version:           " + fakeenv.Docker +
			"\n API version:       " + fakeenv.DockerAPI + "\n Go version:        go1.20.10"
	}
	// pull/run/build/info/logs/exec/inspect/stats/network/volume/system 等交 AI 仿真
	return p.aiFallbackSilent(st, cmdline)
}

// kubectl kubectl 输出：版本查询走常量，pods 列表本地伪造，其余回连接失败。
func (p *Processor) kubectl(st *shell.Session, cmdline string, args []string) string {
	if v, ok := devToolVersion("kubectl", args); ok {
		return v
	}
	if len(args) == 0 {
		return "kubectl controls the Kubernetes cluster manager."
	}
	if args[0] == "get" && hasArg(args, "pods") {
		return "NAME                     READY   STATUS    RESTARTS   AGE\nweb-6d9f5b7c8-x2k4p      1/1     Running   0          12d"
	}
	return "The connection to the server localhost:8080 was refused - did you specify the right host or port?"
}

// dbClientArgs 解析数据库客户端参数里的用户名。
func dbClientArgs(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-u" || args[i] == "--user" {
			return args[i+1]
		}
	}
	return "root"
}

// Command honeypot 是 SSH/Telnet/MySQL/PostgreSQL/Redis 蜜罐的进程入口。
//
// 用法:
//
//	honeypot [选项]
//
// 选项:
//
//	-c, --config <file>   YAML 配置文件路径（默认 config.yaml）
//	-h, --help            显示帮助
//	    -version          显示版本信息后退出
//	    -health           探测监听端口后退出（供容器 HEALTHCHECK 使用）
//	    check-db          只读自检数据库（版本号 + 7 张表行数）后退出
//
// 生产部署提示：容器内所有端口均大于 1024，无需 root 或任何 capability，
// 运行身份由 docker-compose 的 user: 指定（推荐 10001:10001）。
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"ssh-honeypot-go/internal/ai"
	"ssh-honeypot-go/internal/attacklog"
	"ssh-honeypot-go/internal/auth"
	"ssh-honeypot-go/internal/config"
	"ssh-honeypot-go/internal/geo"
	"ssh-honeypot-go/internal/honeypot/dbpot"
	"ssh-honeypot-go/internal/honeypot/sshpot"
	"ssh-honeypot-go/internal/honeypot/telnetpot"
	"ssh-honeypot-go/internal/shell/cmd"
	versioninfo "ssh-honeypot-go/internal/version"
	"ssh-honeypot-go/internal/vfs"
	"ssh-honeypot-go/internal/web"
)

// 构建信息由 -ldflags "-X main.version=... -X main.commit=... -X main.buildAt=..." 注入。
var (
	version = versioninfo.Default
	commit  = "none"
	buildAt = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run 解析参数并分派子命令，返回进程退出码。
func run(args []string) int {
	opts := parseArgs(args)

	switch {
	case opts.help:
		printUsage(os.Stdout)
		return 0
	case opts.showVersion:
		fmt.Println(versioninfo.New(version, commit, buildAt).String())
		return 0
	case opts.health:
		// 健康检查不初始化日志与存储，避免探针探测污染蜜罐链路
		cfg, err := config.Load(opts.configPath, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "健康检查加载配置失败: %v\n", err)
			return 1
		}
		return runHealth(cfg)
	case opts.checkDB:
		// 升级前自检：只读打开数据库，不建表、不写入
		cfg, err := config.Load(opts.configPath, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "数据库自检加载配置失败: %v\n", err)
			return 1
		}
		return runCheckDB(cfg, os.Stdout)
	}

	return serve(opts.configPath)
}

// serve 启动蜜罐主进程，阻塞直到收到 SIGINT/SIGTERM。
func serve(configPath string) int {
	logger := newLogger(slog.LevelInfo)

	// 首行固定输出运行身份：非 root 部署排查挂载卷权限时首先看这一行
	uid, gid := os.Getuid(), os.Getgid()
	logger.Info(fmt.Sprintf("运行身份 uid=%d gid=%d", uid, gid))

	cfg, err := config.Load(configPath, logger)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	hostname := cfg.ResolveHostname()

	printBanner()

	if err := preflight(cfg, logger); err != nil {
		logger.Error(err.Error())
		logger.Error(fmt.Sprintf("请修复目录属主后重试: sudo chown -R %d:%d %s",
			uid, gid, strings.Join(requiredDirs(cfg), " ")))
		return 1
	}

	logger.Info(fmt.Sprintf("配置摘要: %s, 主机名=%s, 日志=%s, 数据库=%s",
		summarizeServices(cfg), hostname,
		absPath(cfg.Log.File), absPath(cfg.Log.DB)))

	// 启动顺序（plan 5.10）：VFS → geo → attacklog/store → auth → 协议监听
	fs := vfs.New(hostname)
	locator := geo.Load(logger)
	defer locator.Close()

	events, err := attacklog.New(cfg.Log.File, cfg.Log.DB, locator, logger)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	defer events.Close()

	guard := auth.New(cfg.Auth.Passwords(), cfg.Auth.MaxFailures,
		cfg.Auth.WindowMinutes, cfg.Auth.LockMinutes, events, logger)
	processor := cmd.New(events, hostname)

	// AI 命令仿真：未启用或关键配置缺失时为 nil，未知命令全部走本地兜底。
	// 所有失败路径（超时/并发打满/熔断）均立即降级，不阻塞会话线程。
	if aiClient := ai.New(ai.Config{
		Enabled:          cfg.AI.Enabled,
		BaseURL:          cfg.AI.BaseURL,
		APIKey:           cfg.AI.APIKey,
		ModelName:        cfg.AI.ModelName,
		EnableThinking:   cfg.AI.EnableThinking,
		TimeoutSeconds:   cfg.AI.TimeoutSeconds,
		MaxOutputChars:   cfg.AI.MaxOutputChars,
		MaxConcurrent:    cfg.AI.MaxConcurrent,
		FailureThreshold: cfg.AI.FailureThreshold,
		CooldownSeconds:  cfg.AI.CooldownSeconds,
	}, logger); aiClient != nil {
		defer aiClient.Close()
		processor.SetAI(aiClient)
	}

	var sshServer *sshpot.Server
	if cfg.SSH.Enabled {
		srv, err := sshpot.New(sshpot.Options{
			Addr:      fmt.Sprintf(":%d", cfg.SSH.Port),
			FS:        fs,
			Events:    events,
			Guard:     guard,
			Hostname:  hostname,
			Processor: processor,
			Logger:    logger,
		})
		if err != nil {
			logger.Warn("SSH 蜜罐启动失败，继续启动其它服务: " + err.Error())
		} else if err := srv.Start(); err != nil {
			logger.Warn(err.Error())
		} else {
			sshServer = srv
		}
	}

	var telnetServer *telnetpot.Server
	if cfg.Telnet.Enabled {
		srv, err := telnetpot.New(telnetpot.Options{
			Addr:      fmt.Sprintf(":%d", cfg.Telnet.Port),
			FS:        fs,
			Events:    events,
			Guard:     guard,
			Hostname:  hostname,
			Processor: processor,
			Logger:    logger,
		})
		if err != nil {
			logger.Warn("Telnet 蜜罐启动失败，继续启动其它服务: " + err.Error())
		} else if err := srv.Start(); err != nil {
			logger.Warn(err.Error())
		} else {
			telnetServer = srv
		}
	}

	// startDB 按配置启动一个数据库蜜罐：单协议故障不影响其它协议
	startDB := func(name string, svc config.Service, ctor func(dbpot.Options) (*dbpot.Server, error)) *dbpot.Server {
		if !svc.Enabled {
			return nil
		}
		srv, err := ctor(dbpot.Options{
			Addr:   fmt.Sprintf(":%d", svc.Port),
			Events: events,
			Logger: logger,
		})
		if err != nil {
			logger.Warn(name + " 蜜罐启动失败，继续启动其它服务: " + err.Error())
			return nil
		}
		if err := srv.Start(); err != nil {
			logger.Warn(err.Error())
			return nil
		}
		return srv
	}
	mysqlServer := startDB("MySQL", cfg.MySQL, dbpot.NewMySQL)
	postgresServer := startDB("PostgreSQL", cfg.PostgreSQL, dbpot.NewPostgres)
	redisServer := startDB("Redis", cfg.Redis, dbpot.NewRedis)

	// Web 控制台依赖 SQLite（统计/用户/审计均存库），数据库不可用时不启动
	var webServer *web.Server
	if cfg.Web.Enabled {
		if !events.Healthy() {
			logger.Warn("数据库不可用，Web 控制台未启动")
		} else {
			srv, err := web.New(web.Options{
				Addr:                  fmt.Sprintf(":%d", cfg.Web.Port),
				DBPath:                cfg.Log.DB,
				SessionTimeoutMinutes: cfg.Web.SessionTimeoutMinutes,
				TrustedProxies:        cfg.Web.TrustedProxies,
				Locator:               locator,
				Logger:                logger,
			})
			if err != nil {
				logger.Warn("Web 控制台启动失败，蜜罐服务继续运行: " + err.Error())
			} else if err := srv.Start(); err != nil {
				logger.Warn(err.Error())
				_ = srv.Close()
			} else {
				webServer = srv
			}
		}
	}

	logger.Info("按 Ctrl+C 停止。")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("正在关闭蜜罐...")
	if sshServer != nil {
		_ = sshServer.Close()
	}
	if telnetServer != nil {
		_ = telnetServer.Close()
	}
	if mysqlServer != nil {
		_ = mysqlServer.Close()
	}
	if postgresServer != nil {
		_ = postgresServer.Close()
	}
	if redisServer != nil {
		_ = redisServer.Close()
	}
	// Web 控制台持有数据库读连接与审计写队列，必须在 events.Close（关库）之前停止
	if webServer != nil {
		if err := webServer.Close(); err != nil {
			logger.Warn(err.Error())
		}
	}
	if err := events.Close(); err != nil {
		logger.Warn(err.Error())
	}
	return 0
}

// options 命令行选项。
type options struct {
	configPath  string
	help        bool
	showVersion bool
	health      bool
	checkDB     bool
}

// parseArgs 解析命令行参数。未知参数仅告警不退出，与 Java 版行为一致。
func parseArgs(args []string) options {
	opts := options{configPath: config.DefaultConfigFile}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-c", arg == "--config":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "参数 %s 缺少文件路径\n", arg)
				continue
			}
			i++
			opts.configPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			opts.configPath = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-c="):
			opts.configPath = strings.TrimPrefix(arg, "-c=")
		case arg == "-h", arg == "--help":
			opts.help = true
		case arg == "-version", arg == "--version":
			opts.showVersion = true
		case arg == "-health", arg == "--health":
			opts.health = true
		case arg == "check-db", arg == "-check-db", arg == "--check-db":
			opts.checkDB = true
		default:
			fmt.Fprintf(os.Stderr, "未知参数: %s\n", arg)
		}
	}
	if strings.TrimSpace(opts.configPath) == "" {
		opts.configPath = config.DefaultConfigFile
	}
	return opts
}

func printUsage(w *os.File) {
	fmt.Fprintf(w, `用法: honeypot [选项] [check-db]
  -c, --config <file>   YAML 配置文件路径（默认 %s）
  -h, --help            显示帮助
      -version          显示版本信息
      -health           探测监听端口后退出（供容器健康检查）
      check-db          只读自检数据库：版本号 + 7 张表行数（升级前使用）
`, config.DefaultConfigFile)
}

// printBanner 输出启动横幅，保留 Java 版行文并标注 Go 运行时版本。
func printBanner() {
	info := versioninfo.New(version, commit, buildAt)
	fmt.Fprintf(os.Stdout, `
================================================
  SSH/Telnet/DB 蜜罐  v%s  (Go %s)
  仅用于安全研究与授权环境，请勿用于非法用途
================================================

`, info.Version, info.GoVersion)
}

// requiredDirs 返回需要运行身份可写的目录（去重、保持顺序），用于打印权限修复命令。
func requiredDirs(cfg *config.Config) []string {
	candidates := []string{
		filepath.Dir(cfg.Log.File),
		filepath.Dir(cfg.Log.DB),
		// hostkey 与 database.db 同目录，必须可写（否则重启后 SSH 指纹漂移）
		filepath.Dir(sshpot.DefaultHostKeyPath),
	}
	seen := make(map[string]bool, len(candidates))
	dirs := make([]string, 0, len(candidates))
	for _, dir := range candidates {
		if dir == "" {
			dir = "."
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	return dirs
}

// preflight 校验日志目录与数据库目录对当前运行身份可写。
// 不满足时立即失败并提示修复命令，禁止静默降级（否则日志丢失且 hostkey 每次重启都变）。
func preflight(cfg *config.Config, logger *slog.Logger) error {
	for _, dir := range requiredDirs(cfg) {
		if err := ensureWritableDir(dir); err != nil {
			return fmt.Errorf("目录 %s 不可写（uid=%d gid=%d）: %w",
				absPath(dir), os.Getuid(), os.Getgid(), err)
		}
		logger.Info("目录可写: " + absPath(dir))
	}
	return nil
}

// ensureWritableDir 目录不存在时创建（0755），并实际创建临时文件验证可写。
func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".permcheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

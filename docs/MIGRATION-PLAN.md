# NetGazer SSH 蜜罐 Java → Go 迁移技术方案

| 项目 | 内容 |
| --- | --- |
| 源项目 | `ssh-honeypot-j`（Java 25 / Maven，版本 1.2.1，仓库 `D:\idea-workspace\ssh-honeypot-j`） |
| 目标项目 | `ssh-honeypot-go`（Go，版本从 `2.0.0` 起，仓库 `D:\goland-workspace\ssh-honeypot-go`） |
| 工程范式参考 | `ssh-tunnel-go`（Dockerfile / `docker-entrypoint.sh` / Gitea Actions / GitHub Actions） |
| 迁移策略 | 契约优先的等价重写：对外可观测行为保持一致，内部实现按 Go 特性重写 |
| 发布方式 | 镜像名 `ssh-honeypot-j` 保持不变，`docker compose pull && up -d` 即完成升级 |
| 文档状态 | 方案基线（本文件为实施与评审的唯一依据） |

---

## 1. 目标与已确定决策

### 1.1 迁移目标

在**不改动运维侧 compose 文件、不影响历史数据、不改变对外协议与接口**的前提下，用 Go 重写 NetGazer 蜜罐的全部功能，并显著降低资源占用（Java 受限堆 160MB / 常驻约 240MB → Go 目标常驻 ≤ 40MB）。同时将容器运行身份从 root 收敛为非特权账号，具体 UID/GID 由 `docker-compose.yaml` 的 `user:` 指定（镜像默认 10001），降低容器漏洞逃逸到宿主机的风险。

### 1.2 已确定决策（本方案的硬约束）

| 编号 | 决策 | 落地要求 |
| --- | --- | --- |
| D1 | 镜像名保持 `ssh-honeypot-j` | Docker Hub 继续使用 `babyfly/ssh-honeypot-j`，Nexus 继续使用 `scdm/ssh-honeypot-j`；Go 版只新增版本号 tag，不新建镜像仓库、不改 compose |
| D2 | Go 版本从 `2.0.0` 开始 | 首个 tag `release-v2.0.0` → 镜像 `2.0.0` + `latest`；Java 最后一个版本 `1.2.1` 的镜像必须长期保留作为回滚目标 |
| D3 | 功能一致，实现方式按 Go 特性灵活调整 | 一致性按第 2 章分级：硬契约（配置/数据/API/协议主要交互/日志事件）必须一致；软契约（输出文案细节、内部标记、并发模型）允许等价实现；实现细节允许差异 |
| D4 | 容器与 CI 参考 `ssh-tunnel-go` | 多阶段构建（`golang:1.27-bookworm` → `debian:bookworm-slim`）、`CGO_ENABLED=0` 静态二进制、`GOPROXY`/`APT_MIRROR`/`DOCKER_PROXY` 构建注入、ldflags 版本注入、内置 `-health` 子命令、Gitea 推 Nexus（amd64）、GitHub 推 Docker Hub（amd64+arm64） |
| D5 | 方案文档入库 | 即本文件，后续实现偏离需在此登记变更 |
| D6 | **禁止 root 运行，身份由 compose 指定** | 执行用户与组由 `docker-compose.yaml` 的 `user: "10001:10001"` 固定声明（与镜像默认一致、与宿主机卷属主对齐）；镜像保留 `USER 10001:10001` 仅作 `docker run` 的兜底默认；禁止 `user: "0:0"` / `user: root`；不使用"root 启动再降权"方案 |

### 1.3 非目标

- 不引入新的诱捕协议（Http/Nginx 仍为未实现项）。
- 不改变 SQLite 单文件 + JSONL 双写的数据架构。
- 不重写前端页面（Java 版前端资源原样复用）。
- 不在本次迁移中调整蜜罐的"业务口径"（密码本策略、锁定阈值、并发上限保持原值）。

---

## 2. 一致性分级（D3 的落地标准）

### 2.1 硬契约：必须逐项一致，CI 门禁

| 类别 | 内容 | 校验手段 |
| --- | --- | --- |
| 配置 | `config.yaml` 键名/默认值/`credentials` 双写法/`AI_*` 环境变量覆盖/hostname 优先级 | 配置单测 + 双栈启动日志比对 |
| 数据 | 7 张表结构、索引名、`PRAGMA user_version=3`、时间格式、0/1 布尔、字段语义 | `db_diff` 脚本 + Java 库副本双向读写 |
| 鉴权数据 | `pbkdf2-sha256$210000$salt$hash` 可校验、默认管理员引导、`must_change` 语义 | 用 Java 生成的库直接登录 Go 版 |
| HTTP | 23 个 API 的路径、方法、参数、响应字段名与类型、状态码、分页包络 | `api_diff` 双栈 JSON 比对 |
| 前端 | 9 个静态资源路径与内容、`/api/vendor/echarts.js`、缓存头、根路径 302 行为 | Playwright E2E + curl 断言 |
| 协议 | SSH banner / hostkey 指纹 / 认证行为 / 事件分层；Telnet banner 与 IAC 序列；MySQL 8.4 / PG 17 / Redis 7 的握手要素与固定错误码 | 协议回放比对 + `nmap -sV` |
| 日志 | 6 类事件名、事件字段集合、`session` 编号格式、双写一致性 | JSONL 与 DB 抽样比对 |
| 运维 | 端口、`/app/logs`、`/app/db` 卷、hostkey 持久化于 `/app/db/hostkey.ser`、**非 root 运行（默认 `10001:10001`，由 compose `user:` 声明）**、`curl` healthcheck、`TZ`、`SIGTERM` 优雅关闭、`-c/--config` | 真实 compose 冒烟 + 重启后指纹比对 + `id -u` = 10001 + `--user 12345:12345` 可运行 |

### 2.2 软契约：行为等价即可，允许实现差异

| 内容 | Java 现状 | Go 允许的做法 |
| --- | --- | --- |
| 未知命令回退 | 本地 `command not found` / AI 仿真三档路由 | 路由优先级保持一致，具体文案以 `FakeEnv` 常量统一生成 |
| 内部标记 | 输出串携带 `\x00NONL`、`\x00__EXIT__` | 可用返回结构体（`Output{Text, NoNewline, Exit}`）替代，只要终端表现一致 |
| 会话并发模型 | 虚拟线程 + 单线程写队列 | goroutine + 有界 channel（丢弃需计数告警） |
| 日志实现 | `java.util.logging` 文本 | `log/slog` 文本输出，关键行保持可 grep |
| SQLite 驱动 | sqlite-jdbc | `modernc.org/sqlite`（纯 Go，支持多架构静态编译） |
| ECharts 来源 | WebJar | 提取为 `web/vendor/echarts.min.js`，仍经 `/api/vendor/echarts.js` 输出 |
| 会话编号 | 序号 + 毫秒十六进制 | 同格式生成（下游可能有正则依赖） |

### 2.3 允许差异（需在发布说明登记）

| 项 | 说明 |
| --- | --- |
| SSH 算法列表 | `x/crypto/ssh` 与 Apache MINA SSHD 支持的 KEX/Cipher/MAC 集合不完全相同，`nmap -sV` 的算法明细会有差异；banner、hostkey 类型与指纹、认证流程保持一致 |
| JSON 字段顺序 | JSONL 行内字段顺序由实现决定，字段名与值类型一致 |
| 内存/线程指标 | 进程内存占用、GOMAXPROCS、goroutine 数与 Java 指标无可比性 |
| 启动耗时 | Go 启动更快，启动横幅行文可调整（保留版本号与端口摘要） |

---

## 3. 现状盘点与模块映射

### 3.1 Java 侧模块清单

| Java 模块 | 职责 | Go 落点 | 难度 |
| --- | --- | --- | --- |
| `Main` | 装配、启动、优雅关闭 | `cmd/honeypot` | 低 |
| `config/HoneypotConfig` | YAML + 环境变量 + hostname 解析 | `internal/config` | 低 |
| `log/AttackLogger` | JSONL + SQLite 双写、串行落盘 | `internal/attacklog` | 低 |
| `log/SqliteLogStore` | 事件表 DDL 与写入 | `internal/store` | 低 |
| `geo/IpLocator` | ip2region xdb v4/v6 + 缓存 + 内置回退 | `internal/geo` | 中 |
| `auth/CredentialGuard` | 密码本 + 窗口内失败锁定 | `internal/auth` | 低 |
| `fs/VirtualFileSystem` `fs/VNode` | 共享内存虚拟文件系统 | `internal/vfs` | 中 |
| `env/FakeEnv` | 硬件/网络/软件版本硬事实 | `internal/fakeenv` | 低 |
| `shell/FakeShell` | 行编辑、ANSI、历史、Ctrl+C/D | `internal/shell` | 中 |
| `shell/CommandProcessor` | 200+ 命令仿真 + 路由 + AI 回退（87KB） | `internal/shell/cmd` | 高 |
| `shell/SessionState` | 会话上下文、提示符、主目录 | `internal/shell` | 低 |
| `ssh/SshHoneypotServer` | SSH 服务、banner、心跳、并发限流 | `internal/honeypot/sshpot` | 高 |
| `telnet/TelnetHoneypotServer` | IAC 协商 + login 流程 | `internal/honeypot/telnetpot` | 中 |
| `mysql/MySqlHoneypotServer` | 握手抓凭据 + 1045/1040 | `internal/honeypot/dbpot` | 中 |
| `postgres/PostgresHoneypotServer` | 明文口令 + 28P01/53300 | `internal/honeypot/dbpot` | 中 |
| `redis/RedisHoneypotServer` | NOAUTH/WRONGPASS/超限 | `internal/honeypot/dbpot` | 中 |
| `web/WebServer` `ApiController` | 23 路由、Session、审计中间件 | `internal/web` | 中 |
| `web/LogRepository` `UserRepository` `AuditLogRepository` `ClientIps` `AuthService` | 查询/用户/审计/IP 解析 | `internal/web` | 中 |
| `ai/AiClient` | OpenAI 兼容 + 信号量 + 熔断 | `internal/ai` | 低 |
| `resources/web/*` | 前端页面与资源 | `web/`（`go:embed`） | 无（复用） |

### 3.2 已确认的现状事实（影响实现决策）

1. `hostkey.ser` 实际内容是 `-----BEGIN OPENSSH PRIVATE KEY-----`（ecdsa-sha2-nistp256，注释 `host key`），位于 Java 项目根目录、运行路径为 `/app/hostkey.ser`；Go 可直接 `ssh.ParsePrivateKeyFile` 解析，**SSH 主机指纹无需变化**。
2. 全部结构化数据落在一个 SQLite 文件：`sessions`、`auth_attempts`、`commands`、`downloads`、`ip_locks`、`sys_users`、`sys_audit_log`，`user_version=3`。
3. Java 版 Dockerfile 未持久化 `hostkey.ser`（只落容器可写层），容器重建即更换主机密钥。Go 版统一改存 `db/hostkey.ser`（容器内 `/app/db/hostkey.ser`），随 `/app/db` 卷持久化，容器重建与版本升级都不再变化；首次启动会读取旧路径 `hostkey.ser` 完成无感接续（见 5.1）。
4. `VirtualFileSystem` 由 `Main` 创建**单个实例**并被所有协议服务共享，攻击者写入的文件跨会话可见；Go 版必须保持该语义（读写加锁即可，不要做"每会话独立"的"改进"）。
5. 前端 `app.js` 调用的 19 个 API 路径与 `ApiController` 完全对齐，`login.html` 仅依赖 `/api/login`；前端可零改动复用。
6. Java 镜像未声明 `USER`，容器内进程与生成的 `db/*`、`logs/*` 文件属主均为 root；Go 版运行身份改由 compose 的 `user:` 指定，首次升级需将宿主机目录属主交接给该 UID:GID。

---

## 4. Go 工程架构

### 4.1 目录结构

```
ssh-honeypot-go/
├── cmd/honeypot/
│   ├── main.go              # 参数解析、装配、信号处理、-health/-version 子命令
│   └── main_test.go
├── internal/
│   ├── config/              # yaml.v3 解析 + AI_* 覆盖 + hostname 解析
│   ├── attacklog/           # 事件 API + 单 writer goroutine + 有界队列
│   ├── store/               # SQLite DDL/写入/查询连接池
│   ├── geo/                 # ip2region xdb + 内置库 embed + 缓存
│   ├── auth/                # CredentialGuard
│   ├── vfs/                 # VNode 树 + RWMutex
│   ├── fakeenv/             # 环境硬事实（与 AI systemPrompt 同源）
│   ├── shell/               # 行编辑器、会话循环、提示符
│   ├── shell/cmd/           # processor.go + 按命令族拆文件
│   ├── ai/                  # OpenAI 兼容客户端 + 熔断
│   ├── honeypot/sshpot/     # SSH 监听、banner、会话、keepalive
│   ├── honeypot/telnetpot/
│   ├── honeypot/dbpot/      # mysql.go / postgres.go / redis.go
│   ├── web/                 # 路由、API、Session、仓储、审计、ClientIP
│   └── version/             # 版本信息（ldflags 注入）
├── web/                     # 前端资源（复用 Java 版）+ vendor/echarts.min.js
├── docs/
│   └── MIGRATION-PLAN.md    # 本文件
├── scripts/conformance/     # 差分与回放脚本
├── config.yaml              # 与 Java 版逐字一致
├── db/                      # 运行时生成：database.db、hostkey.ser（容器内挂载 /app/db）
├── Dockerfile
├── docker-entrypoint.sh
├── .dockerignore
├── .gitea/workflows/docker-image.yml
├── .github/workflows/docker-image.yml
├── go.mod
└── README.md
```

### 4.2 依赖选型

| 需求 | 选型 | 理由与备选 |
| --- | --- | --- |
| SSH 服务端 | `golang.org/x/crypto/ssh` | 需自控 banner、pty-req/window-change、exec、keepalive、并发限流；`gliderlabs/ssh` 封装过厚。备选：`gliderlabs/ssh` + listener 劫持 |
| SQLite | `modernc.org/sqlite` | 纯 Go，`CGO_ENABLED=0` 可交叉编译 amd64/arm64；备选 `mattn/go-sqlite3`（需 cgo，CI 复杂度上升） |
| YAML | `gopkg.in/yaml.v3` | `credentials` 需要自定义 `UnmarshalYAML` 兼容字符串/数组 |
| IP 归属地 | `github.com/lionsoul2014/ip2region/binding/golang/xdb` | 必须用支持 xdb v3 的 v4/v6 双库版本 |
| HTTP | 标准库 `net/http` + `go:embed` | 23 条路由手写更可控，不引框架 |
| 口令哈希 | `golang.org/x/crypto/pbkdf2` | 210000 次 / 16B salt / 32B key + 常数时间比较 |
| 日志 | 标准库 `log/slog` + 自写 JSONL | 不引入重型日志库 |
| 终端处理 | 自写行编辑器 | 行为需与 Java 版逐键一致，`x/term` 仅作辅助 |

`go.mod` 基线（版本号以本地工具链为准，Go 版本对齐参考项目 1.27）：

```go
module git.pi.mmxx.fun/tool/ssh-honeypot-go

go 1.27

require (
    github.com/lionsoul2014/ip2region/binding/golang v0.0.0-xxxx
    golang.org/x/crypto v0.58.0
    gopkg.in/yaml.v3 v3.0.1
    modernc.org/sqlite v1.3x.x
)
```

---

## 5. 关键技术方案

### 5.1 SSH 服务（`internal/honeypot/sshpot`）

**banner 伪装**：`x/crypto/ssh` 的服务端标识是常量 `SSH-2.0-Go`，需在 `net.Listener` 层包装 `net.Conn`，首次 `Write` 时把首行替换为 `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n`，对上层隐藏字节数差异。禁止直接 fork 依赖。

```go
type bannerConn struct {
    net.Conn
    once sync.Once
}

func (c *bannerConn) Write(p []byte) (int, error) {
    out := p
    c.once.Do(func() {
        if bytes.HasPrefix(p, []byte("SSH-2.0-Go")) {
            rest := p[bytes.IndexByte(p, '\n')+1:]
            buf := append([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"), rest...)
            out = buf
        }
    })
    n, err := c.Conn.Write(out)
    if n > len(p) {
        n = len(p)
    }
    return n, err
}
```

**hostkey 存放与加载**：密钥统一存放在 `db/hostkey.ser`（容器内 `/app/db/hostkey.ser`），与 `database.db` 同目录，随 `/app/db` 卷持久化，容器重建与镜像升级都不会导致 SSH 指纹变化。

加载顺序（首次升级的关键）：

1. 读 `db/hostkey.ser`（新路径，已持久化）；
2. 不存在时读旧路径 `hostkey.ser`（Java 1.2.x 的 `/app/hostkey.ser`），解析成功后**复制**到 `db/hostkey.ser`，旧文件保留不删除，便于回滚到 Java 版时继续使用同一指纹；
3. 两者都不存在：生成 ed25519 密钥写入 `db/hostkey.ser`，文件权限 `0600`，属主为实际运行 UID:GID；
4. 文件存在但解析失败（非 OpenSSH 格式）：备份为 `<原路径>.bak` 后按第 3 步处理，并打印醒目告警。

约束：启动时先检查 `db`、`logs` 目录与 `config.yaml` 对**实际运行身份**的读写权限，不满足则**立即退出并打印修复命令**（`sudo chown -R <uid>:<gid> logs db`，uid/gid 取 `os.Getuid()`/`os.Getgid()` 的真实值）；启动日志首行打印 `uid=<n> gid=<n>` 便于排查；禁止静默降级或使用临时密钥（否则指纹漂移且重启即变）。

**认证与事件分层**（与 Java 版一致，不可简化）：

| 阶段 | protocol 取值 | 说明 |
| --- | --- | --- |
| 密码认证 | `ssh` | 无论成功失败都记录 `auth_attempt` + `session_open`；失败补 `session_close(duration=0)` |
| 公钥认证 | `ssh` | 记录 `[pubkey:<算法>]` 作为 password，计入失败锁定，返回拒绝 |
| 交互 shell | `ssh-shell` | 认证成功后再开一条会话记录 |
| exec | `ssh-exec` | 结束时补 `session_close` |

**资源与生命周期**：
- 最大并发会话 50（含 pre-auth 连接，超限立即 close），用 `atomic.Int64` 计数并在连接关闭时递减。
- 心跳 30s 发 `keepalive@openssh.com` 全局请求，连续 2 次无响应视为死连接并关闭，保证 `session_close` 不丢。
- `session_close` 必须幂等（`sync.Once`）。
- 后台 goroutine 全部挂在会话 context 上，避免泄漏。

**pty/窗口**：处理 `pty-req`、`window-change`（保存行列，用于 `stty`、`tput` 类输出）、`shell`、`exec`、`env` 请求；未识别的 channel 类型按真实 OpenSSH 行为拒绝。

### 5.2 伪 Shell 与命令仿真

- 行编辑器按 Java 行为逐项实现：回显、退格、左右移动、上下历史、Ctrl+C（丢弃当前行并回提示符）、Ctrl+D（退出）、Tab 补全（按 Java 版是否实现为准）。
- 输出统一走 `shell.Output{Text string; NoNewline bool; Exit bool}` 结构体，取代 Java 的 `\x00NONL` / `\x00__EXIT__` 字符串标记（软契约允许）。
- `CommandProcessor` 按命令族拆文件，避免单文件上万行：`cmd_fs.go`（ls/cd/cat/pwd/touch/mkdir/rm/cp/mv/chmod）、`cmd_sys.go`（uname/id/whoami/ps/w/free/df/uptime/hostname/date）、`cmd_net.go`（ifconfig/ip/netstat/curl/wget/ping）、`cmd_dev.go`（docker/git/node/npm/go/mvn/gcc/python）、`cmd_pkg.go`（apt/dpkg/systemctl/service）、`cmd_misc.go`（history/su/sudo/echo/exit）。
- 采用**黄金样本驱动**：先在 Java 版上为每条命令（含典型参数变体）抓取输出，存 `internal/shell/cmd/testdata/golden/`，Go 实现逐条 `diff` 到零差异。首批覆盖 README 列出的 40+ 高频命令，长尾命令进入第二批。
- 命令随机延时、`sleep` 上限 120s、下载 URL 提取并记录 `download` 事件等行为保持一致。

### 5.3 虚拟文件系统（`internal/vfs`）

- 单个 `VirtualFileSystem` 实例由 `main` 创建后注入所有协议，保持"跨会话共享"语义。
- `VNode` 树用 `sync.RWMutex` 保护；路径解析需与 Java 版一致：`.`/`..` 归一、`~` 展开、越权 `cd` 拒绝、`/home/<user>` 按需创建。
- 诱饵文件内容（`/etc/passwd`、`/etc/shadow`、`/root/.bash_history`、`/root/.my.cnf` 等）原样搬运，注意与 `fakeenv` 中的用户/主机名保持同一数据源。

### 5.4 数据层（`internal/store` + `internal/attacklog`）

- DDL、索引、`user_version=3` 与 Java 版逐字一致；启动时幂等执行，不做破坏性迁移。若需记录 Go 版自身元信息，新建 `sys_meta` 表，不改动既有表语义。
- 连接策略：1 条写连接（单 goroutine 独占）+ 读查询短连接（`query_only=ON`）；`journal_mode=WAL`、`busy_timeout=5000`、写连接 `cache_size=-600`、读连接 `cache_size=-4096`。
- DSN 示例：`file:db/database.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=query_only(false)`。
- 写入模型：事件提交到容量 8192 的 channel，单 writer goroutine 串行写 JSONL（每行 flush）后写 SQLite；队列满时丢弃并累计 `dropped` 计数，周期性告警。
- 时间：`ts`/`opened_at` 与 `epoch_ms` 必须来自同一次 `time.Now()`，格式 `2006-01-02 15:04:05.000`，本地时区。

### 5.5 IP 归属地（`internal/geo`）

加载顺序与 Java 一致：配置路径的外部 `db/ip2region_v4.xdb`、`db/ip2region_v6.xdb` → 缺失回退二进制内置库（`go:embed`，约 48MB，注意二进制体积与镜像层）→ 均缺失则归属地留空，不影响其他功能。内置 1 万条 IP（含 v4/v6/内网/保留地址）的解析结果必须与 Java 版完全一致，作为 M1 门禁。

> 内置库会让二进制增大几十 MB。若镜像体积敏感，可改为"缺库时仅告警并留空"，通过构建 tag 控制是否 embed，发布时按需选择。

### 5.6 Web 控制台（`internal/web`）

- 复用 Java 版前端 9 个文件，`go:embed` 打包；`/api/vendor/echarts.js` 由 `web/vendor/echarts.min.js` 提供，保留 `Content-Type` 与 `Cache-Control: public, max-age=86400`。
- Session：内存 `map[string]session` + 滑动过期（`sessionTimeoutMinutes`）+ 定时清理；Cookie 名 `JSESSIONID`，`HttpOnly`、`SameSite=Lax`、`Path=/`；登录成功换新 ID。
- 中间件顺序与语义：请求体大小上限（`Content-Length > 1MB` → 413 `{"ok":false,"error":"请求体过大"}`）→ 审计采集 → 鉴权（`/api/login` 与登录页静态资源放行）→ 审计落库（异步，记录 method/path/path_desc/query/masked_body/status/resp 摘要/duration/ok/location）。
- 统计接口加 60s TTL 缓存（键含当日日期），与 Java 版一致，避免 Dashboard 7 个并发聚合压垮大表。
- `ClientIps`：仅当直连地址为私网/环回时才信任 `X-Forwarded-For`/`X-Real-IP`/`Proxy-Client-IP`/`WL-Proxy-Client-IP`，取链路首个公网 IP；需覆盖 IPv4-mapped IPv6 归一化与端口剥离。
- Web 登录失败防护独立于蜜罐：5 次失败锁 IP 15 分钟，内存态，重启清零。

### 5.7 AI 命令仿真（`internal/ai`）

- 配置：`enabled`、`base_url`（自动补 `/v1`）、`api_key`、`model_name`、`enable_thinking`（经 `chat_template_kwargs` 透传）、`timeout_seconds`、`max_output_chars`、`max_concurrent`、`failure_threshold`、`cooldown_seconds`，全部支持 `AI_*` 环境变量覆盖（空值视为未设置）。
- 并发控制必须是"**立即降级不排队**"：用 `select { case sem <- struct{}{}: ... default: 降级 }`。
- 熔断：连续失败达阈值进入冷却期，期间直接本地降级；成功后清零。
- 路由优先级与 Java 一致：本地专门仿真 → 版本常量（`fakeenv`）→ AI + 空串回退 → AI + `command not found` 回退。
- system prompt 与 `fakeenv` 同源，保证攻击者交叉验证一致。

### 5.8 数据库蜜罐（`internal/honeypot/dbpot`）

| 协议 | 必须保持的要件 |
| --- | --- |
| MySQL | 版本串 `8.4.0`、`mysql_native_password`、20 字节 salt、能力位可正常被 mysql 客户端解析；捕获用户名/密码/库名；错误 `1045 / 28000 Access denied for user '<u>'@'<ip>'`；超限 `1040 / 08004 Too many connections`；并发上限 20 |
| PostgreSQL | 正确处理 StartupMessage 与 SSLRequest（按 Java 版行为应答）；下发 `AuthenticationCleartextPassword(3)`；读取 PasswordMessage 并剥离 NUL；`FATAL 28P01 password authentication failed for user "<u>"`；超限 `53300 sorry, too many clients already`；并发上限 20 |
| Redis | RESP 解析，支持 `AUTH`、`AUTH user pass`、`HELLO ... AUTH ...`；未认证其他命令回 `-NOAUTH Authentication required.`；统一 `-WRONGPASS invalid username-password pair or user is disabled.`；超限 `-ERR max number of clients reached`；并发上限 20 |
| 共同 | 所有连接读超时（避免 goroutine 堆积）、捕获即记录 `auth_attempt`、`session_open` + `session_close(0)`、限流计数用信号量 |

### 5.9 Telnet（`internal/honeypot/telnetpot`）

banner `\r\nUbuntu 22.04.3 LTS\r\n`；IAC 协商序列 `WILL ECHO`、`WILL SGA`、`DO SGA`、`DO NAWS`、`DONT LINEMODE`，并逐字节过滤客户端 IAC 命令；提示 `"<hostname> login: "` / `"Password: "`；单连接尝试上限取 `auth.maxFailures`；认证成功进入伪 Shell（`protocol=telnet`）。

### 5.10 进程装配与生命周期（`cmd/honeypot`）

- 参数：`-c/--config`（默认 `config.yaml`）、`-h/--help`、`-health`、`-version`；未知参数告警不退出（兼容 Java 行为）。
- 子命令 `-health`：参考 `ssh-tunnel-go`，探测配置中启用的端口（Web 优先，其次 SSH），全部不可达返回非 0，供镜像 `HEALTHCHECK` 使用。
- 启动顺序：配置 → 日志 → VFS/fakeenv → geo → attacklog/store → auth → AI → 五协议监听 → Web；任一蜜罐端口监听失败仅告警不整体退出（与 Java 行为一致：Web 依赖 DB，DB 不可用时不启动 Web）。
- 关闭：`signal.NotifyContext(SIGINT/SIGTERM)` → 停止接受新连接 → 关闭在途会话（限时 5s）→ flush JSONL → `PRAGMA wal_checkpoint(TRUNCATE)` 后关库 → 退出码 0。

---

## 6. 构建、镜像与发布（对齐 `ssh-tunnel-go`）

### 6.1 版本号与镜像标签

| 项 | 规则 |
| --- | --- |
| 源码版本 | `2.0.0` 起（`release-v2.0.0` tag） |
| 镜像名 | **保持不变**：Docker Hub `babyfly/ssh-honeypot-j`，Nexus `scdm/ssh-honeypot-j` |
| 标签 | `release-vX.Y.Z` → `X.Y.Z` + `latest`；预发布用 `release-v2.0.0-rc.1` 手工验证，不覆盖 `latest` |
| 回滚标签 | `1.2.1`（Java 最后一版）必须长期保留，`latest` 覆盖前先在 release note 声明 |
| 构建信息 | ldflags 注入 `main.version` / `main.commit` / `main.buildAt`，`honeypot -version` 与启动横幅输出 |

### 6.2 Dockerfile 设计（多阶段 + 静态二进制 + 保留 curl）

```dockerfile
# 多阶段：构建机原生架构交叉编译，运行阶段 debian bookworm-slim
ARG GO_IMAGE=golang:1.27-bookworm
ARG BASE_IMAGE=debian:bookworm-slim
ARG APT_MIRROR=

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /build

ARG GOPROXY
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV CGO_ENABLED=0
RUN if [ -n "$GOPROXY" ]; then go env -w GOPROXY="$GOPROXY"; fi

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildAt=${BUILD_DATE}" \
        -o /out/honeypot ./cmd/honeypot

FROM ${BASE_IMAGE}
WORKDIR /app

ARG APT_MIRROR
# curl 为兼容存量 compose 的 healthcheck（curl -f http://127.0.0.1:8080）；
# tzdata 保证 TZ=Asia/Shanghai 下的本地时间与 Java 版一致
RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|security.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl tzdata passwd && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/honeypot /app/honeypot
COPY config.yaml /app/config.yaml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# 默认非 root 账号（仅作 docker run 时的兜底）：实际执行身份由 compose 的 user: 决定，
# 因此 /app 内文件需对任意 UID 可读可执行，logs/db 预留可写权限（实际以挂载卷权限为准）
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    groupadd -g 10001 honeypot && \
    useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin honeypot && \
    mkdir -p /app/logs /app/db && \
    chown -R 10001:10001 /app && \
    chmod 0755 /app /app/honeypot && \
    chmod 0644 /app/config.yaml && \
    chmod 0777 /app/logs /app/db

# 兜底声明：compose 未写 user: 时也不会以 root 运行；
# compose 中 user: "<UID>:<GID>" 可覆盖此默认值
USER 10001:10001
ENV HOME=/tmp

ENTRYPOINT ["docker-entrypoint.sh"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/app/honeypot", "-health"]

EXPOSE 2222 2323 3306 5432 6379 8080
VOLUME ["/app/logs", "/app/db"]
```

与 Java 版镜像的行为对齐点：

- 工作目录 `/app`，配置 `config.yaml`，日志 `logs/honeypot.jsonl`，库 `db/database.db`，hostkey `db/hostkey.ser`（与库同卷，容器重建不丢失）。
- **以非 root 运行，身份由 compose `user:` 指定**（镜像 `USER 10001:10001` 仅作兜底）：所有监听端口（2222/2323/3306/5432/6379/8080）均大于 1024，无需 `CAP_NET_BIND_SERVICE`，无需任何 Linux capability，因此任意 UID 均可运行。
- 二进制/配置对任意用户可读可执行（`0755`/`0644`），`logs`/`db` 镜像内预留 `0777`，使 `user:` 仍可临时覆盖为其他 UID（如 CI 用 `12345:12345` 验证）；本项目部署统一使用 `10001:10001`。
- 一次性权限交接：宿主机 `logs/`、`db/`（及 `config.yaml`）属主需与 compose 中 `user:` 的 UID:GID 一致；Java 版创建的目录属主为 root，升级前必须 `sudo chown -R <UID>:<GID> logs db`。
- 镜像体积预期：约 90-140MB（debian-slim + 双 xdb 内置库）；若采用"缺库留空"的构建模式可降至约 30MB。
- 实现上不依赖 `os/user`（仅用 `os.Getuid()`/`os.Getgid()` 数字），`HOME=/tmp`；因此 compose 可指定 `/etc/passwd` 中不存在的 UID，不会因查不到用户而报错。

### 6.3 docker-entrypoint.sh

与参考项目一致，仅做 exec 转发，保证 `docker run <image> -c /etc/honeypot.yaml` 原生命令行用法不变：

```sh
#!/bin/sh
set -e
exec /app/honeypot "$@"
```

环境变量到配置的映射（`AI_*` 10 项）已内置于二进制，脚本不再翻译。

### 6.4 Gitea Actions（推 Nexus，linux/amd64）

以 `.gitea/workflows/docker-image.yml` 为模板，改动点：

| 项 | 取值 |
| --- | --- |
| `env.IMAGE_NAME` | `ssh-honeypot-j`（**不改名**） |
| 推送地址 | `${{ vars.NEXUS_REGISTRY_DOCKER }}/scdm/ssh-honeypot-j` |
| `env.GOPROXY` | `https://repo.pi.mmxx.fun/repository/go-public,direct` |
| `env.APT_MIRROR` | `repo.huaweicloud.com` |
| `env.DOCKER_PROXY` | `repo.pi.mmxx.fun/docker-public`，用于覆盖 `GO_IMAGE` / `BASE_IMAGE` |
| `runs-on` | `golang` |
| `platforms` | `linux/amd64`（无需 QEMU） |
| 触发 | push `main` 仅 `latest`；push `release-v*` 推版本号 + `latest`；支持手工触发 |
| cache | `type=gha`（Gitea 兼容） |
| 其他 | `provenance: false`、`NEXUS_*` 用 `vars`、构建前校验镜像地址格式 |
| 安全校验 | 断言 `docker inspect -f '{{.Config.User}}' <image>` 为 `10001:10001`（兜底默认非 root）；再以 `docker run --rm --user 12345:12345 --entrypoint id <image> -u` 验证身份可被 `user:` 覆盖，输出 `12345`；失败则阻断推送 |

### 6.5 GitHub Actions（推 Docker Hub，amd64 + arm64）

以 `.github/workflows/docker-image.yml` 为模板，改动点：

| 项 | 取值 |
| --- | --- |
| `env.IMAGE_NAME` | `ssh-honeypot-j` |
| `env.IMAGE_USERNAME` | `babyfly` |
| `verify` job | `gofmt -l` 门禁 + `go vet ./...` + `go test ./... -race -count=1` |
| `build-and-push` | `needs: verify`，`if: github.event_name != 'pull_request'` |
| platforms | `linux/amd64,linux/arm64`，需 `docker/setup-qemu-action@v3` |
| Secrets | `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` |
| 附加测试 | 建议在 `verify` 中执行 `scripts/conformance` 的快速子集（协议黄金样本 + API 契约） |

### 6.6 发布纪律（避免 "latest" 意外破坏存量部署）

1. 先推 `release-v2.0.0-rc.1`（只出 `2.0.0-rc.1` tag），在测试机按第 7 章完成切换与回滚演练。
2. 再推 `release-v2.0.0`（出 `2.0.0` + `latest`），同时在 README/Release Note 首页固定提示：
   - 升级命令与回滚命令；
   - `latest` 自本版本起指向 Go 实现；
   - Java 版最后版本为 `1.2.1`。
3. 保留 `1.2.1` 镜像与 Nexus 同 tag，永不删除。
4. `main` 分支的自动 `latest` 仅推送到 Nexus（内网先行），Docker Hub 的 `latest` 只在正式 tag 时更新。

---

## 7. 无感升级与回滚

### 7.1 compose 改动清单（基于实际部署文件）

以现网 compose 为基线（`scdm/ssh-honeypot-j:latest`、bind mount `./logs`/`./db`、未挂载 `config.yaml`、Web `12186:8080`、AI 走环境变量），逐项对照：

| compose 配置 | 升级后 | 说明 |
| --- | --- | --- |
| `image: scdm/ssh-honeypot-j:latest` | 不变 | 镜像名与 tag 保持（Docker Hub 同名仓库为 `babyfly/ssh-honeypot-j`） |
| `user: "10001:10001"` | **新增** | 固定运行身份，与镜像默认一致，不随宿主机用户变化；宿主机 `./logs`、`./db` 属主须为 10001；禁止 `0:0`/`root` |
| `container_name` / `hostname: ubuntu` / `restart: always` | 不变 | `hostname` 继续决定诱捕主机名（Docker hostname > config.yaml > `svr01`） |
| `volumes: ./logs:/app/logs`、`./db:/app/db` | 不变 | bind mount 路径不变；宿主目录属主需与 `user:` 一致；hostkey 落 `/app/db/hostkey.ser` 后随卷持久化 |
| `environment: TZ / AI_*`（8 项） | 不变 | 环境变量语义与优先级一致；空值视为未设置 |
| （未挂载 `config.yaml`） | 不变 | 继续使用镜像内置 `config.yaml` + 环境变量覆盖；若后续挂载，需对运行 UID 可读 |
| `ports: 22:2222 / 23:2323 / 3306:3306 / 12186:8080` | 不变 | 端口映射不变；PG/Redis 保持注释状态 |
| `healthcheck: curl -f http://127.0.0.1:8080` | 不变 | 镜像保留 `curl`；`start_period: 20s` 可原样使用（Go 版启动 ≤1s） |
| `mem_limit: 300m` | 不变（可下调） | Go 版常驻 ≤40MB，实测稳定后可降至 `128m`，非必需 |
| `security_opt` | **建议新增** | 现网未配置，建议加 `no-new-privileges:true` 与 `cap_drop: [ALL]`（见 7.6） |
| `logging` | 不变 | 现网未配置，继续使用 Docker 默认 `json-file` |

升级后的完整 compose（除 `user:` 与可选加固外，与现网逐字一致）：

```yaml
services:
  ssh-honeypot-j:
    image: scdm/ssh-honeypot-j:latest
    container_name: ssh-honeypot-j
    hostname: ubuntu
    restart: always
    user: "10001:10001"        # 新增：固定运行身份；宿主机 ./logs ./db 需属主 10001
    volumes:
      - ./logs:/app/logs
      - ./db:/app/db
    environment:
      - TZ=Asia/Shanghai
      - AI_ENABLED=true
      - AI_BASE_URL=http://llama-cpp-vulkan:8000/v1
      - AI_API_KEY=<与原值相同，不入库>
      - AI_MODEL_NAME=2B
      - AI_MAX_CONCURRENT=2
      - AI_TIMEOUT_SECONDS=60
      - AI_COOLDOWN_SECONDS=10
    ports:
      - 22:2222
      - 23:2323
      - 3306:3306
    #   - 5432:5432
    #   - 6379:6379
      - 12186:8080
    mem_limit: 300m
    security_opt:              # 可选加固（推荐）
      - no-new-privileges:true
    cap_drop:                  # 可选加固（推荐）
      - ALL
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 20s
```

`user:` 同时指定 UID 与 GID，改完 `up -d` 即生效、无需重建镜像；镜像内 `USER 10001:10001` 仅在未声明 `user:` 时兜底，避免 `docker run` 手工启动回退 root。

本方案统一采用 **`10001:10001`**：与镜像默认一致，所有机器复用同一份 compose，不随宿主机登录用户变化；镜像内已存在该账号，`/etc/passwd` 有对应条目，无需依赖宿主机用户。代价是宿主机 `ls -l` 显示数字属主，建议在 README 中标注“10001 = honeypot”。

### 7.2 升级步骤（运维手册）

```bash
# 1. 停机并备份（db 含 WAL 文件，必须一起打包）
docker compose stop
tar czf honeypot-backup-$(date +%F-%H%M).tgz logs/ db/ config.yaml 2>/dev/null
#   hostkey 已随 db/ 一起备份（db/hostkey.ser）；旧版根目录残留的 hostkey.ser 如需回滚请单独保留

# 2. 权限交接（仅首次从 Java 版升级需要）
#   Java 版以 root 写入，./logs ./db 属主很可能是 0:0；
#   先确认属主，再统一改为 10001（与 user: 一致）
ls -ldn logs db
sudo chown -R 10001:10001 logs db
#   仅当另挂了 config.yaml 时才需要：sudo chmod 644 config.yaml

# 3. 数据兼容自检（只读，不修改任何内容）
docker run --rm --user 10001:10001 -v $PWD/db:/app/db scdm/ssh-honeypot-j:2.0.0 check-db
#   期望输出：schema OK / user_version=3 / 7 张表行数摘要

# 4. 升级（两种等价方式任选）
docker compose pull && docker compose up -d
#   或显式锁版本：sed -i 's#ssh-honeypot-j:latest#ssh-honeypot-j:2.0.0#' docker-compose.yml

# 5. 验收（注意宿主机映射端口为 12186）
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:12186         # 期望 302
curl -s http://127.0.0.1:12186/api/me                                  # 期望 401 JSON
ssh -p 2222 -o StrictHostKeyChecking=no -o BatchMode=yes root@127.0.0.1 # 期望拒绝但 banner 为 OpenSSH
docker compose exec ssh-honeypot-j id -u                               # 期望 10001（非 0）
docker inspect -f '{{.HostConfig.SecurityOpt}}' ssh-honeypot-j          # 可选：确认 no-new-privileges 生效

# 6. 验证主机密钥已持久化（重启后指纹不变）
ssh-keyscan -p 2222 127.0.0.1 2>/dev/null | ssh-keygen -lf -   # 记录指纹
docker compose restart && sleep 3
ssh-keyscan -p 2222 127.0.0.1 2>/dev/null | ssh-keygen -lf -   # 指纹应与重启前一致
ls -l db/hostkey.ser                                            # 期望 -rw------- 10001
```

### 7.3 回滚步骤

```bash
docker compose down
docker compose pull && docker compose up -d   # 镜像 tag 改回 1.2.1
# 或：sed -i 's#ssh-honeypot-j:2.0.0#ssh-honeypot-j:1.2.1#' docker-compose.yml
```

回滚到 Java 版（root 运行）可直接启动（root 不受属主限制）；但回滚后 Java 版新建的文件会重新变成 root 属主，**再次升级回 Go 版前必须按 compose `user:` 的取值重新执行一次 `sudo chown -R <UID>:<GID> logs db`**。

回滚可行性由三条承诺保证：

1. Go 版**不提升** `user_version`，不删除/重命名任何列与索引。
2. Go 版新增内容只写新表（`sys_meta`，可不存在）与追加行，不改历史行。
3. JSONL 为追加写，格式不变，Java 版可继续追加。

### 7.4 硬性禁止

- 禁止 Java 与 Go 同时挂载同一 `db/database.db` 运行（会重复记录 session/审计，且 WAL 写入互相干扰）。灰度对比必须使用数据库副本与独立日志目录。
- 禁止在 Go 版中加入"自动迁移脚本"去改写既有表结构。

### 7.5 灰度对比（可选，正式切换前建议执行一次）

蜜罐端口分流会稀释攻击样本，因此采用影子实例：Go 版监听所有端口 +10000、数据库指向副本、日志独立；用 `scripts/conformance/replay.py` 回放录制流量 24 小时，比对协议响应与落库结果。Web 控制台可通过 nginx 将少量流量导向影子实例做真实用户灰度。

### 7.6 容器安全基线

镜像默认即满足下表；带 * 的项目仍需运维在 compose 中显式加固（不强制，不改不影响运行）。

| 项 | 做法 | 状态 |
| --- | --- | --- |
| 运行身份 | 由 compose `user: "<UID>:<GID>"` 指定；镜像 `USER 10001:10001` 仅兜底；禁止 `0:0`/`root`；不采用"root 启动后 gosu 降权" | compose 声明 |
| 文件属主 | `/app` 内文件 `0755`/`0644`、`logs`/`db` `0777`；hostkey `0600` 属主为实际运行 UID | 默认内置 |
| 权限能力 | 无需任何 capability；建议 `cap_drop: [ALL]` | 建议显式 * |
| 提权防护 | `security_opt: [no-new-privileges:true]`（存量 compose 已配置） | 建议显式 * |
| 根文件系统 | 可 `read_only: true` + `tmpfs: [/tmp]`；`/app/logs`、`/app/db` 仍为可写卷 | 可选 * |
| 网络 | 不使用 `network_mode: host`、不发布 `privileged`；仅映射必要端口 | 建议显式 * |
| 镜像 | 运行阶段仅 `ca-certificates`/`curl`/`tzdata`/`passwd`，无编译器与 SDK | 默认内置 |

> 注：部署统一使用 `user: "10001:10001"`，宿主机 `./logs`、`./db`（bind mount）属主必须为 10001，否则启动预检失败并打印实际 `uid/gid` 与 chown 命令；校验发生在启动阶段而非运行中，不会产生静默丢数据。后续若改用其他 `user:`，历史库/日志文件属主会不匹配，需同步 `chown`。

---

## 8. 验证与测试

### 8.1 测试分层

| 层次 | 内容 | 工具 |
| --- | --- | --- |
| 单元 | 配置解析、PBKDF2 校验、ClientIps、VFS 路径、行编辑器按键序列、AI 熔断 | `go test` |
| 契约 | 23 个 API 四态（成功/未登录/无权限/非法参数）、JSON 结构与类型 | `api_diff` |
| 协议 | Telnet / MySQL / PG / Redis 逐字节；SSH banner 与认证流程 | `replay.py`、`nmap -sV`、`ssh -vvv` |
| 数据 | schema/索引/user_version/事件字段；Java 库副本双向读写 | `db_diff`、`sqlite3` |
| 前端 | 登录→总览→五类明细→用户管理→强制改密 | Playwright |
| 稳定性 | `-race`、并发压测、goroutine 泄漏 | `go test -race`、自建压测脚本 |

### 8.2 性能与安全门禁

| 指标 | 目标 |
| --- | --- |
| 常驻内存（空载） | ≤ 20MB |
| 常驻内存（100 并发 SSH 会话 + 持续爆破） | ≤ 40MB |
| 启动到全部端口可连 | ≤ 1s |
| 100 并发 SSH + 50 conn/s MySQL 持续 30 分钟 | 无 goroutine 泄漏、无 `database is locked`、日志丢弃计数为 0 |
| 优雅关闭 | SIGTERM 后 ≤ 2s 退出，JSONL 无半行、DB 可正常打开 |
| 容器身份 | `docker inspect -f '{{.Config.User}}'` = `10001:10001`；compose 中 `id -u` = 10001；以 `--user 12345:12345` 覆盖后仍能正常启动 |
| 只读根文件系统 | 开启 `read_only` 后仍能正常启动与抓取攻击（验证临时文件未落到 `/`） |

---

## 9. 实施计划

| 里程碑 | 内容 | 验收 | 人日 |
| --- | --- | --- | --- |
| M0 | 骨架（config/version/health/graceful）、Dockerfile、entrypoint、双 CI、`.dockerignore` | `docker build` 成功；`-version` 输出 2.0.0；配置解析与 Java 一致 | 3 |
| M1 | store + attacklog + geo（含内置库回退） | 用 Java 库副本：schema diff 为空、`user_version=3`、万级 IP 归属地一致 | 4 |
| M2 | SSH 服务 + FakeShell + VFS（高频命令外的一切） | banner/hostkey 指纹一致；交互体验一致；session 事件分层正确 | 7 |
| M3 | CommandProcessor 第一批（40+ 高频命令） | golden 样本全绿 | 8 |
| M4 | Telnet + MySQL + PG + Redis | 报文级 diff 通过，凭据与事件落库一致 | 6 |
| M5 | Web（23 API + 前端复用 + Session + 用户 + 审计） | api_diff 全绿；前端零改动可用 | 7 |
| M6 | CommandProcessor 第二批 + AI 客户端 | 路由优先级与降级用例通过 | 6 |
| M7 | 差分体系、CI 加固、切换与回滚演练、README/升级指南、`release-v2.0.0` | 真实主机完成一次升级 + 回滚 | 5 |
| 合计 | | | **46 人日** |

排期建议：单人约 9-10 周；双人并行（M3/M4 与 M5 并行）约 5 周。

发布切分：

- `2.0.0-rc.1` = M0-M5（功能主体等价，长尾命令走本地 `command not found`）
- `2.0.0` = M0-M7（全量功能等价 + 切换演练完成）
- `2.1.0` = 后续增强（SSH 算法集对齐、内置 IP 库改为可选、hostkey 轮换子命令 `rotate-hostkey`）

---

## 10. 风险登记

| ID | 风险 | 影响 | 应对 |
| --- | --- | --- | --- |
| R1 | 200+ 命令移植产生细微文案差异 | 蜜罐真实度下降 | 黄金样本驱动 + 按命令族拆文件 + CI diff 门禁 |
| R2 | SSH 算法列表与 MINA 不同 | 高级指纹识别 | 列为已知差异；2.1.0 提供算法配置项贴近 OpenSSH 8.9p1 |
| R3 | `modernc.org/sqlite` 与 sqlite-jdbc 锁行为差异 | 偶发 `database is locked` | DSN 固定 PRAGMA；写连接单例；30 分钟压测门禁 |
| R4 | ip2region v3 xdb 与 Java 输出不一致 | 归属地统计偏差 | M1 万级 IP diff 门禁，不一致阻断发版 |
| R5 | compose `user:` 与宿主机卷属主不一致，导致不可写 | 首次升级启动失败 | 启动前预检 + fail-fast 提示实际 `uid/gid` 与 chown 命令；升级手册第 2 步一次性 `chown`；CI 用 root 属主目录做负向用例 |
| R6 | 时区与毫秒格式不一致 | 趋势统计跨日错位 | 单测固定 TZ；双栈同时刻写库比对 |
| R7 | `latest` 被 Go 版覆盖导致未经确认的升级 | 存量部署异常 | 发布纪律（6.6）+ 保留 1.2.1 + 升级/回滚步骤前置在 README |
| R8 | 有界队列在极端攻击下丢日志 | 数据缺失 | 容量 8192 + 丢弃计数告警 + 配置项 |
| R9 | 心跳缺失导致 `session_close` 丢失 | 会话统计偏低 | `keepalive@openssh.com` + 2 次无应答断连 + 双栈对拍 |
| R10 | 打包内置 xdb 导致镜像/二进制膨胀 | 分发体积 | 默认内置（功能优先），提供 `nogeoembed` 构建标签裁剪 |
| R11 | compose 误配 `user: "0:0"`/`root`，或有人删掉镜像 `USER` 兜底 | 回退为 root，丢失安全边界 | CI 断言 `Config.User` 与 `--user` 覆盖行为；README 与 compose 示例标注禁止 root；评审 checklist 必查 |

---

## 11. 附录

### 11.1 附录 A：HTTP API 清单（23 条，硬契约）

| 方法 | 路径 | 权限 | 关键参数 |
| --- | --- | --- | --- |
| POST | `/api/login` | 公开 | body: `username`,`password` |
| POST | `/api/logout` | 登录 | - |
| GET | `/api/me` | 登录 | - |
| PUT | `/api/password` | 登录 | body: `oldPassword`,`newPassword`(≥8) |
| GET | `/api/stats/overview` | 登录 | - |
| GET | `/api/stats/trend` | 登录 | `days`(1..30, 默认 14) |
| GET | `/api/stats/protocol` | 登录 | - |
| GET | `/api/stats/top-ips` | 登录 | `limit`(1..50, 默认 10) |
| GET | `/api/stats/top-locations` | 登录 | `limit` |
| GET | `/api/stats/top-usernames` | 登录 | `limit` |
| GET | `/api/stats/top-passwords` | 登录 | `limit` |
| GET | `/api/sessions` | 登录 | `srcIp`,`protocol`,`start`,`end`,`page`,`size` |
| GET | `/api/auth-attempts` | 登录 | `srcIp`,`username`,`protocol`,`success`,`start`,`end`,`page`,`size` |
| GET | `/api/commands` | 登录 | `sessionId`,`srcIp`,`username`,`keyword`,`start`,`end`,`page`,`size` |
| GET | `/api/downloads` | 登录 | `srcIp`,`keyword`,`start`,`end`,`page`,`size` |
| GET | `/api/ip-locks` | 登录 | `srcIp`,`page`,`size` |
| GET | `/api/audit-logs` | admin | `username`,`srcIp`,`method`,`path`,`start`,`end`,`page`,`size` |
| GET | `/api/audit-logs/trend` | admin | `days` |
| GET | `/api/users` | admin | - |
| POST | `/api/users` | admin | body: `username`(2-32 `[a-zA-Z0-9_.-]`),`password`(≥8),`role`(admin/viewer),`mustChange` |
| PUT | `/api/users/{id}/status` | admin | body: `enabled` |
| PUT | `/api/users/{id}/password` | admin | body: `password`,`mustChange` |
| DELETE | `/api/users/{id}` | admin | 不能删除自己；至少保留一个启用管理员 |

响应包络与方法级差异见 2.1；`/api/login`、`/api/me` 返回 `{"ok":true,"user":{...}}`，其余为 `{"ok":true,"data":...}`。

### 11.2 附录 B：攻击事件字段（JSONL + SQLite 双写）

| 事件 | JSONL 字段 | SQLite 目标 |
| --- | --- | --- |
| `session_open` | `ts`,`event`,`session`,`protocol`,`src_ip`,`src_port`,`location` | `sessions` INSERT |
| `session_close` | `ts`,`event`,`session`,`src_ip`,`duration_ms`,`location` | `sessions` UPDATE |
| `auth_attempt` | `ts`,`event`,`session`,`protocol`,`src_ip`,`username`,`password`,`success`,`location` | `auth_attempts` INSERT |
| `command` | `ts`,`event`,`session`,`src_ip`,`username`,`command`,`location` | `commands` INSERT |
| `download` | `ts`,`event`,`session`,`src_ip`,`username`,`url`,`location` | `downloads` INSERT |
| `ip_locked` | `ts`,`event`,`src_ip`,`until`,`location` | `ip_locks` INSERT |

`protocol` 取值：`ssh`、`ssh-shell`、`ssh-exec`、`telnet`、`mysql`、`postgresql`、`redis`。

### 11.3 附录 C：`config.yaml` 全量键

| 段 | 键 | 默认值 |
| --- | --- | --- |
| 根 | `hostname` | 空（解析优先级：Docker hostname > 此值 > `svr01`） |
| `ssh` | `enabled`,`port` | `true`,`2222` |
| `telnet` | `enabled`,`port` | `true`,`2323` |
| `mysql` | `enabled`,`port` | `true`,`3306` |
| `postgresql` | `enabled`,`port` | `true`,`5432` |
| `redis` | `enabled`,`port` | `true`,`6379` |
| `log` | `file`,`db`,`ipdb_v4`,`ipdb_v6` | `logs/honeypot.jsonl`、`logs/database.db`、`db/ip2region_v4.xdb`、`db/ip2region_v6.xdb` |
| `ai` | `enabled`,`base_url`,`api_key`,`model_name`,`enable_thinking`,`timeout_seconds`,`max_output_chars`,`max_concurrent`,`failure_threshold`,`cooldown_seconds` | `false`、空、空、空、`false`、`20`、`8192`、`1`、`3`、`300` |
| `web` | `enabled`,`port`,`sessionTimeoutMinutes` | `true`,`8080`,`30` |
| `auth` | `maxFailures`,`windowMinutes`,`lockMinutes`,`credentials` | `3`,`5`,`30`、内置弱口令本 |

环境变量覆盖（空值视为未设置）：`AI_ENABLED`、`AI_BASE_URL`、`AI_API_KEY`、`AI_MODEL_NAME`、`AI_ENABLE_THINKING`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS`、`AI_MAX_CONCURRENT`、`AI_FAILURE_THRESHOLD`、`AI_COOLDOWN_SECONDS`。

### 11.4 附录 D：SQLite 表清单（`user_version=3`）

| 表 | 关键列 | 索引 |
| --- | --- | --- |
| `sessions` | `session_id`(UNIQUE),`protocol`,`src_ip`,`src_port`,`opened_at`,`opened_epoch_ms`,`closed_at`,`duration_ms`,`location` | `src_ip`,`opened_epoch_ms`,`protocol` |
| `auth_attempts` | `ts`,`ts_epoch_ms`,`session_id`,`protocol`,`src_ip`,`username`,`password`,`success`,`location` | `src_ip`,`username`,`ts_epoch_ms`,`password`,`location` |
| `commands` | `ts`,`ts_epoch_ms`,`session_id`,`src_ip`,`username`,`command`,`location` | `session_id`,`src_ip`,`ts_epoch_ms` |
| `downloads` | `ts`,`ts_epoch_ms`,`session_id`,`src_ip`,`username`,`url`,`location` | `src_ip`,`ts_epoch_ms` |
| `ip_locks` | `ts`,`ts_epoch_ms`,`src_ip`,`locked_until`,`location` | `src_ip`,`ts_epoch_ms` |
| `sys_users` | `id`,`username`(UNIQUE),`password_hash`,`role`,`status`,`must_change`,`created_at`,`last_login_at` | 主键/唯一约束 |
| `sys_audit_log` | `ts`,`epoch_ms`,`username`,`src_ip`,`method`,`path`,`path_desc`,`query`,`req_body`,`status`,`resp_body`,`duration_ms`,`ok`,`location` | `epoch_ms`,`username` |

新增内容只允许走新表（如 `sys_meta`），且不得影响上表的读写语义。

---

## 12. 变更记录

| 日期 | 版本 | 内容 |
| --- | --- | --- |
| 2026-10-25 | v1.0 | 方案基线：确定镜像名保持 `ssh-honeypot-j`、Go 版本从 2.0.0 起、一致性分级、构建与 CI 对齐 `ssh-tunnel-go` |
| 2026-10-25 | v1.1 | hostkey 改存 `/app/db/hostkey.ser` 随 db 卷持久化，保留旧路径 `hostkey.ser` 兼容接续，并补充重启后指纹不变的验收步骤 |
| 2026-10-25 | v1.2 | 安全加固：镜像改为非 root 运行，禁止 root；补充一次性权限交接、安全基线与容器身份门禁 |
| 2026-10-25 | v1.3 | 执行用户与组改由 compose `user:` 指定（镜像 `USER` 仅兜底），镜像内权限位适配任意 UID，补充 compose 示例与 UID 对齐校验 |
| 2026-10-25 | v1.4 | 按实际部署 compose（`scdm/ssh-honeypot-j`、bind mount、未挂 config.yaml、Web 12186、AI 环境变量）校准升级对照与完整示例；补充不依赖 `os/user` 的实现约束 |
| 2026-10-25 | v1.5 | 固定部署身份为 `10001:10001`（路线 B）：compose、chown、验收与门禁全部对齐；CI 改用 `12345:12345` 验证身份可覆盖 |

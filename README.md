# NetGazer 网络凝视者（Go 版）

## GitHub
- https://github.com/AbnerSC/ssh-honeypot-go.git
- [![GitHub Stars](https://img.shields.io/github/stars/AbnerSC/ssh-honeypot-go?style=flat&label=Stars)](https://github.com/AbnerSC/ssh-honeypot-go/stargazers)
- [![Docker Pulls](https://img.shields.io/docker/pulls/babyfly/ssh-honeypot-j?label=Docker%20Pulls)](https://hub.docker.com/r/babyfly/ssh-honeypot-j)


一款 **中交互** 多协议蜜罐，静默凝视每一次针对服务器的暴力破解与入侵行为。

同时诱捕 SSH / Telnet / MySQL / PostgreSQL / Redis 五种协议，攻击者"登录"后进入伪 Shell
与虚拟文件系统，可随意浏览、修改（仅内存生效）；所有凭证、命令、恶意下载实时落盘，
并可在 Web 控制台可视化查看。未知命令可选交给大模型仿真，避免千篇一律的报错穿帮。

> ⚠️ 仅用于安全研究与授权环境。蜜罐会吸引真实攻击者，请务必在隔离的
> 测试/专用机器上运行，不要部署在存有敏感数据的生产服务器上。

## 支持的功能

| 能力 | 说明 |
| --- | --- |
| SSH 蜜罐 | 伪装 `OpenSSH_8.9p1 Ubuntu`，密码本内账号可"登录成功"；支持交互式 Shell 与 `ssh user@host "cmd"` exec 通道 |
| Telnet 蜜罐 | 模拟经典 `login:` 流程，含 IAC 终端协商 |
| MySQL / PostgreSQL / Redis 蜜罐 | 按真实协议握手并捕获账号密码，再返回与真服务一致的认证失败报文；单协议并发上限 20 |
| 伪 Shell | 行编辑（回显、退格、左右移动、历史、Ctrl+C/D），200+ 命令族（`ls` `cat` `ps` `netstat` `su` `sudo` `apt` `systemctl` `docker` `git` `python3` 等），支持 `;`、`&&`、管道、`>` / `>>` 重定向，执行带随机延时 |
| 虚拟文件系统 | 内置诱饵文件 `/etc/passwd`、`/etc/shadow`、`/root/.my.cnf`、`/root/.bash_history` 等，攻击者的增删改只发生在内存 |
| 攻击日志 | JSONL + SQLite 双写：来源 IP、凭证、每条命令、恶意下载 URL、会话时长、IP 归属地 |
| Web 控制台 | 统计图表、五类事件明细分页查询、系统用户管理、操作审计，前端随二进制内嵌 |
| 源 IP 锁定 | 连续登录失败达阈值即锁定该 IP，锁定事件同样入库 |
| AI 命令仿真（可选） | 未知命令交大模型生成仿真输出，服务不可用自动降级，不阻塞会话 |

## 快速开始

### Docker 部署（推荐）

```yaml
services:
  ssh-honeypot-j:
    image: scdm/ssh-honeypot-j:latest
    container_name: ssh-honeypot-j
    hostname: ubuntu
    restart: always
    user: "10001:10001"            # 固定运行身份，禁止 0:0 / root
    volumes:
      - ./logs:/app/logs           # 攻击日志 JSONL
      - ./db:/app/db               # SQLite 库、hostkey
    environment:
      - TZ=Asia/Shanghai
      - AI_ENABLED=true
      - AI_BASE_URL=http://llama-cpp-vulkan:8000/v1
      - AI_API_KEY=
      - AI_MODEL_NAME=2B
      - AI_MAX_CONCURRENT=2
      - AI_TIMEOUT_SECONDS=60
      - AI_COOLDOWN_SECONDS=10
    ports:
      - 22:2222
      - 23:2323
      - 3306:3306
      - 5432:5432
      - 6379:6379
      - 12186:8080
    mem_limit: 128m
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 20s
```

```bash
mkdir -p logs db
sudo chown -R 10001:10001 logs db     # 属主必须与 user: 一致
docker compose up -d
```

- 宿主机 `./logs`、`./db` 属主不符时启动预检直接失败并打印实际 `uid/gid` 与修复命令，不会静默丢数据
- IP 归属地库（ip2region v4/v6）已内置在二进制中，无需挂载外部文件，也不会释放临时文件；
  仅向量索引（约 512KB/库）常驻内存，数据段按需读取，避免 46MB 整库入堆

### 本地构建运行

```bash
go build -trimpath -buildvcs=false -o honeypot ./cmd/honeypot

./honeypot                          # 使用默认 config.yaml
./honeypot -c /etc/honeypot.yaml    # 指定配置文件
./honeypot -version                 # 版本信息
./honeypot -health                  # 探测配置中启用的端口
./honeypot check-db                 # 只读自检数据库：版本号 + 7 张表行数
```

配置文件不存在时使用内置默认值；未知命令行参数仅告警不退出。

## 配置说明（config.yaml）

完整键与默认值见 [config.yaml](config.yaml)（已带中文注释）。常用项：

| 段 | 键 | 默认值 |
| --- | --- | --- |
| 根 | `hostname` | 空（优先级：Docker hostname > 本键 > `svr01`） |
| `ssh` | `enabled`,`port` | `true`,`2222` |
| `telnet` | `enabled`,`port` | `true`,`2323` |
| `mysql` | `enabled`,`port` | `true`,`3306` |
| `postgresql` | `enabled`,`port` | `true`,`5432` |
| `redis` | `enabled`,`port` | `true`,`6379` |
| `web` | `enabled`,`port`,`sessionTimeoutMinutes` | `true`,`8080`,`30` |
| `log` | `file`,`db` | `logs/honeypot.jsonl`、`db/database.db` |
| `auth` | `maxFailures`,`windowMinutes`,`lockMinutes`,`credentials` | `3`,`5`,`60`、内置弱口令本 |

`auth.credentials` 是登录密码本（不在表内的账号一律登录失败），支持单密码与密码列表：

```yaml
auth:
  maxFailures: 3
  windowMinutes: 5
  lockMinutes: 60
  credentials:
    root: ["123456", "toor", "password"]
    admin: "admin123"        # 单字符串写法
```

## 验证蜜罐是否工作

```bash
ssh -p 2222 root@127.0.0.1                              # 交互式伪 Shell（密码见密码本）
ssh -p 2222 root@127.0.0.1 "uname -a; cat /etc/passwd"  # exec 通道
telnet 127.0.0.1 2323
mysql -h127.0.0.1 -P3306 -uroot -p                      # 捕获凭证后返回 1045
```

登录一次、敲几条命令后，`logs/honeypot.jsonl` 与 Web 控制台都应出现对应记录。

## Web 可视化控制台

与蜜罐同进程部署，前端内嵌，启动后访问 `http://<主机IP>:8080/`。

- 首次启动自动创建默认管理员 `admin/admin123`，登录后强制修改密码
- 功能：总览指标与趋势图、协议分布、Top 攻击 IP / 用户名 / 口令 / 归属地；
  会话、登录尝试、命令、恶意下载、IP 锁定五类事件分页查询（支持 IP / 用户名 / 协议 /
  关键字 / 时间范围过滤）；系统用户管理；操作审计（敏感字段已脱敏）
- 角色：`admin`（全部权限）、`viewer`（仅查看）
- 连续 5 次登录失败锁定来源 IP 15 分钟，请求体上限 1MB
- 建议 Web 端口仅对运维网段开放，不要直接暴露到公网

## AI 大模型命令仿真（可选）

默认关闭，未配置大模型服务时开箱即用，未知命令统一返回本地 `-bash: xxx: command not found`。
Docker 部署可直接注入环境变量（优先级：环境变量 > `config.yaml` > 默认值）：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AI_ENABLED` | `false` | 是否启用 |
| `AI_BASE_URL` | 空 | OpenAI 兼容接口地址（自动补全 `/v1`） |
| `AI_API_KEY` | 空 | API 密钥，本地无鉴权服务可留空 |
| `AI_MODEL_NAME` | 空 | 模型名称 |
| `AI_ENABLE_THINKING` | `false` | 思考模式，响应更慢，建议同步调大超时 |
| `AI_TIMEOUT_SECONDS` | `20` | 单次请求超时（秒），超时立即降级 |
| `AI_MAX_OUTPUT_CHARS` | `8192` | 单条输出字符上限，超长截断 |
| `AI_MAX_CONCURRENT` | `1` | 全局并发上限，超出立即降级不排队 |
| `AI_FAILURE_THRESHOLD` | `3` | 连续失败达到该次数后熔断 |
| `AI_COOLDOWN_SECONDS` | `300` | 熔断时长（秒） |

启用前提：`AI_ENABLED=true` 且 `AI_BASE_URL`、`AI_MODEL_NAME` 非空。
常见命令（`ls`、`cat`、`systemctl`、`docker ps`、`apt` 等）与版本查询（`node -v`、
`git --version` 等）走本地仿真，不消耗大模型请求。

## 日志格式

每行一个 JSON 事件（`logs/honeypot.jsonl`），同时写入 SQLite。

事件先在内存攒批，每 1 秒（或攒满 512 条）落盘一次：JSONL 一次 Flush，SQLite 一个事务提交，
单条事件不再逐条 fsync。

SQLite 侧除 5 张明细表外，还维护 `stats_daily`（按天）与 `stats_ip_daily`（按天 + 来源 IP）
两张预聚合表，控制台的总览、趋势与排行直接读聚合结果，不再对百万级明细做全表统计。
库结构版本记录在 `PRAGMA user_version`（当前为 4）：首次启动自动建表并一次性从明细回溯历史数据，
百万级库会有短暂耗时，之后启动不再重复。

| 事件 | 字段 |
| --- | --- |
| `session_open` | `ts`,`event`,`session`,`protocol`,`src_ip`,`src_port`,`location` |
| `session_close` | `ts`,`event`,`session`,`src_ip`,`duration_ms`,`location` |
| `auth_attempt` | `ts`,`event`,`session`,`protocol`,`src_ip`,`username`,`password`,`success`,`location` |
| `command` | `ts`,`event`,`session`,`src_ip`,`username`,`command`,`location` |
| `download` | `ts`,`event`,`session`,`src_ip`,`username`,`url`,`location` |
| `ip_locked` | `ts`,`event`,`src_ip`,`until`,`location` |

`protocol` 取值：`ssh`、`ssh-shell`、`ssh-exec`、`telnet`、`mysql`、`postgresql`、`redis`。

```bash
jq -r 'select(.event=="auth_attempt") | [.ts,.src_ip,.username,.password] | @tsv' logs/honeypot.jsonl
```

## 诱捕协议清单

- [x] SSH
- [x] Telnet
- [x] MySQL
- [x] PostgreSQL
- [x] Redis
- [ ] HTTP（Nginx）

// Package ai 大模型命令仿真客户端（OpenAI 兼容 /v1/chat/completions 接口）。
//
// 职责：为伪 Shell 未覆盖的未知命令（如 ./malware、nmap 等自定义工具）生成
// 以假乱真的终端输出，替代千篇一律的 "command not found"，提升蜜罐欺骗度。
//
// 蜜罐稳定性优先：所有失败路径（未启用/未配置/超时/并发打满/熔断/解析失败）
// 均返回 ok=false，由调用方降级本地兜底，绝不阻塞会话线程：
//   - 连接 3 秒 + 请求 timeout_seconds 双超时，超时立即降级；
//   - 全局并发上限，超出立即降级不排队，防大模型服务被并发会话打爆；
//   - 连续失败熔断：达到 failure_threshold 后冷却 cooldown_seconds 秒，期间直接降级；
//   - 输出净化：剥离思考段与代码围栏、过滤控制字符、按 max_output_chars 截断，
//     防止模型口误暴露 AI 身份或破坏终端渲染。
//
// 行为与 Java 版 org.open.scdm.honeypot.ai.AiClient 逐项对齐（硬契约：降级语义与提示词）。
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"git.pi.mmxx.fun/tool/ssh-honeypot-go/internal/fakeenv"
)

const (
	// connectTimeout 建立连接超时：模型服务不可达时尽快降级，不拖慢伪 Shell 响应。
	connectTimeout = 3 * time.Second
	// minRequestTimeout 单次请求超时下限（秒）；上限由配置决定。
	minRequestTimeout = 3
	// minMaxOutputChars 单条输出字符数下限：防误配成 0 导致输出全被截没。
	minMaxOutputChars = 256
	// minCooldownSeconds 熔断时长下限（秒）。
	minCooldownSeconds = 10
	// maxTokens 单次生成 token 上限：思考模式下推理也消耗 token，放大取值防输出被截断。
	maxTokens = 32768
	// maxResponseBytes 响应体读取上限，防异常服务返回超大内容撑爆内存。
	maxResponseBytes = 8 << 20
	// temperature 采样温度，与 Java 版一致取 1。
	temperature = 1.0
)

// thinkBlock 混合推理模型把思考段内联在 content 中：整段剥离。
var thinkBlock = regexp.MustCompile(`(?s)<think>.*?</think>`)

// Config 大模型命令仿真配置，字段与 config.yaml 的 ai 段一一对应。
type Config struct {
	Enabled          bool
	BaseURL          string
	APIKey           string
	ModelName        string
	EnableThinking   bool
	TimeoutSeconds   int
	MaxOutputChars   int
	MaxConcurrent    int
	FailureThreshold int
	CooldownSeconds  int
}

// Client 大模型命令仿真客户端。nil 指针安全：未启用时调用方直接持有 nil，
// 所有方法对 nil 都返回「不可用」，AI 对蜜罐完全透明。
type Client struct {
	cfg      Config
	endpoint string
	http     *http.Client
	permits  chan struct{}
	logger   *slog.Logger
	// maxOutputChars 单条输出字符上限（构造时钳制到 >=256）。
	maxOutputChars int

	// 熔断器：连续失败计数与熔断截止时间戳（毫秒 epoch）。
	failures  atomic.Int32
	openUntil atomic.Int64
}

// New 构造客户端；未启用或关键配置（base_url/model_name）缺失时返回 nil，
// 调用方持有 nil 即全程走本地兜底。
func New(cfg Config, logger *slog.Logger) *Client {
	if !cfg.Enabled {
		return nil
	}
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		warnf(logger, "ai.enabled=true 但未配置 base_url，AI 命令仿真未启用（未知命令走本地兜底）")
		return nil
	}
	if strings.TrimSpace(cfg.ModelName) == "" {
		warnf(logger, "ai.enabled=true 但未配置 model_name，AI 命令仿真未启用（未知命令走本地兜底）")
		return nil
	}

	// base_url 归一化：去尾部斜杠并自动补 /v1，兼容 http://host:port 与 http://host:port/v1 两种写法
	for strings.HasSuffix(base, "/") {
		base = base[:len(base)-1]
	}
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	c := &Client{
		cfg:            cfg,
		endpoint:       base + "/chat/completions",
		permits:        make(chan struct{}, max(1, cfg.MaxConcurrent)),
		logger:         logger,
		maxOutputChars: max(minMaxOutputChars, cfg.MaxOutputChars),
		http: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(max(minRequestTimeout, cfg.TimeoutSeconds)) * time.Second,
		},
	}
	infof(logger, "AI 命令仿真已启用: "+c.endpoint+" 模型="+cfg.ModelName+
		" 思考="+onOff(cfg.EnableThinking)+
		" 超时="+fmt.Sprint(max(minRequestTimeout, cfg.TimeoutSeconds))+"s"+
		" 并发上限="+fmt.Sprint(max(1, cfg.MaxConcurrent)))
	return c
}

// Endpoint 归一化后的 chat/completions 地址（供启动日志与测试断言）。
func (c *Client) Endpoint() string {
	if c == nil {
		return ""
	}
	return c.endpoint
}

// GenerateShellOutput 生成未知命令的仿真终端输出。
//
// hostname/username/cwd 描述会话状态，recent 为最近执行的命令（不含当前命令），
// cmdline 为当前命令原文。ok=false 表示本次不可用（未启用/超时/并发打满/熔断/解析失败），
// 调用方据此降级本地兜底；ok=true 且内容为空串属正常（该命令成功时本就无输出）。
func (c *Client) GenerateShellOutput(hostname, username, cwd string, recent []string, cmdline string) (string, bool) {
	if c == nil || c.circuitOpen() {
		return "", false
	}
	// 并发打满立即降级，不排队阻塞会话线程
	select {
	case c.permits <- struct{}{}:
	default:
		return "", false
	}
	defer func() { <-c.permits }()

	payload, err := c.buildRequest(hostname, username, cwd, recent, cmdline)
	if err != nil {
		c.onFailure("AI 请求构造失败: " + reason(err))
		return "", false
	}
	resp, err := c.http.Do(payload)
	if err != nil {
		c.onFailure("AI 请求失败: " + reason(err))
		return "", false
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		c.onFailure("AI 响应读取失败: " + reason(err))
		return "", false
	}
	if resp.StatusCode/100 != 2 {
		c.onFailure(fmt.Sprintf("AI 服务 HTTP %d", resp.StatusCode))
		return "", false
	}
	content, ok := parseContent(data)
	if !ok {
		c.onFailure("AI 响应解析失败（无 choices[0].message.content）")
		return "", false
	}
	c.failures.Store(0) // 成功即复位熔断计数
	out := c.sanitize(content)
	infof(c.logger, "AI 命令仿真输出: "+out)
	return out, true
}

// Close 释放空闲连接。在途请求自带超时兜底，关闭等待有界。
func (c *Client) Close() {
	if c == nil || c.http == nil {
		return
	}
	c.http.CloseIdleConnections()
}

// 请求构建与响应解析

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model              string         `json:"model"`
	Messages           []chatMessage  `json:"messages"`
	Temperature        float64        `json:"temperature"`
	MaxTokens          int            `json:"max_tokens"`
	ChatTemplateKwargs map[string]any `json:"chat_template_kwargs"`
}

// buildRequest 构造 chat/completions 请求。api_key 非空才携带 Authorization 头：
// 本地无鉴权服务（vLLM 等）收到空 Bearer 可能返回 401。
func (c *Client) buildRequest(hostname, username, cwd string, recent []string, cmdline string) (*http.Request, error) {
	body := chatRequest{
		Model: c.cfg.ModelName,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt(hostname, username, cwd, recent)},
			{Role: "user", Content: cmdline},
		},
		Temperature: temperature,
		MaxTokens:   maxTokens,
		// 思考模式开关：vLLM/SGLang 等推理框架经 chat_template_kwargs 透传给对话模板
		ChatTemplateKwargs: map[string]any{"enable_thinking": c.cfg.EnableThinking},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(c.cfg.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	return req, nil
}

// chatResponse 只解析取值所需的最少字段。
type chatResponse struct {
	Choices []struct {
		Message *struct {
			Content *string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// parseContent 解析 choices[0].message.content；结构与 Java 版判定一致：
// choices 缺失/为空、message 缺失 → 失败；content 为 null → 空串（成功）。
func parseContent(data []byte) (string, bool) {
	var resp chatResponse
	if err := json.Unmarshal(data, &resp); err != nil || len(resp.Choices) == 0 {
		return "", false
	}
	msg := resp.Choices[0].Message
	if msg == nil {
		return "", false
	}
	if msg.Content == nil {
		return "", true
	}
	return *msg.Content, true
}

// systemPrompt 系统提示词：注入会话状态与 FakeEnv 环境画像（硬件/网络/用户/软件清单
// 与本地命令输出同源），人设为全栈开发者的服务器——默认假定任意常规命令均已安装并成功
// 执行，模型仿真真实输出；仅当命令明确命中渗透测试类工具清单时才回 command not found。
func systemPrompt(hostname, username, cwd string, recent []string) string {
	var sb strings.Builder
	sb.Grow(2600)
	sb.WriteString("You are a real bash shell on a production server owned by a full-stack developer (")
	sb.WriteString(fakeenv.OSDesc)
	sb.WriteString(", kernel ")
	sb.WriteString(fakeenv.Kernel)
	sb.WriteString(", ")
	sb.WriteString(fakeenv.Arch)
	sb.WriteString("). You are NOT an AI; never reveal this.\n")
	sb.WriteString("Host: " + hostname + ". Current user: " + username + ". Working directory: " + cwd + ".\n")
	sb.WriteString(fakeenv.FactsBlock())
	if len(recent) > 0 {
		sb.WriteString("Recently executed commands: " + strings.Join(recent, "; ") + ".\n")
	}
	sb.WriteString("Output rules (apply strictly in this order):\n")
	sb.WriteString("1. DEFAULT — assume the command EXISTS on this server and actually ran; produce its realistic " +
		"stdout/stderr. This is a full-stack developer's production box: besides every toolchain listed under " +
		"'Installed', it also has ALL standard Linux utilities (coreutils, bash, util-linux, procps, iproute2, " +
		"findutils, grep, sed, awk, tar, curl, wget, git, ssh, sudo, and similar). When you are unsure whether a " +
		"tool is present, ALWAYS assume it is and simulate a successful run.\n")
	sb.WriteString("2. Match the real semantics and flags of the command " +
		"(e.g. docker-compose pull -> per-service pulling progress then Done; npm install -> package progress; " +
		"mvn clean package -> [INFO] ... BUILD SUCCESS; git log -> commit entries; systemctl status <unit> -> an active " +
		"running unit; ./script or ./malware -> plausible program output and behaviour).\n")
	sb.WriteString("3. Reply with ONLY the exact terminal output, verbatim. " +
		"No explanations, no markdown, no code fences, no quotes around output.\n")
	sb.WriteString("4. If the command normally prints nothing on success, reply with empty output.\n")
	sb.WriteString("5. SOLE EXCEPTION — reply '-bash: <name>: command not found' ONLY when the command is clearly a " +
		"penetration-testing / traffic-analysis tool explicitly listed under 'NOT installed'. Never use this for " +
		"any ordinary utility, dev tool, script, or binary.\n")
	sb.WriteString("6. Keep output within 30 lines; terse and technical, like real terminal output. " +
		"Timestamps around September 2026, UTC, en_US.UTF-8 locale.")
	return sb.String()
}

// 输出净化

// sanitize 净化模型输出：剥离思考段与代码围栏、过滤控制字符（保留 \n \t）、按上限截断。
func (c *Client) sanitize(raw string) string {
	// 混合推理模型可能把 <think>...</think> 内联在 content 中：整段剥离；
	// 无开标签的孤立闭标签（部分服务端已剥开标签）直接删除
	s := strings.TrimSpace(strings.ReplaceAll(thinkBlock.ReplaceAllString(raw, ""), "</think>", ""))

	// 模型违规用 ``` 围栏包裹输出：仅当整体被围栏包裹才剥，避免误伤真实输出中的反引号
	if strings.HasPrefix(s, "```") {
		firstNewline := strings.IndexByte(s, '\n')
		lastFence := strings.LastIndex(s, "```")
		if firstNewline >= 0 && lastFence > firstNewline {
			s = strings.TrimSpace(s[firstNewline+1 : lastFence])
		} else {
			s = "" // 只剩孤立围栏标记
		}
	}

	var sb strings.Builder
	sb.Grow(min(len(s)+16, c.maxOutputChars+16))
	n := 0
	for _, r := range s {
		if n >= c.maxOutputChars {
			break
		}
		if r == '\n' || r == '\t' || r >= 0x20 {
			sb.WriteRune(r)
			n++
		}
	}
	return sb.String()
}

// 熔断器

// circuitOpen 熔断开启中则直接降级；到期自动半开（放行下一次请求试探恢复）。
func (c *Client) circuitOpen() bool {
	until := c.openUntil.Load()
	return until > 0 && time.Now().UnixMilli() < until
}

// onFailure 累计连续失败次数，达到阈值后进入冷却期并清零计数。
func (c *Client) onFailure(reason string) {
	failures := int(c.failures.Add(1))
	if failures >= max(1, c.cfg.FailureThreshold) {
		cooldown := max(minCooldownSeconds, c.cfg.CooldownSeconds)
		c.openUntil.Store(time.Now().Add(time.Duration(cooldown) * time.Second).UnixMilli())
		c.failures.Store(0)
		warnf(c.logger, fmt.Sprintf("AI 服务连续失败 %d 次（%s），熔断 %d 秒后自动重试，期间未知命令走本地兜底",
			failures, reason, cooldown))
		return
	}
	warnf(c.logger, fmt.Sprintf("AI 服务调用失败（连续第 %d 次）: %s", failures, reason))
}

// 小工具

// reason 异常描述：部分实现 Error() 为空串时回退类型名，保证日志可读。
func reason(err error) string {
	if err == nil {
		return "未知错误"
	}
	if msg := err.Error(); msg != "" {
		return msg
	}
	return fmt.Sprintf("%T", err)
}

func onOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

func infof(logger *slog.Logger, message string) {
	if logger != nil {
		logger.Info(message)
	}
}

func warnf(logger *slog.Logger, message string) {
	if logger != nil {
		logger.Warn(message)
	}
}

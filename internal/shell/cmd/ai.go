package cmd

import (
	"strings"

	"ssh-honeypot-go/internal/shell"
)

// AIClient 大模型命令仿真客户端（M6 接入的大模型网关）。
//
// 未注入时（蜜罐未配置 AI），未知命令回退本地 command not found，
// 已安装但无本地仿真的命令回退空串——降级过程对攻击者不可感知。
type AIClient interface {
	// GenerateShellOutput 生成一条命令的仿真输出；ok=false 表示未启用或调用失败。
	GenerateShellOutput(hostname, username, cwd string, recent []string, cmdline string) (string, bool)
}

// SetAI 注入大模型客户端（传 nil 表示禁用）。
func (p *Processor) SetAI(ai AIClient) {
	p.ai = ai
}

// aiGenerate 调大模型生成仿真输出，携带最近 3 条历史作为会话上下文，
// 让输出与前序操作连贯。当前命令本身不作为上下文。
//
// st.History 记录的是攻击者键入的整行（与真实 bash 的 history 一致），一行可能包含
// 多条命令（`whoami; terraform plan`），因此不能简单地丢弃末条：末条里当前命令之前
// 的部分仍属于「前序命令」，需要保留，否则同一行串联的命令拿不到上下文。
func (p *Processor) aiGenerate(st *shell.Session, cmdline string) (string, bool) {
	if p.ai == nil {
		return "", false
	}
	recent := recentCommands(st.History, cmdline, 3)
	return p.ai.GenerateShellOutput(st.Hostname, st.Username, st.Cwd, recent, cmdline)
}

// recentCommands 从历史里倒序取最多 limit 条前序命令，输出保持时间正序。
// 当前命令在末条历史中的位置及其后内容会被裁掉，避免把待执行的命令当成已执行。
func recentCommands(history []string, cmdline string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	recent := make([]string, 0, limit)
	for i := len(history) - 1; i >= 0 && len(recent) < limit; i-- {
		line := strings.TrimSpace(history[i])
		if line == "" {
			continue
		}
		if i == len(history)-1 {
			// 末条是本行输入：只保留当前命令之前的片段
			if idx := strings.LastIndex(line, cmdline); idx >= 0 {
				line = strings.TrimSpace(strings.TrimRight(line[:idx], "; "))
				if line == "" {
					continue
				}
			}
		}
		if line == strings.TrimSpace(cmdline) {
			continue
		}
		recent = append(recent, line)
	}
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	return recent
}

// aiFallback 未知命令回退：优先大模型仿真，不可用时本地 command not found。
func (p *Processor) aiFallback(st *shell.Session, cmdline, name string) string {
	if out, ok := p.aiGenerate(st, cmdline); ok {
		return out
	}
	return commandNotFound(name)
}

// aiFallbackSilent 已安装命令回退：优先大模型仿真，不可用时空串
// （这类命令成功时本就无输出，回空串不穿帮，也避免与「开发工具已装」的人设矛盾）。
func (p *Processor) aiFallbackSilent(st *shell.Session, cmdline string) string {
	if out, ok := p.aiGenerate(st, cmdline); ok {
		return out
	}
	return ""
}

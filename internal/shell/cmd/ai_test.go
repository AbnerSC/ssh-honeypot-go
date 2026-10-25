package cmd

import (
	"reflect"
	"strings"
	"testing"
)

// fakeAI 记录调用参数，用于断言 AI 上下文拼装结果。
type fakeAI struct {
	calls  int
	recent []string
	cmd    string
}

func (f *fakeAI) GenerateShellOutput(hostname, username, cwd string, recent []string, cmdline string) (string, bool) {
	f.calls++
	f.recent = append([]string(nil), recent...)
	f.cmd = cmdline
	return "AI:" + cmdline, true
}

// TestRecentCommands 前序命令提取：普通多行历史与一行多命令都要给出正确上下文。
func TestRecentCommands(t *testing.T) {
	cases := []struct {
		name    string
		history []string
		cmdline string
		want    []string
	}{
		{"普通多行", []string{"whoami", "uname -a", "kubectl get pods"}, "kubectl get pods", []string{"whoami", "uname -a"}},
		{"一行多命令", []string{"whoami; terraform plan"}, "terraform plan", []string{"whoami"}},
		{"一行三条命令", []string{"cd /tmp && touch a && terraform plan"}, "terraform plan", []string{"cd /tmp && touch a &&"}},
		{"首条命令无上下文", []string{"terraform plan"}, "terraform plan", nil},
		{"最多三条", []string{"a", "b", "c", "d", "terraform plan"}, "terraform plan", []string{"b", "c", "d"}},
	}
	for _, c := range cases {
		got := recentCommands(c.history, c.cmdline, 3)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: recentCommands=%q, 期望 %q", c.name, got, c.want)
		}
	}
}

// TestAIGenerateContext 未知命令触发 AI 时，同一行串联的前序命令要进入上下文。
func TestAIGenerateContext(t *testing.T) {
	p := newProcessor()
	st := newSession()
	ai := &fakeAI{}
	p.SetAI(ai)

	out := p.Execute(st, "whoami; terraform plan")
	if ai.calls != 1 {
		t.Fatalf("AI 调用次数=%d, 期望 1", ai.calls)
	}
	if !strings.HasSuffix(out.Text, "AI:terraform plan\n") {
		t.Fatalf("AI 输出未透传: %q", out.Text)
	}
	if !reflect.DeepEqual(ai.recent, []string{"whoami"}) {
		t.Fatalf("AI 上下文=%q, 期望 [whoami]", ai.recent)
	}

	// 未注入 AI 时回退本地 command not found
	p2 := newProcessor()
	if got := p2.Execute(newSession(), "terraform plan").Text; got != "-bash: terraform: command not found\n" {
		t.Fatalf("无 AI 时回退输出=%q", got)
	}
}

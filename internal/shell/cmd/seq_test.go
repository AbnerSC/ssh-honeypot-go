package cmd

import (
	"strings"
	"testing"
)

// TestSeqCommand seq 对齐 GNU 语义：单/双/三参数、步长、浮点、-w、-s；
// 大范围不能再静默输出空串（旧实现 >1000 即返回空，是可被指纹识别的破绽）。
func TestSeqCommand(t *testing.T) {
	p := newProcessor()
	st := newSession()
	cases := []struct{ cmd, want string }{
		{"seq", "seq: missing operand\n"},
		{"seq 5", "1\n2\n3\n4\n5\n"},
		{"seq 3 5", "3\n4\n5\n"},
		{"seq 1 2 9", "1\n3\n5\n7\n9\n"},
		{"seq 5 1", ""},
		{"seq 1 -1 5", ""},
		{"seq -w 8 12", "08\n09\n10\n11\n12\n"},
		{"seq -s , 1 4", "1,2,3,4\n"},
		{"seq 1 0.5 2", "1.0\n1.5\n2.0\n"},
		{"seq abc", "seq: invalid floating point argument: 'abc'\n"},
	}
	for _, c := range cases {
		if out := p.Execute(st, c.cmd); out.Text != c.want {
			t.Fatalf("%q 输出=%q 期望=%q", c.cmd, out.Text, c.want)
		}
	}

	// 大范围必须完整输出
	out := p.Execute(st, "seq 1 50000")
	if n := strings.Count(out.Text, "\n"); n != 50000 {
		t.Fatalf("seq 1 50000 行数=%d", n)
	}
	if !strings.HasPrefix(out.Text, "1\n2\n") || !strings.HasSuffix(out.Text, "49999\n50000\n") {
		t.Fatalf("seq 1 50000 首尾异常: %q ... %q", out.Text[:4], out.Text[len(out.Text)-14:])
	}

	// 上限保护：超大范围截断到 maxSeqLines，避免内存被滥用
	out = p.Execute(st, "seq 1 100000000")
	if n := strings.Count(out.Text, "\n"); n != maxSeqLines {
		t.Fatalf("超大 seq 行数=%d，期望上限 %d", n, maxSeqLines)
	}
}

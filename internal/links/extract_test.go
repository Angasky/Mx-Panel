package links

import "testing"

func TestPastedCandidatesKeepLinesAndCredentials(t *testing.T) {
	input := "```text\r\n[节点](trojan://pass%29@example.net:443#Name) <hy2://secret@example.net:443>\r\n`http://example.net:80#inline`\rbroken\n```"
	items := Candidates(input)
	if len(items) != 4 || items[0].Line != 2 || items[1].Line != 2 || items[2].Line != 3 || items[3].Line != 4 {
		t.Fatal("candidate count or line numbers changed")
	}
	for _, item := range items[:3] {
		if _, err := Parse(item.Value); err != nil {
			t.Fatal("wrapper not removed", err)
		}
	}
	for _, input := range []string{"trojan://secret)@example.net:443#name)", "hy2://secret@example.net:443?obfs=salamander&obfs-password=secret)", "http://example.net:80#name;"} {
		got := Candidates(input)
		if len(got) != 1 || got[0].Value != input {
			t.Fatal("bare URI punctuation stripped")
		}
	}
	policy := "name = snell, example.net, 443, psk=secret"
	got := Candidates(policy)
	if len(got) != 1 || got[0].Value != policy {
		t.Fatal("Snell policy split")
	}
}

func TestAdjacentMarkdownAndBalancedParentheses(t *testing.T) {
	first := "trojan://pass%29@example.net:443#First(nested(name))"
	second := "hy2://secret@example.net:443#Second"
	for _, input := range []string{
		"[one](" + first + ")[two](" + second + ")",
		"说明：[one](" + first + ")，[two](" + second + ")。",
		"[one](" + first + " \"title\")[two](" + second + ")",
	} {
		items := Candidates(input)
		if len(items) != 2 || items[0].Value != first || items[1].Value != second {
			t.Fatal("adjacent links or nested parentheses changed", items)
		}
		for _, item := range items {
			if _, err := Parse(item.Value); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Literal parentheses in an unwrapped URI remain untouched.
	bare := "trojan://p(a)ss@example.net:443#Name)"
	if items := Candidates(bare); len(items) != 1 || items[0].Value != bare {
		t.Fatal("bare parentheses changed")
	}
}

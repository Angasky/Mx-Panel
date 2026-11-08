package links

import (
	"reflect"
	"strings"
	"testing"
)

func TestLegacyEscapedAndQuotedURIs(t *testing.T) {
	for _, uri := range []string{
		"trojan://pass%40word@example.net:443#Name",
		"vless://11111111-1111-4111-8111-111111111111@example.net:443?security=tls&sni=example.net",
		"https://user:pass%5C%40word@example.net:443#HTTP",
		"socks5://user:pass%5C.word@example.net:1080",
		mieruURI([]string{"2999", "3000"}, []string{"TCP", "UDP"}),
	} {
		want, err := ParseMany(uri)
		if err != nil {
			t.Fatal(err)
		}
		escaped := strings.NewReplacer("://", `\://`, "@", `\@`, ".", `\.`).Replace(uri)
		for _, input := range []string{escaped, "'" + escaped + "'", "\"" + escaped + "\"", "'" + uri + "'", "\"" + uri + "\""} {
			got, err := ParseMany(input)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("paste changed node", err)
			}
			if len(want) == 1 {
				node, err := Parse(input)
				if err != nil || !reflect.DeepEqual(node, want[0]) {
					t.Fatal("single paste mismatch", err)
				}
			}
		}
	}
}

func TestPastedQuotesPreserveBareDataAndLineNumbers(t *testing.T) {
	input := "'trojan\\://secret\\@example\\.net:443#First'\n[second](hy2\\://secret\\@example\\.net:443#Second)\nhttp://example.net:80#name'\nbroken"
	got := Candidates(input)
	if len(got) != 4 {
		t.Fatal("candidate count")
	}
	for i, item := range got {
		if item.Line != i+1 {
			t.Fatal("line number")
		}
		if i < 3 {
			node, err := Parse(item.Value)
			if err != nil {
				t.Fatal(err)
			}
			if i == 2 && node["name"] != "name'" {
				t.Fatal("bare quote stripped")
			}
		}
	}
	for _, input := range []string{`trojan://pass%5C%40word@example.net:443`, `trojan://secret@example.net:443#name\.end`} {
		if normalizePastedURI(input) != input {
			t.Fatal("ordinary URI rewritten")
		}
	}
}

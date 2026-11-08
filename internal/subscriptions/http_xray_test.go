package subscriptions

import (
	"encoding/json"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestImportedHTTPPathsExportXrayHA(t *testing.T) {
	source := rocketFixture()
	nodes := []any{}
	for _, uri := range []string{"http://user:first-secret@a.example.com:8080#primary", "https://user:second-secret@b.example.com:443?sni=proxy.example.com#backup"} {
		node, err := links.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		node["headers"] = Record{"User-Agent": "legacy-client", "X-Route": "{{.Target}}"}
		nodes = append(nodes, node)
	}
	source.Document["proxies"] = nodes
	for _, format := range []string{"v2rayn-ha", "v2rayng-ha"} {
		out, err := Convert(source, format, time.Now())
		if err != nil || out.Count != 1 || len(out.Skipped) != 0 {
			t.Fatal("imported HTTP paths omitted", format, err)
		}
		var docs []Record
		if err := json.Unmarshal(out.Body, &docs); err != nil || len(docs) != 1 {
			t.Fatal("invalid config", err)
		}
		outbounds := docs[0]["outbounds"].([]any)
		for i := 0; i < 2; i++ {
			outbound := outbounds[i].(Record)
			if outbound["protocol"] != "http" {
				t.Fatal("protocol changed")
			}
			headers := outbound["settings"].(Record)["headers"].(Record)
			for key, expected := range (Record{"User-Agent": "legacy-client", "X-Route": "{{.Target}}"}) {
				tmpl, err := template.New(key).Parse(headers[key].(string))
				if err != nil {
					t.Fatal(err)
				}
				var rendered strings.Builder
				if err = tmpl.Execute(&rendered, Record{"Target": "changed"}); err != nil || rendered.String() != expected {
					t.Fatal("header changed", key, err)
				}
			}
			endpoint := outbound["settings"].(Record)["servers"].([]any)[0].(Record)
			auth := endpoint["users"].([]any)[0].(Record)
			if auth["pass"] != []string{"first-secret", "second-secret"}[i] {
				t.Fatal("auth lost")
			}
		}
		raw, _ := json.Marshal(docs[0])
		checkXrayHAConfig(t, raw)
	}
	nodes[1].(Record)["headers"] = Record{"Host": "unmapped.example.net"}
	if out, err := Convert(source, "v2rayn-ha", time.Now()); err == nil || len(out.Body) > 0 {
		t.Fatal("partial unsupported group exported")
	}
}

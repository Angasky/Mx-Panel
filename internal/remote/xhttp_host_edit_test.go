package remote

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestManagedXHTTPHostEditRoundTripAndNativeValidation(t *testing.T) {
	cert, key := templateTestCertificate(t, "node.example.com", false)
	row, err := buildInboundTemplate(Record{"template": "vless-xhttp-tls", "port": 24001, "serverName": "node.example.com", "certFile": cert, "keyFile": key}, "")
	if err != nil {
		t.Fatal(err)
	}
	row["goCreateKey"] = "fixture"
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	row["settings"].(Record)["clients"] = []any{user}
	before, _ := json.Marshal(row)
	for _, host := range []string{"cdn.example.com", ""} {
		next, err := prepareManagedCoreEdit(row, Record{"xhttpHost": host, "xhttpPath": "/new", "xhttpMode": "packet-up"})
		if err != nil {
			t.Fatal(err)
		}
		if managedCoreFields(next)["xhttpHost"] != host {
			t.Fatal("editor lost Host")
		}
		nodes, err := InboundNodes(next, Record{"host": "node.example.com"})
		if err != nil || len(nodes) != 1 {
			t.Fatal(err)
		}
		uri, err := links.Export(nodes[0])
		if err != nil {
			t.Fatal(err)
		}
		restored, err := links.Parse(uri)
		if err != nil || value(restored["xhttp-opts"].(Record)["host"]) != host {
			t.Fatal("export lost Host", err)
		}
		after, _ := json.Marshal(row)
		if string(before) != string(after) {
			t.Fatal("edit mutated source")
		}
		if binary := os.Getenv("MXIOC_TEST_XRAY"); binary != "" {
			native, err := legacyNativeInbound("xray", next)
			if err != nil {
				t.Fatal(err)
			}
			native["listen"] = "127.0.0.1"
			data, _ := json.Marshal(Record{"inbounds": []any{native}, "outbounds": []any{Record{"protocol": "blackhole"}}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			command := exec.CommandContext(ctx, binary, "run", "-test", "-config", "stdin:")
			command.Stdin = strings.NewReader(string(data))
			output, err := command.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatal("Xray rejected Host edit", err, string(output))
			}
		}
	}
	for _, host := range []any{"bad/path", "bad host", "bad@host", "a\r\nb", true, strings.Repeat("a", 257)} {
		if _, err := prepareManagedCoreEdit(row, Record{"xhttpHost": host}); err == nil {
			t.Fatal("invalid Host accepted")
		}
	}
}

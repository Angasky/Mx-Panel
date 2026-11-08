package remote

import (
	"encoding/json"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestPanelHY2MappingAndPasswordSurviveURIExport(t *testing.T) {
	row := Record{"protocol": "hysteria", "port": json.Number("24443"), "remark": "HY2", "settings": Record{"version": json.Number("2"), "clients": []any{Record{"auth": "correct:@ 密码", "password": "wrong", "email": "owned"}, Record{"auth": "disabled", "enable": false}}}, "streamSettings": Record{"network": "hysteria", "security": "tls", "tlsSettings": Record{"serverName": "vpn.example.com", "alpn": []any{"h3"}}}}
	nodes, err := InboundNodes(row, Record{"host": "198.51.100.10", "nodeAddress": "edge.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatal("disabled user exported")
	}
	node := nodes[0]
	if node["server"] != "edge.example.com" || node["password"] != "correct:@ 密码" || node["network"] != nil {
		t.Fatal("HY2 mapping differs")
	}
	uri, err := links.Export(node)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := links.Parse(uri)
	if err != nil || restored["password"] != node["password"] {
		t.Fatal("HY2 auth lost")
	}
	row["settings"].(Record)["version"] = json.Number("1")
	nodes, err = InboundNodes(row, Record{"host": "198.51.100.10"})
	if err != nil || len(nodes) != 0 {
		t.Fatal("Hysteria1 mislabelled as HY2")
	}
}
func TestParseChinesePanelSettings(t *testing.T) {
	settings, err := parsePanelSettings("port（面板端口）: 13145\nwebBasePath（访问路径）: /riben/\ncert: /cert.pem\n", Record{"host": "198.51.100.10", "domain": "panel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if settings["panelUrl"] != "https://panel.example.com:13145/riben/" {
		t.Fatal("panel address changed")
	}
	if _, err = parsePanelSettings("port: 80\nwebBasePath: /../secret/\n", Record{}); err == nil {
		t.Fatal("invalid panel path accepted")
	}
}

func TestInboundJSONRejectsTrailingDocumentsBeforeIdentityAndExport(t *testing.T) {
	for _, raw := range []string{`{"clients":[]} {"clients":[{"email":"other"}]}`, `{"clients":[]} garbage`, `{} null`} {
		if _, err := object(raw); err == nil {
			t.Fatal("trailing JSON accepted")
		}
		row := Record{"id": 1, "protocol": "vless", "settings": raw, "streamSettings": Record{}, "port": 443}
		if _, err := InboundNodes(row, Record{"host": "example.com"}); err == nil {
			t.Fatal("export accepted ambiguous settings")
		}
		if _, err := userSettings(row); err == nil {
			t.Fatal("identity accepted ambiguous settings")
		}
	}
	if _, err := object("{\"clients\":[]} \n\t"); err != nil {
		t.Fatal("valid trailing whitespace rejected", err)
	}
}

func TestPanelCleanupInventoryRejectsAmbiguousIdentity(t *testing.T) {
	for _, input := range [][]any{
		{Record{"id": 1}, nil}, {Record{"id": 1}, `{"id":2}`},
		{Record{"id": 1}, Record{"id": "01"}}, {Record{"id": 0}},
		{Record{"id": true}}, {Record{"id": json.Number("1.5")}},
	} {
		live, err := panelLiveInboundIDs(input)
		if err == nil || live != nil {
			t.Fatal("partial or ambiguous inventory could authorize cleanup", input, live, err)
		}
	}
	live, err := panelLiveInboundIDs([]any{Record{"id": json.Number("1")}, Record{"id": "02"}})
	if err != nil || !live["1"] || !live["2"] || len(live) != 2 {
		t.Fatal(live, err)
	}
	live, err = panelLiveInboundIDs([]any{})
	if err != nil || live == nil || len(live) != 0 {
		t.Fatal("valid empty inventory rejected", live, err)
	}
}

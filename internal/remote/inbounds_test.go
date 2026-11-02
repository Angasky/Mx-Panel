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

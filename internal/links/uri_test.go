package links

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestHY2StandardPathSNIAndEscapedPassword(t *testing.T) {
	node := map[string]any{"name": "HY2", "type": "hysteria2", "server": "2001:db8::1", "port": 24443, "password": ":@ p+secret", "servername": "tls.example.com"}
	uri, err := Export(node)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil || u.Path != "/" || u.Query().Get("sni") != "tls.example.com" {
		t.Fatal(uri, err)
	}
	restored, err := Parse(uri)
	if err != nil || restored["password"] != node["password"] {
		t.Fatal("HY2 password changed", restored, err)
	}
}

func TestPythonURICompatibility(t *testing.T) {
	data, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Node map[string]any
		URI  string
	}
	if json.Unmarshal(data, &rows) != nil {
		t.Fatal("fixture invalid")
	}
	for _, row := range rows {
		t.Run(text(row.Node["type"]), func(t *testing.T) {
			got, err := Parse(row.URI)
			if err != nil {
				t.Fatal("Python URI rejected", err)
			}
			exported, err := Export(got)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Parse(exported)
			if err != nil {
				t.Fatal(err)
			}
			fields := []string{"name", "type", "server", "port"}
			switch row.Node["type"] {
			case "vless", "vmess":
				fields = append(fields, "uuid")
			case "snell":
				fields = append(fields, "psk", "version")
			case "tuic":
				fields = append(fields, "uuid", "password")
			default:
				fields = append(fields, "password")
			}
			for _, key := range fields {
				if text(restored[key]) != text(row.Node[key]) {
					t.Fatalf("%s was not preserved", key)
				}
			}
		})
	}
}
func TestRealityAndTransportRoundTrip(t *testing.T) {
	value := "vless://22453845-ff1a-471d-8214-25952a9348a6@vpn.example.com:24443?security=reality&sni=www.example.com&pbk=test-public-key&sid=0123456789abcdef&flow=xtls-rprx-vision&fp=chrome#Reality"
	node, err := Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := Export(node)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	opts := restored["reality-opts"].(map[string]any)
	if opts["short-id"] != "0123456789abcdef" || opts["public-key"] != "test-public-key" {
		t.Fatal("Reality credentials changed")
	}
	value = "trojan://secret@vpn.example.com:443?security=tls&type=ws&path=%2Fvpn&host=ws.example.com&sni=vpn.example.com#WS"
	node, err = Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	uri, err = Export(node)
	if err != nil {
		t.Fatal(err)
	}
	restored, err = Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	ws := restored["ws-opts"].(map[string]any)
	if ws["path"] != "/vpn" {
		t.Fatal("WS path lost")
	}
}
func TestRejectsMalformedAndDoesNotLeakSecrets(t *testing.T) {
	for _, value := range []string{"snell://not-base64?version=4", "https://secret@host:0", "unknown://secret@host:443", "hy2://secret@host:99999"} {
		_, err := Parse(value)
		if err == nil {
			t.Fatal("bad URI accepted")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("credential leaked")
		}
	}
}

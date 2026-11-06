package remote

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func ss2022Fixture(method string) Record {
	size := 16
	if method == "2022-blake3-aes-256-gcm" {
		size = 32
	}
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, size)) }
	return Record{"id": 1, "tag": "ss-fixture", "remark": "SS2022", "protocol": "shadowsocks", "port": 24001,
		"settings": Record{"method": method, "password": key(1), "clients": []any{
			Record{"email": "first", "password": key(2)}, Record{"email": "second", "password": key(3)},
			Record{"email": "disabled", "password": key(4), "enable": false},
		}}, "streamSettings": Record{"network": "tcp", "security": "none"}}
}

func TestShadowsocksMultiUserExportsPreserveAuthentication(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		row := ss2022Fixture(method)
		before, _ := json.Marshal(row)
		nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
		if err != nil || len(nodes) != 2 {
			t.Fatal("multi-user SS2022 export missing", err)
		}
		settings := row["settings"].(Record)
		for i, node := range nodes {
			uri, err := links.Export(node)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := links.Parse(uri)
			want := value(settings["password"]) + ":" + value(anyRecords(settings["clients"])[i]["password"])
			if err != nil || parsed["password"] != want || parsed["cipher"] != method || parsed["name"] != node["name"] {
				t.Fatal("SS2022 URI lost a user credential", err)
			}
		}
		after, _ := json.Marshal(row)
		if string(before) != string(after) {
			t.Fatal("export mutated server metadata")
		}
		settings["clients"] = []any{}
		if nodes, err := InboundNodes(row, Record{}); err != nil || len(nodes) != 0 {
			t.Fatal("empty user list exported the server key", err)
		}
		if _, err := legacyNativeInbound("sing-box", row); err == nil {
			t.Fatal("empty users could fall back to single-user server-key authentication")
		}
	}
	row := Record{"protocol": "shadowsocks", "port": 24001, "settings": Record{"method": "aes-128-gcm", "password": "server-ignored", "clients": []any{
		Record{"password": "first", "method": "aes-256-gcm"}, Record{"password": "second", "method": "aes-128-gcm"},
	}}}
	nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
	if err != nil || len(nodes) != 2 || nodes[0]["cipher"] != "aes-256-gcm" || nodes[1]["cipher"] != "aes-128-gcm" || nodes[1]["password"] != "second" {
		t.Fatal("classic SS user methods or passwords leaked across users", err)
	}
	first := anyRecords(row["settings"].(Record)["clients"])[0]
	first["method"] = "2022-blake3-aes-128-gcm"
	if _, err := InboundNodes(row, Record{}); err == nil {
		t.Fatal("SS2022 user exported without its server key model")
	}
	first["method"] = "aes-256-gcm"
	delete(anyRecords(row["settings"].(Record)["clients"])[1], "method")
	if _, err := InboundNodes(row, Record{}); err == nil {
		t.Fatal("classic multi-user method guessed from the ignored server default")
	}
	delete(row["settings"].(Record), "clients")
	if nodes, err := InboundNodes(row, Record{}); err != nil || len(nodes) != 1 || nodes[0]["password"] != "server-ignored" {
		t.Fatal("legacy single-user SS changed", err)
	}
}

func TestShadowsocksMultiUserRejectsAmbiguousOrInvalidCredentials(t *testing.T) {
	for _, change := range []func(Record){
		func(row Record) { row["settings"].(Record)["clients"] = true },
		func(row Record) { row["settings"].(Record)["users"] = []any{} },
		func(row Record) { row["settings"].(Record)["password"] = "invalid" },
		func(row Record) { anyRecords(row["settings"].(Record)["clients"])[0]["password"] = "invalid" },
		func(row Record) { anyRecords(row["settings"].(Record)["clients"])[0]["method"] = "aes-128-gcm" },
		func(row Record) { row["streamSettings"].(Record)["security"] = "tls" },
		func(row Record) { row["streamSettings"].(Record)["network"] = "ws" },
	} {
		row := ss2022Fixture("2022-blake3-aes-128-gcm")
		change(row)
		if _, err := InboundNodes(row, Record{}); err == nil {
			t.Fatal("incomplete SS credentials or transport silently exported")
		}
	}
}

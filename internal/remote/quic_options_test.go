package remote

import (
	"maps"
	"reflect"
	"testing"
)

func TestSingQUICDefaultsMatchPythonAndRejectLostOptions(t *testing.T) {
	tuic := Record{"type": "tuic", "server": "example.net", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "password": "secret"}
	before := maps.Clone(tuic)
	out, err := singRelayOutbound(tuic, "proxy")
	if err != nil || out["congestion_control"] != "bbr" || out["udp_relay_mode"] != "native" {
		t.Fatal("Python defaults changed", out, err)
	}
	if !reflect.DeepEqual(tuic, before) {
		t.Fatal("source mutated")
	}
	for _, algorithm := range []string{"bbr", "cubic", "new_reno"} {
		for _, mode := range []string{"native", "quic"} {
			node := maps.Clone(tuic)
			node["congestion-controller"], node["udp-relay-mode"] = algorithm, mode
			out, err := singRelayOutbound(node, "proxy")
			if err != nil || out["congestion_control"] != algorithm || out["udp_relay_mode"] != mode {
				t.Fatal(out, err)
			}
		}
	}
	for _, field := range []string{"congestion-controller", "udp-relay-mode"} {
		for _, bad := range []any{nil, true, 12, "", "invalid"} {
			node := maps.Clone(tuic)
			node[field] = bad
			if _, err := singRelayOutbound(node, "proxy"); err == nil {
				t.Fatal("invalid explicit option accepted", field, bad)
			}
		}
	}
	hy := Record{"type": "hysteria2", "server": "example.net", "port": 443, "password": "secret"}
	for _, patch := range []Record{{"obfs-password": "orphan"}, {"obfs": "unknown", "obfs-password": "secret"}, {"obfs": nil}, {"obfs": "salamander"}, {"obfs": "salamander", "obfs-password": nil}, {"obfs": "salamander", "obfs-password": 12}, {"obfs": "salamander", "obfs-password": ""}} {
		node := maps.Clone(hy)
		maps.Copy(node, patch)
		if _, err := singRelayOutbound(node, "proxy"); err == nil {
			t.Fatal("lost or invalid obfuscation accepted", patch)
		}
	}
	hy["obfs"], hy["obfs-password"] = "salamander", "obfs-secret"
	out, err = singRelayOutbound(hy, "proxy")
	if err != nil || out["obfs"].(Record)["password"] != "obfs-secret" {
		t.Fatal("obfuscation lost", err)
	}
}

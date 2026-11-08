package remote

import (
	"encoding/json"
	"testing"
)

func TestManagedProtocolSwitchRequiresEmptyCanonicalSettings(t *testing.T) {
	row := transportEditFixture(t) // Initially has an independent user.
	if _, exposed := managedCoreFields(row)["protocol"]; exposed {
		t.Fatal("protocol edit exposed for an inbound retaining users")
	}
	if _, err := prepareManagedCoreEdit(row, Record{"protocol": "vmess"}); err == nil {
		t.Fatal("protocol switch reused existing user credentials")
	}
	row["settings"] = coreProtocolSettings("vless")
	row["settings"].(Record)["custom"] = true
	if _, err := prepareManagedCoreEdit(row, Record{"protocol": "vmess"}); err == nil {
		t.Fatal("protocol switch discarded extension settings")
	}
	delete(row["settings"].(Record), "custom")
	for _, invalid := range []any{"shadowsocks", "", true, Record{}} {
		if _, err := prepareManagedCoreEdit(row, Record{"protocol": invalid}); err == nil {
			t.Fatal("unsupported protocol accepted")
		}
	}
	before, _ := json.Marshal(row)
	next, err := prepareManagedCoreEdit(row, Record{"protocol": "vmess", "network": "grpc", "grpcService": "converted"})
	if err != nil {
		t.Fatal(err)
	}
	settings := next["settings"].(Record)
	if next["protocol"] != "vmess" || settings["decryption"] != nil || settings["disableInsecureEncryption"] != false ||
		next["streamSettings"].(Record)["grpcSettings"].(Record)["serviceName"] != "converted" {
		t.Fatal("protocol/transport conversion retained incompatible fields")
	}
	after, _ := json.Marshal(row)
	if string(before) != string(after) {
		t.Fatal("protocol conversion mutated original metadata")
	}
	first, err := NewUser(next)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewUser(next)
	if err != nil || first["id"] == second["id"] || value(first["flow"]) != "" {
		t.Fatal("reimport did not create independent protocol-compatible UUIDs", err)
	}
	restored, err := prepareManagedCoreEdit(next, Record{"protocol": "vless"})
	if err != nil || !sameCoreInbound(restored["settings"].(Record), coreProtocolSettings("vless")) {
		t.Fatal("VMess to VLESS conversion kept VMess settings", err)
	}
}

func TestManagedTLSProtocolConversionsKeepAuthenticationSeparated(t *testing.T) {
	for _, source := range []string{"vless", "vmess", "trojan"} {
		for _, target := range []string{"vless", "vmess", "trojan"} {
			t.Run(source+"/"+target, func(t *testing.T) {
				row := transportEditFixture(t)
				row["protocol"], row["settings"] = source, coreProtocolSettings(source)
				before, _ := json.Marshal(row)
				next, err := prepareManagedCoreEdit(row, Record{"protocol": target, "network": "grpc", "grpcService": "converted"})
				if err != nil || next["protocol"] != target || !sameCoreInbound(next["settings"].(Record), coreProtocolSettings(target)) {
					t.Fatal("protocol conversion retained incompatible authentication settings", err)
				}
				first, err := NewUser(next)
				if err != nil {
					t.Fatal(err)
				}
				second, err := NewUser(next)
				field := "id"
				if target == "trojan" {
					field = "password"
					if first["id"] != nil {
						t.Fatal("Trojan user retained a UUID")
					}
				} else if first["password"] != nil {
					t.Fatal("UUID protocol retained a Trojan password")
				}
				if err != nil || value(first[field]) == "" || first[field] == second[field] {
					t.Fatal("converted protocol reused authentication credentials", err)
				}
				after, _ := json.Marshal(row)
				if string(before) != string(after) {
					t.Fatal("conversion mutated source metadata")
				}
			})
		}
	}
}

func TestProtocolSwitchPreservesHostAndALPN(t *testing.T) {
	for _, source := range []string{"vless", "vmess", "trojan"} {
		for _, target := range []string{"vless", "vmess", "trojan"} {
			row := transportEditFixture(t)
			row["settings"] = coreProtocolSettings("vless")
			row, err := prepareManagedCoreEdit(row, Record{"network": "ws", "wsHost": "cdn.example.com", "wsPath": "/owned", "alpn": "http/1.1,h2"})
			if err != nil {
				t.Fatal(err)
			}
			row["protocol"], row["settings"] = source, coreProtocolSettings(source)
			before, _ := json.Marshal(row)
			next, err := prepareManagedCoreEdit(row, Record{"protocol": target})
			if err != nil {
				t.Fatal(err)
			}
			if next["protocol"] != target || !sameCoreInbound(row["streamSettings"].(Record), next["streamSettings"].(Record)) {
				t.Fatal("protocol switch altered Host, ALPN, or TLS")
			}
			if _, exposed := managedCoreFields(next)["network"]; exposed {
				t.Fatal("lossy transport switch enabled")
			}
			if _, err := prepareManagedCoreEdit(next, Record{"network": "grpc"}); err == nil {
				t.Fatal("transport switch discarded retained fields")
			}
			after, _ := json.Marshal(row)
			if string(before) != string(after) {
				t.Fatal("source mutated")
			}
			user, err := NewUser(next)
			if err != nil {
				t.Fatal(err)
			}
			next["settings"].(Record)["clients"] = []any{user}
			if _, err := prepareManagedCoreEdit(next, Record{"protocol": source}); err == nil {
				t.Fatal("retained user allowed conversion")
			}
		}
	}
}

func TestProtocolSwitchRetainsExtensionGuards(t *testing.T) {
	for _, change := range []func(Record){
		func(r Record) {
			r["streamSettings"].(Record)["wsSettings"].(Record)["headers"] = Record{"X-Custom": "keep"}
		},
		func(r Record) {
			r["streamSettings"].(Record)["wsSettings"].(Record)["headers"] = Record{"Host": "bad/path"}
		},
		func(r Record) { r["streamSettings"].(Record)["tlsSettings"].(Record)["alpn"] = []any{"custom"} },
		func(r Record) { r["streamSettings"].(Record)["sockopt"] = Record{"mark": 1} },
	} {
		row := transportEditFixture(t)
		row["settings"] = coreProtocolSettings("vless")
		row, err := prepareManagedCoreEdit(row, Record{"network": "ws"})
		if err != nil {
			t.Fatal(err)
		}
		change(row)
		if _, err := prepareManagedCoreEdit(row, Record{"protocol": "trojan"}); err == nil {
			t.Fatal("unknown or invalid transport accepted")
		}
	}
}

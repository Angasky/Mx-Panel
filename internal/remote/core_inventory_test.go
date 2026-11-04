package remote

import (
	"strings"
	"testing"
)

func TestCoreInventoryLegacyIDsAndNativePresence(t *testing.T) {
	saved := `{"inbounds":[{"id":17,"port":443,"tag":"mxioc-inbound-17","protocol":"vless","settings":{"private":"secret"}},{"id":18,"port":444,"tag":"mxioc-inbound-18","protocol":"vless","enable":false},{"id":19,"port":445,"tag":"mxioc-inbound-19","protocol":"vless"},{"id":20,"port":446,"tag":"mxioc-inbound-20","protocol":"vless"}]}`
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			protocol, port := "protocol", "port"
			if kind == "sing-box" {
				protocol, port = "type", "listen_port"
			}
			doc := Record{"inbounds": []any{
				Record{"tag": "mxioc-inbound-17", protocol: "vless", port: 443},
				Record{"tag": "mxioc-inbound-20", protocol: "vless", port: 447},
				Record{"tag": "unmanaged", protocol: "vless", port: 448},
			}}
			result, err := coreInventory(kind, Record{"coreState": "encrypted"}, doc, saved)
			if err != nil {
				t.Fatal(err)
			}
			rows := result["inbounds"].([]any)
			if result["readOnly"] != true || len(rows) != 4 || result["server"].(Record)["coreState"] != nil {
				t.Fatalf("unexpected inventory: %v", result)
			}
			for i, status := range []string{"mismatch", "disabled", "missing", "mismatch"} {
				row := rows[i].(Record)
				if row["coreStatus"] != status || row["id"] != 17+i || row["settings"] != nil {
					t.Errorf("unexpected row: %v", row)
				}
				if (len(value(row["missingUserIdentity"])) == 64) != (status == "missing") {
					t.Errorf("unexpected absence proof for %s", status)
				}
			}
			pending, err := coreInventory(kind, Record{"coreUserPending": "pending"}, doc, saved)
			if err != nil || anyRecords(pending["inbounds"])[2]["missingUserIdentity"] != nil {
				t.Fatal("pending operation must not establish absence", err)
			}
		})
	}
}

func TestCoreInventoryRejectsMalformedRecords(t *testing.T) {
	for _, saved := range []string{`{}`, `{"inbounds":[null]}`, `{"inbounds":[{"id":1,"port":443,"tag":"manual","protocol":"vless"}]}`} {
		if _, err := coreInventory("xray", nil, Record{}, saved); err == nil {
			t.Errorf("accepted %s", saved)
		}
	}
	doc := Record{"inbounds": []any{Record{"tag": "duplicate"}, Record{"tag": "duplicate"}}}
	if _, err := coreInventory("xray", nil, doc, ""); err == nil {
		t.Error("accepted duplicate native tags")
	}
}

func TestCoreInventoryVerifiesLegacyUsersBeforeSharing(t *testing.T) {
	saved := `{"inbounds":[{"id":17,"port":443,"tag":"mxioc-inbound-17","remark":"legacy","protocol":"vless","settings":{"clients":[{"id":"3c5827c6-2f92-4861-a1f8-562d5388bca7","email":"valid"},{"id":"30403cc4-583b-426a-8424-ec98489977b2","email":"disabled","enable":false}],"decryption":"none"}}]}`
	xray := `{"inbounds":[{"tag":"mxioc-inbound-17","protocol":"vless","listen":"0.0.0.0","port":443,"settings":{"clients":[{"id":"3c5827c6-2f92-4861-a1f8-562d5388bca7","email":"valid"}],"decryption":"none"},"streamSettings":{},"sniffing":{}}]}`
	sing := `{"inbounds":[{"tag":"mxioc-inbound-17","type":"vless","listen":"::","listen_port":443,"users":[{"uuid":"3c5827c6-2f92-4861-a1f8-562d5388bca7","name":"valid"}]}]}`
	for kind, config := range map[string]string{"xray": xray, "sing-box": sing} {
		for _, changed := range []bool{false, true} {
			raw := config
			if changed {
				raw = strings.ReplaceAll(raw, "3c5827c6-2f92-4861-a1f8-562d5388bca7", "94f022d0-9ab0-4664-96de-82aca7677c74")
			}
			doc, err := object(raw)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coreInventory(kind, Record{"host": "example.net"}, doc, saved)
			if err != nil {
				t.Fatal(err)
			}
			row := result["inbounds"].([]any)[0].(Record)
			shares := row["shareLinks"].([]any)
			if changed && (row["coreStatus"] != "mismatch" || len(shares) != 0) {
				t.Fatalf("%s: credential drift should prevent export", kind)
			}
			if !changed && (row["coreStatus"] != "present" || len(shares) != 1 ||
				!strings.HasPrefix(shares[0].(string), "vless://3c5827c6-2f92-4861-a1f8-562d5388bca7@")) {
				t.Fatalf("%s: verified enabled user should have exactly one share", kind)
			}
		}
	}
}

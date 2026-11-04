package remote

import "testing"

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
			for i, status := range []string{"present", "disabled", "missing", "mismatch"} {
				row := rows[i].(Record)
				if row["coreStatus"] != status || row["id"] != 17+i || row["settings"] != nil {
					t.Errorf("unexpected row: %v", row)
				}
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

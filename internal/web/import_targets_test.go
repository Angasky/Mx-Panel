package web

import (
	"encoding/json"
	"testing"
)

func TestImportTargetsContractAndAccessControl(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	body := `{"serverId":"source","inboundIds":[1,2]}`
	w := request(s, "POST", "/admin/api/servers/users/targets", body, token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		Profiles []struct {
			ID, Name           string
			ImportedInboundIDs []int
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Profiles) != 1 || result.Profiles[0].ImportedInboundIDs == nil {
		t.Fatal(w.Body.String())
	}
	if w := request(s, "POST", "/admin/api/servers/users/targets", body, "", "https://panel.test", true); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(s, "POST", "/admin/api/servers/users/targets", body, token, "https://other.test", true); w.Code != 403 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{`{}`, `{"serverId":"s","inboundIds":[1,1]}`, `{"serverId":"s","inboundIds":[true]}`} {
		if w := request(s, "POST", "/admin/api/servers/users/targets", bad, token, "https://panel.test", true); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
}

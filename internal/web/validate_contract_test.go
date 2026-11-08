package web

import (
	"encoding/json"
	"testing"
)

func TestNodeValidationReturnsPythonShareContract(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for _, extra := range []string{"", `,"dialer-proxy":"upstream"`} {
		w := request(s, "POST", "/admin/api/nodes/validate", `{"config":{"name":"node","type":"http","server":"example.net","port":80`+extra+`}}`, token, "https://panel.test", true)
		var result map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		uri, exists := result["uri"]
		if !exists || extra == "" && uri == nil || extra != "" && uri != nil {
			t.Fatal("validation share contract mismatch", result)
		}
	}
	for _, sid := range []string{`"abc"`, `12`, `"invalid"`} {
		w := request(s, "POST", "/admin/api/nodes/validate", `{"config":{"name":"Reality","type":"vless","uuid":"11111111-1111-4111-8111-111111111111","server":"example.net","port":443,"tls":true,"reality-opts":{"public-key":"key","short-id":`+sid+`}}}`, token, "https://panel.test", true)
		if w.Code != 400 {
			t.Fatal("invalid Reality node accepted", w.Code)
		}
	}
}

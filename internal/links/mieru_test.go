package links

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func mieruURI(ports, protocols []string) string {
	q := url.Values{"profile": {"测试 Mieru"}, "port": ports, "protocol": protocols}
	return "mierus://user:fixture-secret@example.com?" + q.Encode()
}
func TestMieruPythonVectorsAndRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("testdata/mieru-python.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			URI   string
			Nodes []map[string]any
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, row := range fixture.Cases {
		nodes, err := ParseMany(row.URI)
		if err != nil {
			t.Fatal(i, err)
		}
		a, _ := json.Marshal(nodes)
		b, _ := json.Marshal(row.Nodes)
		if string(a) != string(b) {
			t.Fatalf("Python compatibility mismatch %d: %s / %s", i, a, b)
		}
		for _, node := range nodes {
			uri, err := Export(node)
			if err != nil {
				t.Fatal(i, err)
			}
			restored, err := Parse(uri)
			if err != nil || !reflect.DeepEqual(node, restored) {
				t.Fatal("round trip changed credentials/options", i, err)
			}
		}
		if len(nodes) > 1 {
			if _, err = Parse(row.URI); err == nil {
				t.Fatal("single-node parser silently dropped bindings")
			}
		}
	}
}
func TestMieruRejectsInvalidOptionsWithoutLeakingCredentials(t *testing.T) {
	base := mieruURI([]string{"2999"}, []string{"TCP"})
	invalid := []string{
		"mieru://fixture-secret", strings.Replace(base, "example.com?", "example.com:2999?", 1),
		base + "&profile=duplicate", base + "&unknown=option", base + "&mtu=1300", base + "&mtu=1400&mtu=1400",
		base + "&handshake-mode=bad", base + "&multiplexing=bad", base + "&traffic-pattern=%%%",
		"mierus://user:fixture-secret@example.com?profile=%FF&port=2999&protocol=TCP", base + "#%FF",
		mieruURI([]string{"65536"}, []string{"TCP"}), mieruURI([]string{"3000-2999"}, []string{"UDP"}), mieruURI([]string{"2999", "3000"}, []string{"TCP"}), mieruURI([]string{"2999"}, []string{"QUIC"}),
		strings.Replace(base, "fixture-secret", strings.Repeat("x", 65), 1), strings.Replace(base, "fixture-secret", "%0Afixture-secret", 1),
	}
	for i, uri := range invalid {
		nodes, err := ParseMany(uri)
		if err == nil || nodes != nil {
			t.Fatal("invalid link partially accepted", i)
		}
		if strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("credential leaked", i)
		}
	}
	ports, protocols := []string{}, []string{}
	for i := 0; i < 257; i++ {
		ports = append(ports, "2999")
		protocols = append(protocols, "TCP")
	}
	if _, err := ParseMany(mieruURI(ports, protocols)); err == nil {
		t.Fatal("binding cap ignored")
	}
}
func TestMieruNormalizationAndLossyShareRefusal(t *testing.T) {
	node, err := Parse(mieruURI([]string{"02999"}, []string{"tcp"}))
	if err != nil {
		t.Fatal(err)
	}
	if node["port"] != 2999 || node["transport"] != "TCP" {
		t.Fatal("not normalized")
	}
	node["port-range"] = "03000-03002"
	if _, err = NormalizeMieru(node); err == nil {
		t.Fatal("port and range accepted together")
	}
	delete(node, "port")
	node["mtu"] = 1400
	copy, err := NormalizeMieru(node)
	if err != nil || copy["port-range"] != "3000-3002" || copy["mtu"] != nil || node["mtu"] != 1400 {
		t.Fatal("normalization mutated input", err)
	}
	for key, value := range map[string]any{"udp": false, "dialer-proxy": "entry", "custom-option": true} {
		changed := map[string]any{}
		for k, v := range copy {
			changed[k] = v
		}
		changed[key] = value
		if _, err = Export(changed); err == nil {
			t.Fatal("lossy share accepted", key)
		}
	}
	for _, value := range []any{true, 2999.0, "2999.0", json.Number("2999.0")} {
		copy["port"] = value
		delete(copy, "port-range")
		if _, err = NormalizeMieru(copy); err == nil {
			t.Fatal("non-integer port accepted")
		}
	}
	copy["port"] = 2999
	copy["username"] = strings.Repeat("你", 22)
	if _, err = NormalizeMieru(copy); err == nil {
		t.Fatal("UTF8 byte limit ignored")
	}
	copy["username"] = "user"
	copy["traffic-pattern"] = base64.StdEncoding.EncodeToString([]byte("fixture"))
	if _, err = NormalizeMieru(copy); err != nil {
		t.Fatal(err)
	}
	copy["traffic-pattern"] = "Zg==\n"
	if _, err = NormalizeMieru(copy); err == nil {
		t.Fatal("strict Base64 ignored")
	}
}

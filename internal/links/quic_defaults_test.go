package links

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPythonQUICDefaultsAndOverrides(t *testing.T) {
	for _, base := range []string{"hy2://secret@example.net:443", "tuic://11111111-1111-4111-8111-111111111111:secret@example.net:443"} {
		for _, query := range []string{"", "?alpn=", "?alpn=custom,h3"} {
			node, err := Parse(base + query)
			if err != nil {
				t.Fatal(err)
			}
			expected := "h3"
			count := 1
			if query == "?alpn=custom,h3" {
				expected = "custom"
				count = 2
			}
			if node["type"] == "tuic" && query != "?alpn=custom,h3" {
				count = 0
				expected = ""
			}
			alpn, ok := node["alpn"].([]any)
			if (count > 0 && !ok) || len(alpn) != count || (count > 0 && alpn[0] != expected) {
				t.Fatal("Python ALPN default or override lost")
			}
			if node["type"] == "tuic" && (node["congestion-controller"] != "bbr" || node["udp-relay-mode"] != "native") {
				t.Fatal("TUIC defaults missing")
			}
			uri, err := Export(node)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			values, _ := restored["alpn"].([]any)
			if len(values) != count || (count > 0 && values[0] != expected) {
				t.Fatal("ALPN changed on sharing")
			}
		}
	}
	node, err := Parse("tuic://11111111-1111-4111-8111-111111111111:secret@example.net:443?congestion_control=cubic&udp_relay_mode=quic&alpn=custom")
	if err != nil || node["congestion-controller"] != "cubic" || node["udp-relay-mode"] != "quic" || node["alpn"].([]any)[0] != "custom" {
		t.Fatal("explicit settings overwritten", err)
	}
}

func TestPythonQUICExtractedFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_quic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			URI      string
			Expected map[string]any
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, sample := range fixture.Cases {
		node, err := Parse(sample.URI)
		if err != nil {
			t.Fatal(err)
		}
		for key, expected := range sample.Expected {
			if key == "alpn" && node["type"] == "tuic" && !strings.Contains(sample.URI, "alpn=") {
				if node["alpn"] != nil {
					t.Fatal("implicit TUIC ALPN was forced")
				}
				continue
			}
			actual, _ := json.Marshal(node[key])
			want, _ := json.Marshal(expected)
			if string(actual) != string(want) {
				t.Fatalf("Python parity mismatch for %s", key)
			}
		}
	}
}

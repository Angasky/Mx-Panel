package links

import "testing"

func TestSnellPolicyCredentialsIPv6AndAmbiguousURIs(t *testing.T) {
	node, err := Parse("HK = Snell , [2606:4700:4700::1111], 24443, psk=a+b/c@d, version=5, udp=true")
	if err != nil || node["psk"] != "a+b/c@d" || node["server"] != "2606:4700:4700::1111" || node["version"] != 5 || node["udp"] != true {
		t.Fatal(node, err)
	}
	node, err = Parse("snell://host.example.com:24443?psk=snell,secret&version=5#A")
	if err != nil || node["psk"] != "snell,secret" {
		t.Fatal("URI was mistaken for policy", node, err)
	}
	for _, line := range []string{"A = snell, host, 1, psk=a, psk=b", "A = snell, host, 1, psk=a, unknown=b", "A = snell, host, 1, psk=a, obfs-host=example.com", "A = snell, host, 1, psk='a'", "A = snell, host, 1, psk=a, version=6"} {
		if _, err := Parse(line); err == nil {
			t.Fatal("ambiguous policy accepted", line)
		}
	}
}

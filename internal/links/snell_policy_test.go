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

func TestSnellURIRejectsConflictingOrLossyParameters(t *testing.T) {
	for _, uri := range []string{
		"snell://secret@host:443?psk=other", "snell://user:password@host:443",
		"snell://secret@host:443?version=", "snell://secret@host:443?version=01",
		"snell://secret@host:443?udp=true", "snell://secret@host:443?version=3&reuse=1",
		"snell://secret@host:443?obfs-host=example.com", "snell://secret@host:443?obfs=",
		"snell://secret@host:443?security=tls", "snell://secret@host:443?type=ws",
		"snell://secret@host:443?obfs=http&obfs-host=", "snell://%00@host:443",
	} {
		if _, err := Parse(uri); err == nil {
			t.Fatal("accepted incompatible Snell URI", uri)
		}
	}
	for _, uri := range []string{
		"snell://secret@host:443?version=5&udp=TRUE&reuse=FALSE&tfo=TRUE",
		"snell://host:443?%70sk=secret&version=5",
		"snell://secret@host:443?obfs=http",
	} {
		if _, err := Parse(uri); err != nil {
			t.Fatal(uri, err)
		}
	}
	// A question mark inside the fragment belongs to the name, not to the query.
	uri, err := Export(map[string]any{"name": "name?psk=label", "type": "snell", "server": "host", "port": 443, "psk": "secret", "version": 5})
	if err != nil {
		t.Fatal(err)
	}
	node, err := Parse(uri)
	if err != nil || node["name"] != "name?psk=label" || node["psk"] != "secret" {
		t.Fatal(node, err)
	}
}

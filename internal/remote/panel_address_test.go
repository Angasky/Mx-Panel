package remote

import (
	"testing"
)

func TestPanelAddressPythonPathsAndInternationalHosts(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		port        int
	}{
		{" https://PANEL.example.com:13145/riben/// ", "https://panel.example.com:13145/riben/", 13145},
		{"http://[2001:db8::1]:80", "http://[2001:db8::1]:80/", 80},
		{"https://你好.example.com/路径/", "https://xn--6qq79v.example.com/%E8%B7%AF%E5%BE%84/", 443},
		{"https://panel.example.com/a%2Fb/", "https://panel.example.com/a%2Fb/", 443},
	} {
		got, port, err := parsePanelAddress(tc.input)
		if err != nil || port != tc.port || got.String() != tc.want {
			t.Fatal(tc, got, port, err)
		}
	}
	for _, input := range []string{
		"https://user:pass@example.com/", "https://panel.example.com/a/../b/",
		"https://panel.example.com/%2e%2e/", "https://panel.example.com/%00/",
		"https://panel.example.com/%5c/", "https://panel.example.com/a\\b/",
		"https://panel.example.com/a b/", "https://panel.example.com/%zz/",
		"https://panel.example.com:0/", "https://panel.example.com:/",
		"https://panel.example.com/?a=b", "https://panel.example.com/#f",
		"https://[fe80::1%25eth0]/", "https://-bad.example.com/",
	} {
		if _, _, err := parsePanelAddress(input); err == nil {
			t.Fatal("invalid panel address accepted", input)
		}
	}
}

func TestServerSaveRejectsUnsafePanelPaths(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/../", "/%2e/", "/%0a/", "/%5c/"} {
		payload := serverPayload()
		payload["panelAddress"] = "https://panel.example.com" + path
		if _, err := m.Save(payload); err == nil {
			t.Fatal("unsafe saved path", path)
		}
	}
	payload := serverPayload()
	payload["panelAddress"] = "https://你好.example.com/a%2Fb/"
	record, err := m.Save(payload)
	if err != nil || record["panelPath"] != "/a%2Fb/" {
		t.Fatal(record, err)
	}
}

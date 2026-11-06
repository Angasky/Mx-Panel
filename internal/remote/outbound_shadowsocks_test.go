package remote

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestSS2022OutboundPasswordValidation(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, size))
		n := Record{"name": "ss", "type": "ss", "server": "example.com", "port": 23456, "cipher": method, "password": key + ":" + key}
		outbound, err := NodeOutbound(n, "test")
		if err != nil {
			t.Fatal(err)
		}
		endpoint := outbound["settings"].(Record)["servers"].([]any)[0].(Record)
		if endpoint["password"] != n["password"] || endpoint["method"] != method {
			t.Fatal("outbound changed credentials")
		}
		for _, bad := range []string{key + ":", key + ":" + key + ":" + key, key + "\n"} {
			n["password"] = bad
			if _, err := NodeOutbound(n, "test"); err == nil {
				t.Fatal("invalid outbound password accepted")
			}
		}
		n["cipher"] = "2022-unknown"
		n["password"] = key
		if _, err := NodeOutbound(n, "test"); err == nil {
			t.Fatal("unknown cipher accepted")
		}
	}
}

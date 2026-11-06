package links

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"testing"
)

func TestSS2022PasswordValidationAtURIBoundary(t *testing.T) {
	key16 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	key32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	cases := []struct {
		method, password string
		valid            bool
	}{
		{"2022-blake3-aes-128-gcm", key16, true},
		{"2022-blake3-aes-128-gcm", key16 + ":" + key16, true},
		{"2022-blake3-aes-256-gcm", key32 + ":" + key32, true},
		{"2022-blake3-chacha20-poly1305", key32, true},
		{"2022-blake3-chacha20-poly1305", key32 + ":" + key32, false},
		{"2022-unknown", key32, false},
		{"2022-blake3-aes-128-gcm", key32, false},
		{"2022-blake3-aes-128-gcm", key16 + ":" + key32, false},
		{"2022-blake3-aes-128-gcm", key16 + ":" + key16 + ":" + key16, false},
		{"2022-blake3-aes-128-gcm", key16 + "\r\n", false},
		{"2022-blake3-aes-128-gcm", key16[:len(key16)-3] + "B==", false},
		{"2022-blake3-aes-128-gcm", "", false},
	}
	for i, tc := range cases {
		if (ValidateSS2022Password(tc.method, tc.password) == nil) != tc.valid {
			t.Fatalf("validator case %d", i)
		}
		n := map[string]any{"name": "SS", "type": "ss", "server": "example.com", "port": 23456, "cipher": tc.method, "password": tc.password}
		if _, err := Export(n); (err == nil) != tc.valid {
			t.Fatalf("export case %d", i)
		}
		uri := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(tc.method+":"+tc.password)) + "@example.com:23456#SS"
		if _, err := Parse(uri); (err == nil) != tc.valid {
			t.Fatalf("parse encoded case %d", i)
		}
		uri = "ss://" + url.UserPassword(tc.method, tc.password).String() + "@example.com:23456#SS"
		if _, err := Parse(uri); (err == nil) != tc.valid {
			t.Fatalf("parse plain case %d", i)
		}
	}
	classic := map[string]any{"name": "legacy", "type": "ss", "server": "example.com", "port": 23456, "cipher": "aes-128-gcm", "password": "arbitrary:password"}
	uri, err := Export(classic)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Parse(uri)
	if err != nil || n["password"] != classic["password"] {
		t.Fatal("classic password changed", err)
	}
}

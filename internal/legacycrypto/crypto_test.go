package legacycrypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Key        string `json:"key"`
	Token      string `json:"token"`
	Plain      string `json:"plain"`
	Password   string `json:"password"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

func TestPythonFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []vector
	if err = json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	for _, v := range rows {
		got, err := DecryptFernet([]byte(v.Key), v.Token)
		if err != nil || string(got) != v.Plain {
			t.Fatal("Python credential decryption failed")
		}
		if !VerifyPassword(v.Password, v.Salt, v.Hash, v.Iterations) {
			t.Fatal("Python password verification failed")
		}
		if VerifyPassword(v.Password+"wrong", v.Salt, v.Hash, v.Iterations) {
			t.Fatal("wrong password accepted")
		}
		raw, _ := base64.URLEncoding.DecodeString(v.Token)
		for _, offset := range []int{0, 1, 9, 25, len(raw) - 1} {
			changed := bytes.Clone(raw)
			changed[offset] ^= 1
			if _, err := DecryptFernet([]byte(v.Key), base64.URLEncoding.EncodeToString(changed)); err == nil {
				t.Fatal("tampered token accepted")
			}
		}
	}
}

func TestRoundTripAndMalformed(t *testing.T) {
	key := []byte(base64.URLEncoding.EncodeToString(make([]byte, 32)))
	for _, p := range [][]byte{nil, []byte("secret"), []byte("密码:@+/"), make([]byte, 16), make([]byte, 100)} {
		token, err := EncryptFernet(key, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptFernet(key, token)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatal("round trip failed")
		}
	}
	for _, s := range []string{"", "!", "AAAA", base64.URLEncoding.EncodeToString(make([]byte, 74))} {
		if _, err := DecryptFernet(key, s); err == nil {
			t.Fatal("malformed token accepted")
		}
	}
	if _, err := DecryptFernet([]byte("bad key"), ""); err == nil {
		t.Fatal("bad key accepted")
	}
	salt, hash, err := NewPassword("sample-password")
	if err != nil || !VerifyPassword("sample-password", salt, hash, 600000) {
		t.Fatal("new password failed")
	}
}

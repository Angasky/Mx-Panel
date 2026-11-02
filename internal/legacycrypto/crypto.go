// Package legacycrypto preserves the Python edition's credential formats.
package legacycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

var ErrCredential = errors.New("invalid credential data")

// VerifyPassword accepts the same PBKDF2-HMAC-SHA256 JSON fields as Python.
func VerifyPassword(password, saltHex, hashHex string, iterations int) bool {
	if iterations < 100000 || iterations > 2000000 {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := hex.DecodeString(hashHex)
	if err != nil || len(expected) != 32 {
		return false
	}
	actual, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	return err == nil && subtle.ConstantTimeCompare(actual, expected) == 1
}

// NewPassword uses the current Python edition's 600000-iteration format.
func NewPassword(password string) (saltHex, hashHex string, err error) {
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	var digest []byte
	digest, err = pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		return
	}
	return hex.EncodeToString(salt), hex.EncodeToString(digest), nil
}

func decodeKey(encoded []byte) ([]byte, error) {
	key, err := base64.URLEncoding.DecodeString(string(encoded))
	if err != nil || len(key) != 32 {
		return nil, ErrCredential
	}
	return key, nil
}

// DecryptFernet authenticates the entire token before decryption. Credential
// tokens have no TTL in the Python edition; their timestamp is not an expiry.
func DecryptFernet(encodedKey []byte, token string) ([]byte, error) {
	key, err := decodeKey(encodedKey)
	if err != nil {
		return nil, err
	}
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil || len(data) < 73 || data[0] != 0x80 || (len(data)-57)%aes.BlockSize != 0 {
		return nil, ErrCredential
	}
	signed := data[:len(data)-32]
	mac := hmac.New(sha256.New, key[:16])
	mac.Write(signed)
	if !hmac.Equal(mac.Sum(nil), data[len(data)-32:]) {
		return nil, ErrCredential
	}
	block, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, ErrCredential
	}
	plain := make([]byte, len(signed)-25)
	cipher.NewCBCDecrypter(block, signed[9:25]).CryptBlocks(plain, signed[25:])
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plain) {
		return nil, ErrCredential
	}
	valid := 1
	for _, b := range plain[len(plain)-padding:] {
		valid &= subtle.ConstantTimeByteEq(b, byte(padding))
	}
	if valid != 1 {
		return nil, ErrCredential
	}
	return plain[:len(plain)-padding], nil
}

// EncryptFernet emits tokens that Python cryptography.fernet can read.
func EncryptFernet(encodedKey, plain []byte) (string, error) {
	key, err := decodeKey(encodedKey)
	if err != nil {
		return "", err
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	data := make([]byte, 25+len(plain)+padding)
	data[0] = 0x80
	binary.BigEndian.PutUint64(data[1:9], uint64(time.Now().Unix()))
	if _, err = rand.Read(data[9:25]); err != nil {
		return "", err
	}
	padded := make([]byte, len(plain)+padding)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	block, err := aes.NewCipher(key[16:])
	if err != nil {
		return "", err
	}
	cipher.NewCBCEncrypter(block, data[9:25]).CryptBlocks(data[25:], padded)
	mac := hmac.New(sha256.New, key[:16])
	mac.Write(data)
	return base64.URLEncoding.EncodeToString(append(data, mac.Sum(nil)...)), nil
}

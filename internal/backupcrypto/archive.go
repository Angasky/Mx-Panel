// Package backupcrypto implements a versioned, password-protected file format.
package backupcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const MaxPlaintext = 1 << 20
const MaxArchive = MaxPlaintext + 128

var magic = []byte("MXP-BACKUP\x00\x01")

func passwordOK(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 && len(password) <= 256
}
func key(password string, salt []byte) (cipher.AEAD, error) {
	k, e := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	defer clear(k)
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func Encrypt(data []byte, password string) ([]byte, error) {
	if !passwordOK(password) {
		return nil, errors.New("备份密码需至少 12 个字符且不超过 256 字节")
	}
	if len(data) == 0 || len(data) > MaxPlaintext {
		return nil, errors.New("备份内容为空或超过 1 MiB")
	}
	header := append([]byte{}, magic...)
	random := make([]byte, 28)
	if _, e := rand.Read(random); e != nil {
		return nil, errors.New("无法生成备份随机数")
	}
	header = append(header, random...)
	a, e := key(password, random[:16])
	if e != nil {
		return nil, errors.New("备份加密失败")
	}
	return a.Seal(header, random[16:], data, header), nil
}
func Decrypt(data []byte, password string) ([]byte, error) {
	if !passwordOK(password) {
		return nil, errors.New("备份密码需至少 12 个字符且不超过 256 字节")
	}
	h := len(magic) + 28
	if len(data) < h+16 || len(data) > MaxArchive || !bytes.Equal(data[:len(magic)], magic) {
		return nil, errors.New("文件不是支持的 MX-Panel 加密备份，或超过大小限制")
	}
	a, e := key(password, data[len(magic):len(magic)+16])
	if e != nil {
		return nil, errors.New("备份解密失败")
	}
	plain, e := a.Open(nil, data[len(magic)+16:h], data[h:], data[:h])
	if e != nil {
		return nil, errors.New("密码不正确或备份文件已损坏")
	}
	if len(plain) == 0 || len(plain) > MaxPlaintext {
		return nil, errors.New("备份内容大小无效")
	}
	return plain, nil
}

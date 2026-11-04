package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

// bootstrap creates only new files. Legacy state is always opened in place by
// normal startup and is never initialized or overwritten by this command.
func bootstrap(root, auth, username string, input io.Reader) error {
	if len(username) < 3 || len(username) > 64 || strings.ContainsAny(username, ":\x00") || strings.IndexFunc(username, unicode.IsSpace) >= 0 {
		return errors.New("administrator username must be 3 to 64 bytes without spaces or colons")
	}
	password, err := io.ReadAll(io.LimitReader(input, 1026))
	if err != nil {
		return err
	}
	secret := strings.TrimSuffix(string(password), "\n")
	if len(secret) < 12 || len(secret) > 1024 || strings.ContainsAny(secret, "\r\n\x00") {
		return errors.New("administrator password must be a single line of 12 to 1024 bytes")
	}
	profiles := filepath.Join(root, "profiles.json")
	for _, path := range []string{auth, profiles} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("bootstrap requires a new credential file and subscription index")
		}
	}
	salt, hash, err := legacycrypto.NewPassword(secret)
	if err != nil {
		return err
	}
	credentials, err := json.Marshal(map[string]any{
		"username": username, "salt": salt, "hash": hash, "iterations": 600000,
	})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err = writeNewFile(profiles, []byte("{\"profiles\":[]}\n")); err != nil {
		return err
	}
	if err = writeNewFile(auth, credentials); err != nil {
		return errors.Join(err, os.Remove(profiles))
	}
	return nil
}

// Linking the complete temporary file publishes it atomically without
// replacing a file created by another process.
func writeNewFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".mxioc-init-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Link(file.Name(), path)
}

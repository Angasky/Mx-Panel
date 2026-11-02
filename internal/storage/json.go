// Package storage implements serialized, durable JSON transactions without
// changing numeric values or dropping fields introduced by the Python edition.
package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	mu   sync.Mutex
	path string
}

func New(path string) *Store { return &Store{path: path} }

func decode(data []byte) (map[string]any, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("JSON document must be an object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("unexpected trailing JSON data")
	}
	return doc, nil
}

func (s *Store) Read() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	return decode(data)
}

// Update reads under the same lock used for writing, preventing lost updates.
// The transform receives a private decoded document; errors never write it.
func (s *Store) Update(transform func(map[string]any) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	doc, err := decode(data)
	if err != nil {
		return err
	}
	if err = transform(doc); err != nil {
		return err
	}
	next, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	next = append(next, '\n')
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".mxioc-transaction-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err = temp.Write(next); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

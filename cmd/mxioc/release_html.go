package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Legacy units may omit --admin-html or explicitly point at the old data copy.
// Use the verified adjacent release UI; preserve truly custom HTML paths.
func releaseAdminHTML(root, requested, executable, version string) string {
	if version == "" || version == "dev" {
		return requested
	}
	if requested != "" && filepath.Clean(requested) != filepath.Join(filepath.Clean(root), "index.html") {
		return requested
	}
	directory := filepath.Dir(executable)
	b, e := os.ReadFile(filepath.Join(directory, "VERSION"))
	if e != nil || strings.TrimSpace(string(b)) != version {
		return requested
	}
	path := filepath.Join(directory, "index.html")
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() {
		return requested
	}
	return path
}

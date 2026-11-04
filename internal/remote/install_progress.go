package remote

import (
	"bytes"
	"strings"
)

// Only known stage markers are published while the SSH process is running.
// Raw output can contain credentials and is redacted before final storage.
func installStage(line string) string {
	stage, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "MXIOC_STAGE=")
	if ok {
		switch stage {
		case "preflight", "download", "install", "config", "credentials", "service", "installed", "api-check":
			return stage
		}
	}
	return ""
}

type installStageWriter struct {
	line    []byte
	discard bool
	last    string
	report  func(string)
}

func (w *installStageWriter) Write(data []byte) (int, error) {
	n := len(data)
	for len(data) > 0 {
		part, rest, complete := bytes.Cut(data, []byte{'\n'})
		if !w.discard && len(w.line)+len(part) <= 64 {
			w.line = append(w.line, part...)
		} else {
			w.discard = true
		}
		if !complete {
			break
		}
		if !w.discard {
			if stage := installStage(string(w.line)); stage != "" && stage != w.last {
				w.last = stage
				w.report(stage)
			}
		}
		w.line = w.line[:0]
		w.discard = false
		data = rest
	}
	return n, nil
}

func (m *Manager) updateInstallStage(id, stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return
	}
	for _, entry := range data["jobs"].([]any) {
		job, ok := entry.(map[string]any)
		if ok && job["id"] == id && job["status"] == "running" && job["stage"] != stage {
			job["stage"] = stage
			_ = m.flush(data)
			return
		}
	}
}

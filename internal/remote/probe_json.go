package remote

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Decode a read-only discovery snapshot. Comments and trailing commas are
// accepted without altering quoted URLs, passwords or the remote file.
func decodeProbeJSON(raw []byte) (Record, error) {
	b := append([]byte(nil), bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})...)
	quoted, escaped := false, false
	for i := 0; i < len(b); i++ {
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if b[i] == '\\' {
				escaped = true
			} else if b[i] == '"' {
				quoted = false
			}
			continue
		}
		if b[i] == '"' {
			quoted = true
			continue
		}
		if b[i] != '/' || i+1 >= len(b) {
			continue
		}
		if b[i+1] == '/' {
			b[i], b[i+1] = ' ', ' '
			i += 2
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
				i++
			}
			i--
			continue
		}
		if b[i+1] == '*' {
			b[i], b[i+1] = ' ', ' '
			i += 2
			closed := false
			for i < len(b) {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i++
					closed = true
					break
				}
				if b[i] != '\n' && b[i] != '\r' {
					b[i] = ' '
				}
				i++
			}
			if !closed {
				return nil, errors.New("配置注释未闭合")
			}
		}
	}
	quoted, escaped = false, false
	for i := 0; i < len(b); i++ {
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if b[i] == '\\' {
				escaped = true
			} else if b[i] == '"' {
				quoted = false
			}
			continue
		}
		if b[i] == '"' {
			quoted = true
			continue
		}
		if b[i] == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r' || b[j] == '\n') {
				j++
			}
			// Do not turn [,] or {,} into valid empty containers.
			k := i - 1
			for k >= 0 && (b[k] == ' ' || b[k] == '\t' || b[k] == '\r' || b[k] == '\n') {
				k--
			}
			if j < len(b) && (b[j] == ']' || b[j] == '}') && k >= 0 && b[k] != '[' && b[k] != '{' && b[k] != ',' {
				b[i] = ' '
			}
		}
	}
	if !json.Valid(b) {
		return nil, errors.New("配置 JSON / JSONC 语法无效")
	}
	var doc Record
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, errors.New("配置必须是 JSON 对象")
	}
	return doc, nil
}

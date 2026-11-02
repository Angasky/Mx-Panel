package remote

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Python's ownership hashes use ensure_ascii=False, sorted keys and compact
// separators. encoding/json's HTML escaping and float formatting differ, so
// existing ownership records must not be checked with json.Marshal directly.
func canonicalJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	err := appendCanonical(&out, v, 0)
	return out.Bytes(), err
}
func appendCanonical(out *bytes.Buffer, v any, depth int) error {
	if depth > 128 {
		return errors.New("身份数据嵌套过深")
	}
	switch n := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if n {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		if !utf8.ValidString(n) {
			return errors.New("身份字段不是有效 UTF-8")
		}
		out.WriteByte('"')
		for _, r := range n {
			switch r {
			case '"':
				out.WriteString(`\"`)
			case '\\':
				out.WriteString(`\\`)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 32 {
					out.WriteString(`\u00`)
					out.WriteByte("0123456789abcdef"[byte(r)>>4])
					out.WriteByte("0123456789abcdef"[byte(r)&15])
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	case json.Number:
		text := string(n)
		if strings.ContainsAny(text, ".eE") {
			f, err := n.Float64()
			if err != nil {
				return err
			}
			return appendCanonical(out, f, depth+1)
		}
		if _, err := strconv.ParseInt(text, 10, 64); err != nil {
			if _, err = strconv.ParseUint(text, 10, 64); err != nil {
				return errors.New("身份整数超出范围")
			}
		}
		out.WriteString(text)
	case int:
		out.WriteString(strconv.Itoa(n))
	case int64:
		out.WriteString(strconv.FormatInt(n, 10))
	case uint64:
		out.WriteString(strconv.FormatUint(n, 10))
	case float64:
		if math.IsInf(n, 0) || math.IsNaN(n) {
			return errors.New("身份数值不是有限数")
		}
		exp := strconv.FormatFloat(n, 'e', -1, 64)
		_, power, _ := strings.Cut(exp, "e")
		e, _ := strconv.Atoi(power)
		if e >= -4 && e < 16 {
			text := strconv.FormatFloat(n, 'f', -1, 64)
			if !strings.Contains(text, ".") {
				text += ".0"
			}
			out.WriteString(text)
		} else {
			out.WriteString(exp)
		}
	case []any:
		out.WriteByte('[')
		for i, v := range n {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, v, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(n))
		for key := range n {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonical(out, key, depth+1); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := appendCanonical(out, n[key], depth+1); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return errors.New("身份数据包含不支持的类型")
	}
	return nil
}
func identity(v any) (string, error) {
	raw, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func EndpointIdentity(row Record) (string, error) {
	stream, err := object(row["streamSettings"])
	if err != nil {
		return "", err
	}
	return identity(Record{"id": row["id"], "port": row["port"], "protocol": row["protocol"], "tag": row["tag"], "listen": value(row["listen"]), "streamSettings": stream})
}
func UserIdentity(user Record) (string, error) {
	data := Record{}
	for _, key := range []string{"id", "password", "email", "flow"} {
		data[key] = user[key]
	}
	if value(user["auth"]) != "" {
		data["auth"] = user["auth"]
	}
	return identity(data)
}

// Compare this deterministic output before and after a YAML dependency change.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

func record(name string, wire []byte, err error) {
	if err != nil {
		panic(err)
	}
	json.NewEncoder(os.Stdout).Encode(struct {
		Name   string
		Bytes  int
		SHA256 string
	}{name, len(wire), fmt.Sprintf("%x", sha256.Sum256(wire))})
}
func main() {
	for _, count := range []int{0, 1, 100, 1000} {
		nodes := make([]any, count)
		names := make([]any, count)
		for i := range nodes {
			nodes[i] = map[string]any{"name": fmt.Sprintf("节点-%04d", i), "type": "trojan", "server": "example.com", "port": 20000 + i, "password": "true: #秘密\n第二行", "sni": "example.com", "udp": true, "unknown": map[string]any{"id": uint64(18446744073709551615), "seq": int64(9007199254740993)}}
			names[i] = fmt.Sprintf("节点-%04d", i)
		}
		wire, err := yaml.Marshal(map[string]any{"proxies": nodes, "proxy-groups": []any{map[string]any{"name": "Proxy", "type": "select", "proxies": names}}, "rules": []any{"MATCH,Proxy"}})
		record(fmt.Sprintf("config-%d", count), wire, err)
	}
	var document yaml.Node
	input := `# document comment
defaults: &defaults {str: "true", num: 13, text: "中文"}
alias: *defaults
custom: !custom tagged
literal: |+
  first
  second

folded: >-
  one
  two
sequence: [null, true, false, 1.25, .nan, .inf, -0.0]
# trailing comment
`
	if err := yaml.Unmarshal([]byte(input), &document); err != nil {
		panic(err)
	}
	wire, err := yaml.Marshal(&document)
	record("node-alias-comments-tags", wire, err)
	scalars := map[string]any{"time": time.Date(2026, 11, 3, 0, 0, 0, 123000000, time.UTC), "nan": math.NaN(), "inf": math.Inf(1), "negativeZero": math.Copysign(0, -1), "empty": []any{}, "nil": nil, "mixed": map[any]any{true: "yes", 13: "number", "bool": "no", "leading": "0123"}}
	wire, err = yaml.Marshal(scalars)
	record("scalar-types", wire, err)
	for _, indent := range []int{2, 4} {
		var out bytes.Buffer
		encoder := yaml.NewEncoder(&out)
		encoder.SetIndent(indent)
		for _, value := range []any{&document, scalars, []any{map[string]any{"nested": []any{1, 2, "long\ntext"}}}} {
			if err = encoder.Encode(value); err != nil {
				panic(err)
			}
		}
		err = encoder.Close()
		record(fmt.Sprintf("stream-indent-%d", indent), out.Bytes(), err)
	}
}

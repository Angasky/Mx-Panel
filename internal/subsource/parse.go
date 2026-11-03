package subsource

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"go.yaml.in/yaml/v3"
)

const MaxNodes = 20000

type Batch struct {
	Nodes        []map[string]any
	Skipped      []string
	SkippedCount int
}

func (b *Batch) skip(reason string) {
	b.SkippedCount++
	if len(b.Skipped) < 30 {
		b.Skipped = append(b.Skipped, reason)
	}
}

var shortIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{2}(?:[0-9a-fA-F]{2}){0,7}$`)

func normalize(node map[string]any) error {
	kind, _ := node["type"].(string)
	kind = strings.ToLower(kind)
	if kind == "hy2" {
		kind = "hysteria2"
	}
	if kind == "https" {
		kind = "http"
		node["tls"] = true
	}
	node["type"] = kind
	delete(node, "dialer-proxy") // A foreign subscription cannot name local chains.
	if raw, exists := node["reality-opts"]; exists && raw != nil {
		opts, ok := raw.(map[string]any)
		if !ok {
			return errors.New("Reality 参数必须为对象")
		}
		if value, exists := opts["support-x25519mlkem768"]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("Reality 混合密钥握手选项必须为布尔值")
			}
		}
		if value, exists := opts["short-id"]; exists {
			id := ""
			if value != nil {
				id = strings.TrimSpace(fmt.Sprint(value))
			}
			if id == "" || strings.EqualFold(id, "null") || strings.EqualFold(id, "none") {
				delete(opts, "short-id")
			} else if !shortIDPattern.MatchString(id) {
				return errors.New("Reality short ID 无效")
			} else {
				opts["short-id"] = id
			}
		}
	}
	return config.ValidateNode(node)
}

func Parse(text string) (Batch, error) {
	batch := Batch{Nodes: []map[string]any{}, Skipped: []string{}}
	if len(text) > MaxBytes || !utf8.ValidString(text) {
		return batch, errors.New("订阅文本无效或超过 8 MB")
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	var doc any
	decoder := yaml.NewDecoder(strings.NewReader(text))
	if err := decoder.Decode(&doc); err == nil {
		if root, ok := doc.(map[string]any); ok {
			if list, ok := root["proxies"].([]any); ok {
				var extra any
				if decoder.Decode(&extra) != io.EOF {
					return batch, errors.New("不支持多个 YAML 文档")
				}
				if len(list) > MaxNodes {
					return batch, errors.New("订阅节点数量超过 20000")
				}
				for _, value := range list {
					node, ok := value.(map[string]any)
					if !ok || normalize(node) != nil {
						batch.skip("无效或暂未适配的 Clash 节点")
						continue
					}
					batch.Nodes = append(batch.Nodes, node)
				}
				if len(batch.Nodes) == 0 {
					return batch, errors.New("订阅中没有可导入节点")
				}
				return batch, nil
			}
		}
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(compact)
		if err == nil && utf8.Valid(decoded) && (strings.Contains(string(decoded), "://") || strings.Contains(strings.ToLower(string(decoded)), "snell,")) {
			text = string(decoded)
			break
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, "[proxy]") {
			continue
		}
		parsed, err := links.ParseMany(line)
		if err == nil {
			for _, node := range parsed {
				if e := normalize(node); e != nil {
					err = e
					break
				}
			}
		}
		if err != nil {
			batch.skip("节点链接无效，或包含暂未适配参数")
			continue
		}
		batch.Nodes = append(batch.Nodes, parsed...)
		if len(batch.Nodes) > MaxNodes {
			return Batch{}, errors.New("订阅节点数量超过 20000")
		}
	}
	if len(batch.Nodes) == 0 {
		return batch, errors.New("订阅中没有找到可导入的 Clash 或分享链接节点")
	}
	return batch, nil
}

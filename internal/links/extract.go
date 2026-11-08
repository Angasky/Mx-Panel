package links

import (
	"regexp"
	"strings"
)

var pastedURI = regexp.MustCompile("(?i)(?:snell|mierus|mieru|vless|tuic|hysteria2|hy2|trojan|ss|vmess|socks5|socks|https?)(?:\\\\)?://[^\\s<>`\"]+")
var snellPolicyLine = regexp.MustCompile(`(?i)^\s*[^=\r\n]+\s*=\s*snell\s*,`)

type Candidate struct {
	Value string
	Line  int
}

// Candidates accepts pasted prose/Markdown and multiple links per line. Keep
// invalid nonempty lines for existing error reporting. Never strip punctuation
// from bare URIs: it may belong to credentials, query values or node names.
func Candidates(input string) []Candidate {
	input = strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	result := []Candidate{}
	for index, line := range strings.Split(input, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.EqualFold(trimmed, "[proxy]") || strings.HasPrefix(trimmed, "```") {
			continue
		}
		if snellPolicyLine.MatchString(line) {
			result = append(result, Candidate{trimmed, index + 1})
			continue
		}
		found := false
		for cursor := 0; cursor < len(line); {
			span := pastedURI.FindStringIndex(line[cursor:])
			if span == nil {
				break
			}
			start, end := cursor+span[0], cursor+span[1]
			found = true
			// Markdown destinations allow balanced parentheses. Stop at the
			// matching wrapper, then search the remainder for adjacent links.
			if strings.HasSuffix(line[:start], "](") {
				depth := 1
				for i := start; i < end; i++ {
					switch line[i] {
					case '(':
						depth++
					case ')':
						depth--
					}
					if depth == 0 {
						end = i
						break
					}
				}
			}
			// A paired single quote is a wrapper only when it immediately
			// precedes this URI. Bare trailing apostrophes remain data.
			if start > 0 && line[start-1] == '\'' && end > start && line[end-1] == '\'' {
				end--
			}
			result = append(result, Candidate{line[start:end], index + 1})
			cursor = end
		}
		if !found {
			result = append(result, Candidate{trimmed, index + 1})
		}
	}
	return result
}

// Legacy Python accepts escaped pasted URIs. Restrict unescaping to an
// explicitly escaped scheme so ordinary URI passwords retain literal backslashes.
// Percent-encoded data is never decoded here.
func normalizePastedURI(value string) string {
	if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	scheme, _, ok := strings.Cut(value, `\://`)
	if !ok || strings.ContainsAny(scheme, ":/\\@ ?#") {
		return value
	}
	return strings.NewReplacer(`\://`, "://", `\@`, "@", `\.`, ".").Replace(value)
}

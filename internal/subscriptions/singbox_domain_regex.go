package subscriptions

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Mihomo uses regexp2 with IgnoreCase; sing-box uses Go regexp. Accept only
// their common domain-pattern subset, rather than treating successful Go
// compilation as proof that regexp2 gives the same meaning. Hosts are DNS
// names (use Punycode for international names), not arbitrary Unicode text.
func singBoxDomainRegex(value string, noResolve bool) (string, error) {
	fail := func() (string, error) {
		return "", errors.New("域名正则仅支持 1–1024 字节 ASCII 域名、普通分组、字符类、| ^ $ . * + ? 、{n}/{n,m}（0–1000）和转义点/连字符；不支持额外选项或高级正则语法")
	}
	if noResolve || len(value) == 0 || len(value) > 1024 || strings.Contains(value, "(?") {
		return fail()
	}
	inClass := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\\' {
			i++
			if i == len(value) || (value[i] != '.' && value[i] != '-') {
				return fail()
			}
			continue
		}
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' {
			continue
		}
		if ch == '{' {
			if inClass {
				return fail()
			}
			end := strings.IndexByte(value[i+1:], '}')
			if end < 0 {
				return fail()
			}
			end += i + 1
			bounds := strings.Split(value[i+1:end], ",")
			if len(bounds) > 2 {
				return fail()
			}
			previous := -1
			for _, bound := range bounds {
				if bound == "" || len(bound) > 4 {
					return fail()
				}
				for _, c := range bound {
					if c < '0' || c > '9' {
						return fail()
					}
				}
				n, e := strconv.Atoi(bound)
				if e != nil || n > 1000 || n < previous {
					return fail()
				}
				previous = n
			}
			i = end
			continue
		}
		switch ch {
		case '[':
			if inClass { // Includes regexp2 class subtraction and POSIX classes.
				return fail()
			}
			inClass = true
		case ']':
			if !inClass {
				return fail()
			}
			inClass = false
		case '.', '^':
		case '$', '(', ')', '|', '*', '+', '?':
			if inClass {
				return fail()
			}
		default:
			return fail()
		}
	}
	pattern := "(?i)" + value
	if _, err := regexp.Compile(pattern); err != nil {
		return fail()
	}
	return pattern, nil
}

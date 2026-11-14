package subscriptions

import (
	"errors"
	"regexp"
	"strings"
)

// Mihomo uses regexp2 with IgnoreCase; sing-box uses Go regexp. Accept only
// their common domain-pattern subset, rather than treating successful Go
// compilation as proof that regexp2 gives the same meaning. Hosts are DNS
// names (use Punycode for international names), not arbitrary Unicode text.
func singBoxDomainRegex(value string, noResolve bool) (string, error) {
	fail := func() (string, error) {
		return "", errors.New("域名正则仅支持 1–1024 字节 ASCII 域名、普通分组、字符类、| ^ $ . * + ? 和转义点/连字符；不支持额外选项或高级正则语法")
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

// Package hostmatch matches dev-sidecar host patterns against request hosts.
//
// The configuration uses two forms:
//
//	github.com     exact match
//	*.gstatic.com  wildcard: "*" stands for any run of characters, dots included
//
// Matching is case-insensitive and ignores a trailing port.
package hostmatch

import (
	"net"
	"regexp"
	"strings"
	"sync"
)

var (
	mu    sync.RWMutex
	cache = map[string]*regexp.Regexp{}
)

// Compile turns a config host pattern into a regular expression.
func Compile(pattern string) *regexp.Regexp {
	key := strings.ToLower(strings.TrimSpace(pattern))

	mu.RLock()
	re, ok := cache[key]
	mu.RUnlock()
	if ok {
		return re
	}

	// Escape everything, then re-open the "*" wildcards.
	body := strings.ReplaceAll(regexp.QuoteMeta(key), `\*`, `.*`)
	re = regexp.MustCompile(`(?i)^` + body + `$`)

	mu.Lock()
	cache[key] = re
	mu.Unlock()
	return re
}

// Match reports whether host matches pattern.
//
// Three forms are supported, following the desktop's matchHostname():
//
//	github.com       exact (case-insensitive)
//	*.example.com    wildcard; also matches "example.com" itself
//	^.+\\.foo\\.com   regular expression, used verbatim
//
// A leading-dot pattern (".example.com") is read as "*.example.com".
func Match(pattern, host string) bool {
	h := Normalize(host)
	if h == "" {
		return false
	}
	p := strings.TrimSpace(pattern)
	if p == "" {
		return false
	}
	if strings.EqualFold(p, h) {
		return true
	}

	if strings.HasPrefix(p, ".") {
		p = "*" + p
	}
	// "*.example.com" covers the bare domain too, as the desktop's fast path does.
	if rest, ok := strings.CutPrefix(p, "*."); ok && strings.EqualFold(rest, h) {
		return true
	}
	if strings.HasPrefix(p, "^") {
		if re := compileRaw(p); re != nil {
			return re.MatchString(h)
		}
		// RE2 has no lookaround. The configuration uses "^(?!x)rest$" to mean
		// "rest, but not x", so the assertion becomes an exclusion list instead
		// of silently matching nothing — that cost us the working google IP.
		if base, exclusions, ok := rewriteLookahead(p); ok {
			re := compileRaw(base)
			if re == nil || !re.MatchString(h) {
				return false
			}
			for _, ex := range exclusions {
				if ere := compileRaw(ex); ere != nil && ere.MatchString(h) {
					return false
				}
			}
			return true
		}
		// Not a usable regular expression: fall back to literal matching.
	}
	return Compile(p).MatchString(h)
}

// rewriteLookahead pulls every negative lookahead out of an anchored pattern.
// It returns the base expression plus one exclusion per assertion: "everything
// written before the assertion, then the asserted content" is exactly the set
// the lookahead forbids.
func rewriteLookahead(p string) (string, []string, bool) {
	var base strings.Builder
	var exclusions []string
	prefix := ""
	found := false

	for i := 0; i < len(p); {
		if !strings.HasPrefix(p[i:], "(?!") {
			base.WriteByte(p[i])
			prefix += string(p[i])
			i++
			continue
		}
		inner, next, ok := groupContent(p, i+3)
		if !ok {
			return "", nil, false
		}
		exclusions = append(exclusions, prefix+inner)
		found = true
		i = next
	}
	if !found {
		return "", nil, false
	}
	return base.String(), exclusions, true
}

// groupContent returns the text up to the parenthesis matching an already-open
// group, honouring escapes and nested groups.
func groupContent(p string, start int) (string, int, bool) {
	depth := 0
	for i := start; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return p[start:i], i + 1, true
			}
			depth--
		}
	}
	return "", 0, false
}

// compileRaw compiles a pattern that the configuration already wrote as a
// regular expression.
func compileRaw(p string) *regexp.Regexp {
	key := "raw:" + p
	mu.RLock()
	re, ok := cache[key]
	mu.RUnlock()
	if ok {
		return re
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil
	}
	mu.Lock()
	cache[key] = re
	mu.Unlock()
	return re
}

// Normalize lowercases a host and strips a trailing port.
func Normalize(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return ""
	}
	if strings.Contains(h, ":") {
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
	}
	return strings.TrimSuffix(h, ".")
}

// IsIP reports whether host is an IP literal.
func IsIP(host string) bool {
	return net.ParseIP(Normalize(host)) != nil
}

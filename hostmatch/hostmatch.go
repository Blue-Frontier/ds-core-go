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
func Match(pattern, host string) bool {
	h := Normalize(host)
	if h == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(pattern), h) {
		return true
	}
	return Compile(pattern).MatchString(h)
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

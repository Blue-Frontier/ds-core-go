// Package rules compiles dev-sidecar intercept rules and matches requests
// against them.
//
// A configuration block looks like:
//
//	"github.com": {
//	  "^(/[^/]+){2}/releases/download/.*$": { "redirect": "ghp.ci/https://github.com" },
//	  ".*": { "sni": "baidu.com" }
//	}
//
// JSON object order is not preserved by encoding/json, so path patterns are
// ordered deterministically at compile time: catch-all patterns ("^.*$" and
// friends) last, everything else by descending pattern length. That reproduces
// the intent of the shipped configuration, where specific rules sit in front of
// a trailing catch-all.
package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// Action is the outcome of matching one request.
type Action struct {
	Rule config.Rule
	// MatchedPath is the path pattern that fired.
	MatchedPath string
}

// IsZero reports whether no rule matched.
func (a Action) IsZero() bool { return a.MatchedPath == "" }

type compiledRule struct {
	pattern    string
	re         *regexp.Regexp
	rule       config.Rule
	exclusions []*regexp.Regexp
}

type hostEntry struct {
	pattern string
	wild    bool
	rules   []compiledRule
}

// Table is a compiled, read-only rule set.
type Table struct {
	hosts []hostEntry
	// Rewritten lists patterns whose PCRE negative lookahead was translated into
	// a plain pattern plus exclusions (see rewriteNegativeLookahead).
	Rewritten []string
	// Skipped lists patterns the Go regexp engine still cannot compile after
	// rewriting; they are ignored rather than failing the whole configuration.
	Skipped []string
}

// normalizePathPattern mirrors the desktop's isMatched(): "*", ".*" and "true"
// mean "any path", and a pattern starting with *, ? or + is prefixed with "."
// before it is treated as a regex.
func normalizePathPattern(p string) string {
	switch p {
	case "*", ".*", "true":
		return "^.*$"
	}
	if p != "" && (p[0] == '*' || p[0] == '?' || p[0] == '+') {
		return "." + p
	}
	return p
}

// rewriteNamedGroups converts PCRE/.NET named groups "(?<name>...)" to RE2's
// "(?P<name>...)". Lookbehind forms "(?<=" and "(?<!" are left untouched so
// they still fail loudly as unsupported.
func rewriteNamedGroups(p string) string {
	if !strings.Contains(p, "(?<") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p) + 4)
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+1 < len(p) {
			b.WriteByte(p[i])
			b.WriteByte(p[i+1])
			i++
			continue
		}
		if i+3 < len(p) && p[i] == '(' && p[i+1] == '?' && p[i+2] == '<' &&
			p[i+3] != '=' && p[i+3] != '!' {
			b.WriteString("(?P<")
			i += 2 // the loop then steps onto the group name
			continue
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// splitTopLevel splits on '|' that is not inside parentheses.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		case '\\':
			i++
		}
	}
	return append(out, s[start:])
}

// rewriteNegativeLookahead translates the PCRE idiom "^(?!A|B)rest", which RE2
// rejects, into a plain pattern "^rest" plus exclusions "^A", "^B". Both forms
// assert the same thing: the path must not start with any alternative.
//
// This matters because the official configuration uses that idiom for "match
// everything except these prefixes" rules, and silently dropping them removes
// acceleration for the whole host.
func rewriteNegativeLookahead(p string) (base string, exclusions []string, ok bool) {
	if !strings.HasPrefix(p, "^(?!") {
		return "", nil, false
	}
	depth, start := 1, len("^(?!")
	for i := start; i < len(p); i++ {
		switch p[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth != 0 {
				continue
			}
			rest := p[i+1:]
			if rest == "" {
				return "", nil, false
			}
			base = "^" + rest
			for _, alt := range splitTopLevel(p[start:i]) {
				if alt != "" {
					exclusions = append(exclusions, "^"+alt)
				}
			}
			if len(exclusions) == 0 {
				return "", nil, false
			}
			// A second stacked lookahead ("^(?!A)(?!B)rest") is rewritten too.
			for strings.HasPrefix(base, "^(?!") {
				b2, e2, ok2 := rewriteNegativeLookahead(base)
				if !ok2 {
					break
				}
				base = b2
				exclusions = append(exclusions, e2...)
			}
			return base, exclusions, true
		case '\\':
			i++
		}
	}
	return "", nil, false
}

// Compile builds a Table from the "intercepts" section.
func Compile(intercepts map[string]map[string]config.Rule) (*Table, error) {
	hosts := make([]string, 0, len(intercepts))
	for p := range intercepts {
		hosts = append(hosts, p)
	}
	sort.Slice(hosts, func(i, j int) bool {
		// Literal hosts are tried first, then wildcards and regular expressions,
		// matching the desktop's "exact match wins" order.
		wi := isPatternHost(hosts[i])
		wj := isPatternHost(hosts[j])
		if wi != wj {
			return !wi
		}
		return hosts[i] < hosts[j]
	})

	t := &Table{hosts: make([]hostEntry, 0, len(hosts))}
	for _, host := range hosts {
		he := hostEntry{pattern: host, wild: strings.Contains(host, "*")}
		paths := intercepts[host]
		patterns := make([]string, 0, len(paths))
		for p := range paths {
			patterns = append(patterns, p)
		}
		sortPathPatterns(patterns)
		for _, p := range patterns {
			rule := paths[p]
			pattern := normalizePathPattern(p)
			var extra []string
			if base, ex, ok := rewriteNegativeLookahead(p); ok {
				pattern, extra = base, ex
				t.Rewritten = append(t.Rewritten, host+" "+p)
			}
			if ng := rewriteNamedGroups(pattern); ng != pattern {
				pattern = ng
				t.Rewritten = append(t.Rewritten, host+" "+p)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				// Still unsupported (e.g. backreferences): skipping beats
				// refusing to load a configuration whose other rules are fine.
				t.Skipped = append(t.Skipped, host+" "+p)
				continue
			}
			cr := compiledRule{pattern: p, re: re, rule: rule}
			skip := false
			exclusions := append(append([]string{}, rule.Exclusions...), extra...)
			for _, ex := range exclusions {
				ere, err := regexp.Compile(normalizePathPattern(ex))
				if err != nil {
					t.Skipped = append(t.Skipped, host+" !"+ex)
					skip = true
					break
				}
				cr.exclusions = append(cr.exclusions, ere)
			}
			if skip {
				continue
			}
			he.rules = append(he.rules, cr)
		}
		t.hosts = append(t.hosts, he)
	}
	return t, nil
}

// isPatternHost reports whether a host key needs pattern matching rather than a
// straight comparison.
func isPatternHost(host string) bool {
	return strings.Contains(host, "*") || strings.HasPrefix(host, "^") || strings.HasPrefix(host, ".")
}

// Match returns the first rule matching host and path.
func (t *Table) Match(host, path string) (Action, bool) {
	if t == nil {
		return Action{}, false
	}
	h := hostmatch.Normalize(host)
	if path == "" {
		path = "/"
	}
	for _, he := range t.hosts {
		if !hostmatch.Match(he.pattern, h) {
			continue
		}
		for _, cr := range he.rules {
			if !cr.re.MatchString(path) {
				continue
			}
			if excluded(cr, path) {
				continue
			}
			return Action{Rule: cr.rule, MatchedPath: cr.pattern}, true
		}
	}
	return Action{}, false
}

// Hosts returns the number of configured host patterns (for logging).
func (t *Table) Hosts() int {
	if t == nil {
		return 0
	}
	return len(t.hosts)
}

func excluded(cr compiledRule, path string) bool {
	for _, ex := range cr.exclusions {
		if ex.MatchString(path) {
			return true
		}
	}
	return false
}

func isCatchAll(p string) bool {
	switch p {
	case ".*", "^.*$", ".*$", "^.*", "(.*)", ".*?":
		return true
	}
	return false
}

func sortPathPatterns(patterns []string) {
	sort.SliceStable(patterns, func(i, j int) bool {
		ci, cj := isCatchAll(patterns[i]), isCatchAll(patterns[j])
		if ci != cj {
			return !ci
		}
		if ci && cj {
			return patterns[i] < patterns[j]
		}
		if len(patterns[i]) != len(patterns[j]) {
			return len(patterns[i]) > len(patterns[j])
		}
		return patterns[i] < patterns[j]
	})
}

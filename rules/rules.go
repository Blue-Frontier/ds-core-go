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
	"fmt"
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
}

// Compile builds a Table from the "intercepts" section.
func Compile(intercepts map[string]map[string]config.Rule) (*Table, error) {
	hosts := make([]string, 0, len(intercepts))
	for p := range intercepts {
		hosts = append(hosts, p)
	}
	sort.Slice(hosts, func(i, j int) bool {
		wi, wj := strings.Contains(hosts[i], "*"), strings.Contains(hosts[j], "*")
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
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("host %q path pattern %q: %w", host, p, err)
			}
			cr := compiledRule{pattern: p, re: re, rule: paths[p]}
			for _, ex := range paths[p].Exclusions {
				ere, err := regexp.Compile(ex)
				if err != nil {
					return nil, fmt.Errorf("host %q exclusion %q: %w", host, ex, err)
				}
				cr.exclusions = append(cr.exclusions, ere)
			}
			he.rules = append(he.rules, cr)
		}
		t.hosts = append(t.hosts, he)
	}
	return t, nil
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

package rules

import (
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func sampleRules() map[string]map[string]config.Rule {
	return map[string]map[string]config.Rule{
		"github.com": {
			`^(/[^/]+){2}/releases/download/.*$`: {Redirect: "ghp.ci/https://github.com"},
			`.*`:                                 {SNI: "baidu.com"},
		},
		"www.gstatic.com": {
			`/recaptcha/.*`: {Proxy: "www.recaptcha.net"},
			`.*`:            {SNI: "baidu.com", Exclusions: []string{`/recaptcha/.*`}},
		},
		"*.gstatic.com": {
			`.*`: {SNI: "baidu.com"},
		},
	}
}

func TestMatchPathRules(t *testing.T) {
	tbl, err := Compile(sampleRules())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	cases := []struct {
		name   string
		host   string
		path   string
		wantOK bool
		check  func(config.Rule) bool
	}{
		{
			name: "release redirect wins over catch-all", host: "github.com",
			path: "/owner/repo/releases/download/v1.0/tool.zip", wantOK: true,
			check: func(r config.Rule) bool { return r.Redirect == "ghp.ci/https://github.com" },
		},
		{
			name: "catch-all sni", host: "github.com", path: "/owner/repo",
			wantOK: true, check: func(r config.Rule) bool { return r.SNI == "baidu.com" },
		},
		{
			name: "specific proxy rule", host: "www.gstatic.com", path: "/recaptcha/api.js",
			wantOK: true, check: func(r config.Rule) bool { return r.Proxy == "www.recaptcha.net" },
		},
		{
			name: "exclusion falls through to catch-all", host: "www.gstatic.com",
			path: "/css/app.css", wantOK: true,
			check: func(r config.Rule) bool { return r.SNI == "baidu.com" },
		},
		{
			name: "wildcard host", host: "ssl.gstatic.com", path: "/icon.png",
			wantOK: true, check: func(r config.Rule) bool { return r.SNI == "baidu.com" },
		},
		{
			name: "unrelated host", host: "example.com", path: "/", wantOK: false,
		},
		{
			name: "host with port", host: "github.com:443", path: "/a/b/releases/download/x",
			wantOK: true, check: func(r config.Rule) bool { return r.Redirect != "" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, ok := tbl.Match(tc.host, tc.path)
			if ok != tc.wantOK {
				t.Fatalf("match = %v, want %v (rule %+v)", ok, tc.wantOK, action.Rule)
			}
			if ok && tc.check != nil && !tc.check(action.Rule) {
				t.Fatalf("unexpected rule: %+v (pattern %q)", action.Rule, action.MatchedPath)
			}
		})
	}
}

// Nothing expressible is dropped: a lookahead is rewritten (see the tests
// below), and only genuinely unsupported syntax such as an unclosed group is
// skipped, so one bad rule never costs the whole configuration.
func TestCompileSkipsUnsupportedPatterns(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"example.com": {
			`^/ok$`:     {SNI: "kept"},
			`(unclosed`: {SNI: "broken"},
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 1 {
		t.Fatalf("skipped = %v, want 1 entry", tbl.Skipped)
	}
	action, ok := tbl.Match("example.com", "/ok")
	if !ok || action.Rule.SNI != "kept" {
		t.Fatalf("valid rule did not match: %+v ok=%v", action.Rule, ok)
	}
}

// A bad exclusion must drop only its own rule, not the whole table.
func TestCompileSkipsRuleWithBadExclusion(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"example.com": {
			`^/path$`: {SNI: "a", Exclusions: []string{`(?!x)`}},
			`^/keep$`: {SNI: "b"},
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 1 {
		t.Fatalf("skipped = %v, want 1", tbl.Skipped)
	}
	if _, ok := tbl.Match("example.com", "/keep"); !ok {
		t.Fatal("unrelated rule was dropped")
	}
}

// The official config expresses "everything except these prefixes" as a PCRE
// negative lookahead. RE2 rejects it, so it is rewritten into a plain pattern
// plus exclusions; behaviour must stay identical.
func TestNegativeLookaheadIsRewritten(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"*.steamcommunity.com": {
			`^(?!/discussions|/Profile|/app.*/discussions).*$`: {SNI: "baidu.com"},
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 0 {
		t.Fatalf("skipped = %v", tbl.Skipped)
	}
	if len(tbl.Rewritten) != 1 {
		t.Fatalf("rewritten = %v", tbl.Rewritten)
	}

	cases := []struct {
		path string
		want bool
	}{
		{"/workshop/1", true},
		{"/app/123/news", true},
		{"/discussions/1", false},
		{"/Profile/x", false},
		{"/app/123/discussions", false},
	}
	for _, c := range cases {
		if _, ok := tbl.Match("a.steamcommunity.com", c.path); ok != c.want {
			t.Fatalf("%s matched=%v, want %v", c.path, ok, c.want)
		}
	}
}

// "does not contain" alternatives, and stacked lookaheads, rewrite too.
func TestNegativeLookaheadVariants(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"*.steamstatic.com": {
			`^(?!.*cloudflare).*steamstatic\.com$`: {SNI: "a"},
		},
		"*.google.com": {
			`^(?!fonts)(?!.*/translate-pa/).*$`: {SNI: "b"},
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 0 {
		t.Fatalf("skipped = %v", tbl.Skipped)
	}

	cases := []struct {
		host, path string
		want       bool
	}{
		{"x.steamstatic.com", "/b/steamstatic.com", true},
		{"x.steamstatic.com", "/cloudflare/steamstatic.com", false},
		{"a.google.com", "/maps", true},
		// The upstream "(?!fonts)" is asserted at position 0 of a path that
		// starts with '/', so it excludes nothing. The JS kernel matches
		// rOptions.path the same way, so the rewrite keeps that behaviour.
		{"a.google.com", "/fonts/roboto", true},
		{"a.google.com", "/x/translate-pa/y", false},
	}
	for _, c := range cases {
		if _, ok := tbl.Match(c.host, c.path); ok != c.want {
			t.Fatalf("%s%s matched=%v, want %v", c.host, c.path, ok, c.want)
		}
	}
}

// Patterns RE2 still cannot express stay skipped instead of failing the load.
func TestBackreferenceStillSkipped(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"example.com": {`^(a)\1$`: {SNI: "x"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 1 {
		t.Fatalf("skipped = %v, want 1", tbl.Skipped)
	}
}

// PCRE/.NET named groups use "(?<name>...)", RE2 only understands
// "(?P<name>...)"; the rename is mechanical, so the rule keeps working.
func TestNamedGroupIsRewritten(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"example.com": {`^(?<pre>.*).googlevideo1.com$`: {SNI: "x"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 0 {
		t.Fatalf("skipped = %v", tbl.Skipped)
	}
	if len(tbl.Rewritten) != 1 {
		t.Fatalf("rewritten = %v", tbl.Rewritten)
	}
	if _, ok := tbl.Match("example.com", "/a/b.googlevideo1.com"); !ok {
		t.Fatal("rewritten named group did not match")
	}
}

// Lookbehind stays unsupported: it is skipped, not silently mistranslated.
func TestLookbehindStillSkipped(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		"example.com": {`(?<=a)b`: {SNI: "x"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(tbl.Skipped) != 1 {
		t.Fatalf("skipped = %v, want 1", tbl.Skipped)
	}
}

// The desktop treats "*", ".*" and "true" as "any path" (isMatched()), not as
// a regex; compiling "*" as regexp would fail and drop the whole rule.
func TestStarPathPatternMatchesEverything(t *testing.T) {
	for _, pat := range []string{`*`, `.*`, `true`} {
		tbl, err := Compile(map[string]map[string]config.Rule{
			"example.com": {pat: {SNI: "x"}},
		})
		if err != nil {
			t.Fatalf("%q: Compile: %v", pat, err)
		}
		if len(tbl.Skipped) != 0 {
			t.Fatalf("%q: skipped = %v", pat, tbl.Skipped)
		}
		if _, ok := tbl.Match("example.com", "/anything/here"); !ok {
			t.Fatalf("%q did not match", pat)
		}
	}
}

// A "^"-prefixed host key is a regular expression and must be honoured; a
// literal key still wins over it when both could match.
func TestRegexHostKey(t *testing.T) {
	tbl, err := Compile(map[string]map[string]config.Rule{
		`^.*\.googleapis\.com$`: {".*": {SNI: "regex"}},
		"maps.googleapis.com":   {".*": {SNI: "literal"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if a, ok := tbl.Match("maps.googleapis.com", "/x"); !ok || a.Rule.SNI != "literal" {
		t.Fatalf("literal should win: %+v ok=%v", a.Rule, ok)
	}
	if a, ok := tbl.Match("www.googleapis.com", "/x"); !ok || a.Rule.SNI != "regex" {
		t.Fatalf("regex host did not match: %+v ok=%v", a.Rule, ok)
	}
}

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

func TestCompileRejectsBadPattern(t *testing.T) {
	bad := map[string]map[string]config.Rule{
		"example.com": {`(unclosed`: {}},
	}
	if _, err := Compile(bad); err == nil {
		t.Fatal("want error for invalid regexp")
	}
}

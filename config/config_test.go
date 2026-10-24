package config

import "testing"

const sample = `
{
  "server": {
    // line comment
    "intercepts": {
      "github.com": {
        "^(/[^/]+){2}/releases/download/.*$": {
          "redirect": "ghp.ci/https://github.com",
          "desc": "release redirect",
        },
        ".*": { "sni": "baidu.com" },
      },
    },
    /* block
       comment */
    "preSetIPList": { "github.com": ["140.82.113.3"] },
    "dns": { "mapping": { "*.jetbrains.com": "quad9" } },
  },
  "proxy": { "excludeIpList": { "*.windows.net": true } },
}
`

func TestParseJSON5Subset(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	rules := cfg.Server.Intercepts["github.com"]
	if len(rules) != 2 {
		t.Fatalf("want 2 rules for github.com, got %d", len(rules))
	}
	redir := rules["^(/[^/]+){2}/releases/download/.*$"]
	if redir.Redirect != "ghp.ci/https://github.com" {
		t.Errorf("redirect = %q", redir.Redirect)
	}
	if redir.Desc != "release redirect" {
		t.Errorf("desc = %q", redir.Desc)
	}
	if got := rules[".*"].SNI; got != "baidu.com" {
		t.Errorf("sni = %q", got)
	}

	if ips := cfg.Server.PreSetIPList["github.com"]; len(ips) != 1 || ips[0] != "140.82.113.3" {
		t.Errorf("preSetIpList = %v", cfg.Server.PreSetIPList)
	}
	if got := cfg.Server.DNS.Mapping["*.jetbrains.com"]; got != "quad9" {
		t.Errorf("dns mapping = %q", got)
	}
	if !cfg.Proxy.ExcludeIPList["*.windows.net"] {
		t.Error("excludeIpList not parsed")
	}
}

func TestStripJSON5SingleQuotes(t *testing.T) {
	out := string(StripJSON5([]byte(`{'a': 'b', 'c': ['d',],}`)))
	if out != `{"a": "b", "c": ["d"]}` {
		t.Errorf("StripJSON5 = %s", out)
	}
}

func TestStripJSON5KeepsCommentMarkersInStrings(t *testing.T) {
	in := `{"url": "https://example.com/a//b", "x": 1}`
	if got := string(StripJSON5([]byte(in))); got != in {
		t.Errorf("comments inside strings were stripped: %s", got)
	}
}

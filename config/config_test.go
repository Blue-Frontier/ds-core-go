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
	if got := cfg.Server.DNS.Mapping["*.jetbrains.com"]; got.DNSName != "quad9" {
		t.Errorf("dns mapping = %q", got.DNSName)
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

func TestParseDNSProviders(t *testing.T) {
	sample := `
{
  "server": {
    "preSetIpList": {
      "github.com": ["140.82.113.3"],
      "hub.docker.com": null,
      "steam": { "23.209.46.70": true, "104.18.42.105": false }
    },
    "dns": {
      "providers": {
        "safe360": { "server": "tls://dot.360.cn", "forSni": true },
        "cf-DoT": { "server": "tls://1.1.1.1", "sni": "baidu.com" },
        "cf-DoH": { "server": "https://cloudflare-dns.com/dns-query", "servername": "baidu.com" },
        "quad9-ip": { "server": "https://9.9.9.9/dns-query" },
        "legacy": { "host": "223.5.5.5" },
      },
      "mapping": {
        "*.jetbrains.com": "cf-DoT",
        "*.example.org": { "dns": "quad9-ip", "family": 6 },
      },
    },
  },
}
`
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	p := cfg.Server.DNS.Providers
	if p["safe360"].StdServer() != "tls://dot.360.cn" || !p["safe360"].MarkedForSNI() {
		t.Errorf("safe360 = %+v", p["safe360"])
	}
	if got := p["cf-DoT"].SNIOverride(); got != "baidu.com" {
		t.Errorf("cf-DoT sni = %q", got)
	}
	if got := p["cf-DoH"].SNIOverride(); got != "baidu.com" {
		t.Errorf("cf-DoH servername = %q", got)
	}
	if got := p["legacy"].StdServer(); got != "223.5.5.5" {
		t.Errorf("legacy host = %q", got)
	}

	if ips := cfg.Server.PreSetIPList["steam"]; len(ips) != 1 || ips[0] != "23.209.46.70" {
		t.Errorf("object preSetIpList = %v", ips)
	}
	if v, ok := cfg.Server.PreSetIPList["hub.docker.com"]; !ok || len(v) != 0 {
		t.Errorf("null preSetIpList = %v (ok=%v)", v, ok)
	}

	if m := cfg.Server.DNS.Mapping["*.jetbrains.com"]; m.DNSName != "cf-DoT" || m.Family != 0 {
		t.Errorf("mapping string = %+v", m)
	}
	if m := cfg.Server.DNS.Mapping["*.example.org"]; m.DNSName != "quad9-ip" || m.Family != 6 {
		t.Errorf("mapping object = %+v", m)
	}
}

package config

import (
	"encoding/json"
	"testing"
)

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

// The official configuration is JSON5: unquoted keys plus regexes written in
// JS style ("x\.com"), which strict JSON rejects. Both must load.
func TestParseJSON5BareKeysAndLenientEscapes(t *testing.T) {
	src := []byte(`
{
  app: {
    metaInfo: {
      id: "official",
      version: 202610161530,
      updateLog: "it's fine",
    },
  },
  server: {
    intercepts: {
      "x.example": {
        "^(.+\.)?x\.com$": { sni: "a" },
      },
    },
  },
}
`)
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.App.MetaInfo.ID != "official" {
		t.Fatalf("meta id = %q", c.App.MetaInfo.ID)
	}
	if c.App.MetaInfo.Version != 202610161530 {
		t.Fatalf("meta version = %d", c.App.MetaInfo.Version)
	}
	if c.App.MetaInfo.UpdateLog != "it's fine" {
		t.Fatalf("updateLog = %q", c.App.MetaInfo.UpdateLog)
	}
	rules := c.Server.Intercepts["x.example"]
	if len(rules) != 1 {
		t.Fatalf("rules = %+v", rules)
	}
	// JS drops the backslash of an unknown escape, so "x\.com" -> "x.com".
	for pattern, rule := range rules {
		if pattern != "^(.+.)?x.com$" {
			t.Fatalf("pattern = %q", pattern)
		}
		if rule.SNI != "a" {
			t.Fatalf("rule = %+v", rule)
		}
	}
}

// abort/success accept the literal true or an object; options is a switch whose
// tunables sit beside it.
func TestParseSyntheticActions(t *testing.T) {
	src := []byte(`
{
  server: {
    intercepts: {
      "a.example": {
        "^/x$": { abort: true },
        "^/y$": { success: { script: ";", status: 204 } },
        "^/z$": { success: true, status: 204 },
        "^/o$": { options: true, optionsMaxAge: 60, optionsCredentials: false },
      },
    },
  },
}
`)
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rules := c.Server.Intercepts["a.example"]

	abort := rules["^/x$"]
	if abort.Abort == nil || !abort.Abort.Enabled {
		t.Fatalf("abort = %+v", abort.Abort)
	}
	if abort.Success != nil {
		t.Fatal("abort rule must not carry success")
	}

	succ := rules["^/y$"]
	if succ.Success == nil || succ.Success.Status != 204 || succ.Success.Script != ";" {
		t.Fatalf("success = %+v", succ.Success)
	}

	// "success: true" with a sibling status: the desktop ignores the sibling,
	// so Status stays zero and the kernel falls back to 200.
	flag := rules["^/z$"]
	if flag.Success == nil || !flag.Success.Enabled || flag.Success.Status != 0 {
		t.Fatalf("success flag = %+v", flag.Success)
	}

	opt := rules["^/o$"]
	if !bool(opt.Options) {
		t.Fatal("options switch not enabled")
	}
	if opt.OptionsMaxAge != 60 {
		t.Fatalf("optionsMaxAge = %d", opt.OptionsMaxAge)
	}
	if opt.OptionsCredentials == nil || *opt.OptionsCredentials {
		t.Fatalf("optionsCredentials = %v", opt.OptionsCredentials)
	}
}

// responseReplace carries arbitrary header values and the download switch.
func TestParseResponseReplace(t *testing.T) {
	src := []byte(`
{
  server: {
    intercepts: {
      "a.example": {
        "^/d$": { responseReplace: { doDownload: true, headers: { "content-type": "text/plain", "x-n": 3 } } },
        "^/h$": { responseReplace: { headers: { "x-keep": "[remove]" } }, cacheDays: 7 },
      },
    },
  },
}
`)
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rules := c.Server.Intercepts["a.example"]

	d := rules["^/d$"]
	if d.ResponseReplace == nil || !d.ResponseReplace.DoDownload {
		t.Fatalf("doDownload not parsed: %+v", d.ResponseReplace)
	}
	if got := d.ResponseReplace.Headers["content-type"]; got != "text/plain" {
		t.Fatalf("content-type = %v", got)
	}

	h := rules["^/h$"]
	if h.CacheDays != 7 {
		t.Fatalf("cacheDays = %d", h.CacheDays)
	}
	if got := h.ResponseReplace.Headers["x-keep"]; got != "[remove]" {
		t.Fatalf("x-keep = %v", got)
	}
}

// A preset entry written as an object carries a description; it is enabled
// unless it says otherwise. Treating it as disabled emptied the list.
func TestIPListObjectEntries(t *testing.T) {
	var list IPList
	body := `{"192.0.2.10":{"desc":"自动地区官方"},"192.0.2.11":false,"192.0.2.12":true}`
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %v, want two enabled addresses", list)
	}
	seen := map[string]bool{}
	for _, ip := range list {
		seen[ip] = true
	}
	if !seen["192.0.2.10"] || !seen["192.0.2.12"] || seen["192.0.2.11"] {
		t.Fatalf("unexpected entries: %v", list)
	}
}

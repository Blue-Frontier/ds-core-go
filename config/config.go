// Package config loads dev-sidecar remote configuration files.
//
// The shipped configuration uses JSON5 syntax: // and /* */ comments, single
// quotes and trailing commas. Only that subset is supported, which is enough
// for the files published by the dev-sidecar config pipeline and keeps this
// kernel free of third-party dependencies.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Rule is one intercept rule: a path pattern inside a host block.
type Rule struct {
	// Redirect rewrites the response into a 302 to another host. The value is
	// a prefix without scheme, e.g. "ghp.ci/https://github.com".
	Redirect string `json:"redirect,omitempty"`
	// SNI overrides the server name sent upstream.
	SNI string `json:"sni,omitempty"`
	// Proxy swaps the upstream host (same port) for another one.
	Proxy string `json:"proxy,omitempty"`
	// Script and TampermonkeyScript inject JavaScript into HTML responses.
	// Parsed for compatibility; response rewriting is not implemented yet.
	Script             string   `json:"script,omitempty"`
	TampermonkeyScript string   `json:"tampermonkeyScript,omitempty"`
	Exclusions         []string `json:"exclusions,omitempty"`
	Desc               string   `json:"desc,omitempty"`
}

// DNSProvider is one entry of "server.dns.providers". Server understands the
// spellings used by the desktop kernel: "https://..." / "http://..." selects
// DNS-over-HTTPS, "tls://..." or "dot://..." DNS-over-TLS, "tcp://..." plain
// DNS over TCP and everything else plain DNS over UDP. sni/servername rewrites
// the TLS ClientHello SNI of the DNS connection itself (the protected DNS
// server sees a different name); it also disables certificate verification,
// matching the desktop kernel's rejectUnauthorized:false.
type DNSProvider struct {
	Server string `json:"server,omitempty"`
	// Host is a legacy alias for Server.
	Host string `json:"host,omitempty"`
	// Type is derived from the server scheme when empty:
	// https/doh/dns-over-https, tls/dot/dns-over-tls, tcp, udp.
	Type string `json:"type,omitempty"`
	// Port defaults to 853 for DoT, 53 for UDP/TCP; DoH uses the URL port.
	Port int `json:"port,omitempty"`
	// Family forces IPv4 (4) or IPv6 (6) connections to the DNS server.
	Family int `json:"family,omitempty"`
	// SNI rewrites the TLS SNI of the DNS connection itself.
	SNI string `json:"sni,omitempty"`
	// ServerName is an alias for SNI.
	ServerName string `json:"servername,omitempty"`
	// ForSNI (or ForSni) marks this provider as the default for hosts that
	// carry an SNI rule but no DNS mapping.
	ForSNI bool `json:"forSNI,omitempty"`
	ForSni    bool `json:"forSni,omitempty"`
	CacheSize int  `json:"cacheSize,omitempty"`
	// ECH is parsed for configuration compatibility (provider-level ECH kill
	// switch in newer desktop kernels); the Go kernel ignores it for now.
	ECH *bool `json:"ech,omitempty"`
}

// SNIOverride merges the two accepted spellings of the SNI field.
func (p *DNSProvider) SNIOverride() string {
	if p == nil {
		return ""
	}
	if s := strings.TrimSpace(p.SNI); s != "" {
		return s
	}
	return strings.TrimSpace(p.ServerName)
}

// StdServer returns Server, falling back to the legacy Host alias.
func (p *DNSProvider) StdServer() string {
	if p == nil {
		return ""
	}
	if s := strings.TrimSpace(p.Server); s != "" {
		return s
	}
	return strings.TrimSpace(p.Host)
}

// MarkedForSNI merges the two accepted spellings of the forSNI flag.
func (p *DNSProvider) MarkedForSNI() bool {
	if p == nil {
		return false
	}
	return p.ForSNI || p.ForSni
}

// DNSMapping is one "server.dns.mapping" value: either the plain provider name
// ("quad9") or an object form {dns: "name", family: 4}.
type DNSMapping struct {
	DNSName string `json:"dns,omitempty"`
	Family  int    `json:"family,omitempty"`
}

func (m *DNSMapping) UnmarshalJSON(b []byte) error {
	// null keeps the entry empty so it is skipped by consumers.
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		m.DNSName = s
		return nil
	}
	type plain struct {
		DNS    string `json:"dns"`
		Name   string `json:"name"`
		Family int    `json:"family"`
	}
	var o plain
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	m.DNSName = o.DNS
	if m.DNSName == "" {
		m.DNSName = o.Name
	}
	m.Family = o.Family
	return nil
}

// DNS groups the resolution settings.
type DNS struct {
	// Providers names the available DNS servers ("DNS服务管理").
	Providers map[string]*DNSProvider `json:"providers,omitempty"`
	// Mapping selects a provider (by name) per host pattern.
	Mapping map[string]DNSMapping `json:"mapping,omitempty"`
	// SpeedTest is kept for configuration compatibility.
	SpeedTest struct {
		Interval int `json:"interval,omitempty"`
	} `json:"speedTest,omitempty"`
}

// IPList is one "preSetIpList" value. The configuration sends either an array
// of addresses, an object whose keys are addresses and whose values merely
// enable them (true / "false" / "0" fine-grained), or null to delete an entry.
type IPList []string

func (l *IPList) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*l = nil
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*l = arr
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	for key, raw := range obj {
		if entryEnabled(raw) {
			*l = append(*l, key)
		}
	}
	return nil
}

// entryEnabled mirrors the desktop kernel's mapToList: anything truthy counts
// except the strings "false" and "0".
func entryEnabled(raw json.RawMessage) bool {
	switch string(raw) {
	case "true":
		return true
	case "false", "null", "0":
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	if s == "" || s == "false" || s == "0" {
		return false
	}
	return true
}

// Server is the "server" section of the configuration.
type Server struct {
	// Intercepts maps host pattern -> path pattern -> rule.
	Intercepts map[string]map[string]Rule `json:"intercepts,omitempty"`
	// PreSetIPList maps host pattern to addresses that bypass resolution.
	PreSetIPList map[string]IPList `json:"preSetIpList,omitempty"`
	DNS          DNS               `json:"dns,omitempty"`
	WhiteList    map[string]bool   `json:"whiteList,omitempty"`
}

// Proxy is the "proxy" section of the configuration.
type Proxy struct {
	ExcludeIPList map[string]bool `json:"excludeIpList,omitempty"`
}

// Config is a whole dev-sidecar configuration file.
type Config struct {
	Server Server `json:"server,omitempty"`
	Proxy  Proxy  `json:"proxy,omitempty"`
}

// Load reads and parses a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses configuration bytes.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(StripJSON5(data), &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// StripJSON5 converts the JSON5 subset used by dev-sidecar into JSON:
// comments are removed, single-quoted strings are rewritten and trailing
// commas in objects/arrays are dropped.
func StripJSON5(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')

		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++ // sit on the closing '/'
			out = append(out, ' ')

		case c == '"' || c == '\'':
			// Normalize to a double-quoted JSON string.
			quote := c
			out = append(out, '"')
			for i++; i < len(b); i++ {
				if b[i] == '\\' && i+1 < len(b) {
					out = append(out, b[i], b[i+1])
					i++
					continue
				}
				if b[i] == quote {
					break
				}
				if b[i] == '"' {
					out = append(out, '\\')
				}
				out = append(out, b[i])
			}
			out = append(out, '"')

		default:
			out = append(out, c)
		}
	}
	return dropTrailingCommas(out)
}

func dropTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && isSpace(b[j]) {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

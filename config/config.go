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

// DNS groups the resolution settings.
type DNS struct {
	// Mapping selects a resolver (by name) per host pattern.
	Mapping map[string]string `json:"mapping,omitempty"`
	// SpeedTest is kept for configuration compatibility.
	SpeedTest struct {
		Interval int `json:"interval,omitempty"`
	} `json:"speedTest,omitempty"`
}

// Server is the "server" section of the configuration.
type Server struct {
	// Intercepts maps host pattern -> path pattern -> rule.
	Intercepts map[string]map[string]Rule `json:"intercepts,omitempty"`
	// PreSetIPList maps host pattern to addresses that bypass resolution.
	PreSetIPList map[string][]string `json:"preSetIpList,omitempty"`
	DNS          DNS                 `json:"dns,omitempty"`
	WhiteList    map[string]bool     `json:"whiteList,omitempty"`
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

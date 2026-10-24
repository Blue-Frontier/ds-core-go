// Package dnsres resolves names the way the kernel configuration asks for:
// preset addresses first, then a per-host resolver mapping, then the system
// resolver.
package dnsres

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// DefaultServers maps the resolver names used by the configuration to
// addresses.
var DefaultServers = map[string]string{
	"quad9":  "9.9.9.9:53",
	"ali":    "223.5.5.5:53",
	"dnspod": "119.29.29.29:53",
	"google": "8.8.8.8:53",
}

type presetEntry struct {
	pattern string
	ips     []net.IP
}

type mappingEntry struct {
	pattern    string
	serverAddr string
}

// Resolver resolves hosts with preset addresses and per-host DNS servers.
type Resolver struct {
	preset  []presetEntry
	mapping []mappingEntry
	system  *net.Resolver
}

// New builds a resolver from the "server" section.
func New(s *config.Server, servers map[string]string) *Resolver {
	if servers == nil {
		servers = DefaultServers
	}
	r := &Resolver{system: net.DefaultResolver}

	if s != nil {
		for pattern, list := range s.PreSetIPList {
			e := presetEntry{pattern: pattern}
			for _, raw := range list {
				if ip := net.ParseIP(raw); ip != nil {
					e.ips = append(e.ips, ip)
				}
			}
			if len(e.ips) > 0 {
				r.preset = append(r.preset, e)
			}
		}
		for pattern, name := range s.DNS.Mapping {
			addr, ok := servers[name]
			if !ok {
				continue
			}
			r.mapping = append(r.mapping, mappingEntry{pattern: pattern, serverAddr: addr})
		}
	}

	// Longer patterns first so specific entries win deterministically.
	sort.Slice(r.preset, func(i, j int) bool { return len(r.preset[i].pattern) > len(r.preset[j].pattern) })
	sort.Slice(r.mapping, func(i, j int) bool { return len(r.mapping[i].pattern) > len(r.mapping[j].pattern) })
	return r
}

// Lookup resolves host to addresses.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	h := hostmatch.Normalize(host)
	if h == "" {
		return nil, fmt.Errorf("dnsres: empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		return []net.IP{ip}, nil
	}
	if r == nil {
		return net.DefaultResolver.LookupIP(ctx, "ip", h)
	}

	for _, e := range r.preset {
		if hostmatch.Match(e.pattern, h) {
			return e.ips, nil
		}
	}

	res := r.system
	for _, e := range r.mapping {
		if !hostmatch.Match(e.pattern, h) {
			continue
		}
		addr := e.serverAddr
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", addr)
			},
		}
		break
	}
	return res.LookupIP(ctx, "ip", h)
}

// Preset reports whether host has a preset address list.
func (r *Resolver) Preset(host string) bool {
	if r == nil {
		return false
	}
	h := hostmatch.Normalize(host)
	for _, e := range r.preset {
		if hostmatch.Match(e.pattern, h) {
			return true
		}
	}
	return false
}

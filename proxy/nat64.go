package proxy

import (
	"net"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// nat64Prefix returns the synthesis prefix for host, if NAT64 covers it.
func nat64Prefix(cfg config.NAT64, host string) (net.IP, bool) {
	if !cfg.Enabled {
		return nil, false
	}
	prefix := strings.TrimSpace(cfg.Prefix)
	if prefix == "" {
		// The desktop refuses to synthesise without an explicit prefix: there
		// is no built-in public NAT64 gateway.
		return nil, false
	}
	ip := net.ParseIP(prefix)
	if ip == nil {
		return nil, false
	}
	for _, pattern := range cfg.Domains {
		if hostmatch.Match(pattern, host) {
			return ip.To16(), true
		}
	}
	return nil, false
}

// toNAT64 embeds an IPv4 address into the prefix, producing the IPv6 address a
// NAT64 gateway can reach.
func toNAT64(prefix net.IP, v4 net.IP) net.IP {
	p := prefix.To16()
	if p == nil || len(p) != net.IPv6len {
		return nil
	}
	inner := v4.To4()
	if inner == nil {
		return nil
	}
	out := make(net.IP, net.IPv6len)
	copy(out, p)
	copy(out[12:], inner)
	return out
}

// applyNAT64 rewrites the IPv4 answers for a covered host into NAT64 addresses.
// Native IPv6 answers are kept as they are.
func applyNAT64(prefix net.IP, ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			if synth := toNAT64(prefix, v4); synth != nil {
				out = append(out, synth)
			}
			continue
		}
		out = append(out, ip)
	}
	return out
}

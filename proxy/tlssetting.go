package proxy

import (
	"crypto/tls"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// upstreamTLS resolves the TLS floor and the verification switch for host.
// The desktop derives these from server.setting (util.js getTimeoutConfig):
// the per-host tlsVersionMapping wins, then allowTls12 decides between
// TLS 1.3 (the default) and TLS 1.2.
func (s *Server) upstreamTLS(host string) (uint16, bool) {
	st := s.st()
	if st == nil {
		return tls.VersionTLS13, true
	}
	// Node's default floor is TLS 1.2. The desktop's allowTls12:false only
	// tightens the *pooled agent* path; its connection-close path (the one a
	// per-request kernel resembles) still negotiates 1.2. Verified against the
	// desktop proxy: www.baidu.com answers 200 there while a 1.3-only floor
	// fails with "protocol version not supported".
	minVersion := uint16(tls.VersionTLS12)
	best := uint16(0)
	bestLen := -1
	for pattern, version := range st.tlsVersions {
		if !hostmatch.Match(pattern, host) {
			continue
		}
		if len(pattern) > bestLen {
			best, bestLen = version, len(pattern)
		}
	}
	if best != 0 {
		minVersion = best
	}
	return minVersion, st.verifySsl
}

// tlsVersionMap normalises the configured per-host versions.
func tlsVersionMap(in map[string]config.TLSVersionRule) map[string]uint16 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]uint16, len(in))
	for pattern, rule := range in {
		if !rule.Enabled {
			continue
		}
		if v := parseTLSVersion(rule.Version); v != 0 {
			out[pattern] = v
		}
	}
	return out
}

// parseTLSVersion accepts the spellings the desktop's normalizeTlsVersion does.
func parseTLSVersion(s string) uint16 {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tlsv1.2", "1.2", "tls1.2":
		return tls.VersionTLS12
	case "tlsv1.3", "1.3", "tls1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

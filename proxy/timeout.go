package proxy

import (
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// desktopRequestTimeout is the desktop's "server.setting.defaultTimeout".
const desktopRequestTimeout = 20 * time.Second

// timeoutMap turns the configured per-host timeouts into milliseconds.
func timeoutMap(in map[string]config.HostTimeout) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for pattern, t := range in {
		if t.Timeout > 0 {
			out[pattern] = t.Timeout
		}
	}
	return out
}

// RequestTimeout exposes the per-host budget to callers outside the package.
func (s *Server) RequestTimeout(host string) time.Duration { return s.requestTimeout(host) }

// requestTimeout returns how long to wait for a response from host: the
// per-host mapping wins, then the configured default, then the desktop's 20s.
// The desktop keeps github.com at 20s; a shorter fixed budget made slow origins
// fail as if the network were down.
func (s *Server) requestTimeout(host string) time.Duration {
	st := s.st()
	if st == nil {
		return desktopRequestTimeout
	}
	best := 0
	bestLen := -1
	for pattern, ms := range st.timeoutMapping {
		if !hostmatch.Match(pattern, host) {
			continue
		}
		// The most specific pattern wins, mirroring the table lookup.
		if len(pattern) > bestLen {
			best, bestLen = ms, len(pattern)
		}
	}
	if best > 0 {
		return time.Duration(best) * time.Millisecond
	}
	if st.defaultTimeout > 0 {
		return time.Duration(st.defaultTimeout) * time.Millisecond
	}
	return desktopRequestTimeout
}

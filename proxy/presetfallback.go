package proxy

import "time"

// presetDeadTTL is how long a host's preset addresses stay skipped after they
// all failed, so a burst of requests does not each pay the full dial budget.
//
// The desktop kernel has no host-level ban at all: it scores addresses
// individually (`mitmproxy/src/lib/choice/index.js`), switches on the first
// consecutive failure and re-ranks by success rate, so the next request starts
// from the best remaining address immediately. Ten minutes of "use DNS
// instead" was far too long a memory for that model — a host whose DNS is the
// broken side stayed broken until the timer ran out.
const presetDeadTTL = 30 * time.Second

// presetConsideredDead reports whether the preset list for host is known bad.
func (s *Server) presetConsideredDead(host string) bool {
	s.presetMu.Lock()
	defer s.presetMu.Unlock()
	until, ok := s.presetDead[host]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(s.presetDead, host)
		return false
	}
	return true
}

// markPresetDead remembers that every address of the preset list failed.
func (s *Server) markPresetDead(host string) {
	s.presetMu.Lock()
	defer s.presetMu.Unlock()
	if s.presetDead == nil {
		s.presetDead = map[string]time.Time{}
	}
	s.presetDead[host] = time.Now().Add(presetDeadTTL)
}

// clearPresetDead drops the mark. The decision to lead with DNS is a guess made
// from one failed round; when DNS cannot connect either the guess was wrong, so
// the next request should start from the preset again rather than wait out the
// cooldown.
func (s *Server) clearPresetDead(host string) {
	s.presetMu.Lock()
	defer s.presetMu.Unlock()
	delete(s.presetDead, host)
}

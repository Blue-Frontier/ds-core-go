package proxy

import "time"

// presetDeadTTL is how long a host's preset addresses stay skipped after they
// all failed. The list is refreshed by the remote configuration, so this only
// has to outlive a page load or two.
const presetDeadTTL = 10 * time.Minute

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

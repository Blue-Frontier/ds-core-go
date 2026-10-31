package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/dnsres"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// echState caches the ECHConfigList fetched from each host's HTTPS record.
type echState struct {
	cfg     config.ECH
	mu      sync.Mutex
	entries map[string]echEntry
}

type echEntry struct {
	list    []byte
	expires time.Time
}

func newECH(cfg config.ECH) *echState {
	if !cfg.Enabled || !cfg.Use || len(cfg.Domains) == 0 {
		return nil
	}
	return &echState{cfg: cfg, entries: map[string]echEntry{}}
}

func (e *echState) covers(host string) bool {
	for _, pattern := range e.cfg.Domains {
		if hostmatch.Match(pattern, host) {
			return true
		}
	}
	return false
}

// list returns the host's ECHConfigList, fetching it once per TTL.
func (e *echState) list(ctx context.Context, host string, r *dnsres.Resolver) []byte {
	e.mu.Lock()
	entry, ok := e.entries[host]
	e.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.list
	}

	rec, err := r.LookupHTTPS(ctx, host, e.cfg.DNS)
	if err != nil || rec == nil || len(rec.ECH) == 0 {
		return nil
	}
	e.mu.Lock()
	e.entries[host] = echEntry{list: rec.ECH, expires: time.Now().Add(time.Hour)}
	e.mu.Unlock()
	return rec.ECH
}

// echConfigList returns the ECHConfigList for host when the configuration
// covers it, or nil.
func (s *Server) echConfigList(ctx context.Context, host string) []byte {
	st := s.st()
	if st == nil || st.ech == nil || !st.ech.covers(host) {
		return nil
	}
	return st.ech.list(ctx, host, st.dns)
}

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
//
// A host that publishes no ECH parameter in its own HTTPS record still has to
// be reached with ECH when the server requires it, so the shared configuration
// published by the configured publicName is used instead. The desktop kernel
// does the same: "未下发ECH记录，改用共享ECH配置".
func (e *echState) list(ctx context.Context, host string, r *dnsres.Resolver) []byte {
	if cached, ok := e.cached(host); ok {
		return cached
	}

	rec, err := r.LookupHTTPS(ctx, host, e.cfg.DNS)
	if err == nil && rec != nil && len(rec.ECH) > 0 {
		e.store(host, rec.ECH)
		return rec.ECH
	}
	return e.shared(ctx, r)
}

// shared resolves the ECHConfigList of the shared public name.
func (e *echState) shared(ctx context.Context, r *dnsres.Resolver) []byte {
	name := e.cfg.PublicName
	if name == "" {
		return nil
	}
	if cached, ok := e.cached(name); ok {
		return cached
	}
	rec, err := r.LookupHTTPS(ctx, name, e.cfg.DNS)
	if err != nil || rec == nil || len(rec.ECH) == 0 {
		// Cache the miss for a short while so a broken lookup does not cost a
		// DNS round trip on every connection.
		e.store(name, nil)
		return nil
	}
	e.store(name, rec.ECH)
	return rec.ECH
}

func (e *echState) cached(host string) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.entries[host]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.list, true
}

func (e *echState) store(host string, list []byte) {
	ttl := time.Hour
	if list == nil {
		ttl = 5 * time.Minute
	}
	e.mu.Lock()
	e.entries[host] = echEntry{list: list, expires: time.Now().Add(ttl)}
	e.mu.Unlock()
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

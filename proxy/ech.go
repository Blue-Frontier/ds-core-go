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
// bundledShared holds a copy of the shared ECHConfigList. Fetching it needs a
// resolver that publishes ECH parameters, and on networks that reset TLS for
// cloudflare-dns.com no such resolver can be reached, so the app pins the value
// it obtained while a working network was available.
var bundledShared []byte

// SetBundledSharedECH records the shared ECHConfigList shipped with the app.
func SetBundledSharedECH(list []byte) {
	bundledShared = append([]byte(nil), list...)
}

func (e *echState) shared(ctx context.Context, r *dnsres.Resolver) []byte {
	name := e.cfg.PublicName
	if name == "" {
		return nil
	}
	if cached, ok := e.cached(name); ok {
		if len(cached) > 0 {
			return cached
		}
		// A negative entry only says the record was missing once; the bundled
		// copy may still be usable.
		return bundledShared
	}
	// The bundled copy is the same configuration the lookup would return, and a
	// live lookup on a network that blocks it costs the full DNS deadline on the
	// connection's path, so it is preferred when present.
	if len(bundledShared) > 0 {
		e.store(name, bundledShared)
		return bundledShared
	}
	rec, err := r.LookupHTTPS(ctx, name, e.cfg.DNS)
	if err == nil && rec != nil && len(rec.ECH) > 0 {
		e.store(name, rec.ECH)
		return rec.ECH
	}
	if err == nil {
		// The name answered and publishes no ECH parameter; that verdict may be
		// cached. A failed lookup says nothing about the record.
		e.store(name, nil)
	}
	// Either way the bundled copy still lets the connection use ECH.
	return bundledShared
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

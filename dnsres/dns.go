// Package dnsres resolves names the way the desktop kernel asks for: preset
// addresses first, then a per-host provider mapping (DoH / DoT / TCP / UDP
// DNS), for SNI-rewritten hosts the ForSNI provider, and finally the system
// resolver. Each provider keeps its own cache and IP preference state, so a
// dead preset address is rotated away after its first failure.
package dnsres

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// Transport types of the provider switch.
const (
	typUDP    = "UDP"
	typTCP    = "TCP"
	typDoT    = "TLS"
	typDoH    = "HTTPS"
	typPreSet = "PreSet"
)

// builtinServers backfills legacy mapping names ("quad9", ...) that files
// produced before the "providers" section reference directly.
var builtinServers = map[string]string{
	"quad9":  "9.9.9.9:53",
	"ali":    "223.5.5.5:53",
	"dnspod": "119.29.29.29:53",
	"google": "8.8.8.8:53",
}

// Option customizes a Resolver.
type Option func(*Resolver)

// WithLogger sets the resolver's logger.
func WithLogger(log *slog.Logger) Option {
	return func(r *Resolver) {
		if log != nil {
			r.log = log
		}
	}
}

// WithRootCAs overrides the root pool used to verify DoT / DoH server
// certificates. Without an SNI rewrite the DNS connection is verified like
// any other TLS connection; with a rewrite the certificate is not verified
// (matching the desktop kernel's rejectUnauthorized:false).
func WithRootCAs(p *x509.CertPool) Option {
	return func(r *Resolver) {
		r.rootCAs = p
	}
}

// Resolver resolves hosts with preset addresses, per-host DNS providers and
// the system resolver as the last station.
type Resolver struct {
	providers map[string]*Provider
	order     []string // deterministic iteration
	presetIdx *presetIndex
	preset    *Provider
	forSNI    *Provider
	mapping   []mappingEntry
	system    *net.Resolver
	log       *slog.Logger
	rootCAs   *x509.CertPool
}

type mappingEntry struct {
	pattern string
	name    string
	family  int
}

// New builds a resolver from the "server" section.
func New(s *config.Server, opts ...Option) *Resolver {
	r := &Resolver{
		providers: map[string]*Provider{},
		system:    net.DefaultResolver,
		log:       slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}

	names := make([]string, 0, len(s.DNS.Providers))
	for name := range s.DNS.Providers {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		nn := strings.TrimSpace(name)
		conf := s.DNS.Providers[name]
		if nn == "" {
			continue
		}
		p, err := newProvider(nn, conf, r.rootCAs, r.log)
		switch {
		case err != nil:
			r.log.Warn("dnsres: skip DNS provider", "name", nn, "err", err)
		default:
			r.providers[nn] = p
			r.order = append(r.order, nn)
			if conf.MarkedForSNI() && r.forSNI == nil {
				r.forSNI = p
			}
		}
	}

	// PreSet serves the configured address list and is the ForSNI default
	// (desktop kernel: dnsMap.ForSNI ||= PreSet).
	r.presetIdx = newPresetIndex(s.PreSetIPList)
	r.preset = newPreSetProvider(r.presetIdx, r.log)
	if r.forSNI == nil {
		r.forSNI = r.preset
	}

	// Mapping entries: longest pattern first so specific entries win.
	for pattern, m := range s.DNS.Mapping {
		name := strings.TrimSpace(m.DNSName)
		if name == "" {
			continue
		}
		r.mapping = append(r.mapping, mappingEntry{pattern: pattern, name: name, family: m.Family})
	}
	slices.SortStableFunc(r.mapping, func(a, b mappingEntry) int {
		return cmp.Compare(len(b.pattern), len(a.pattern))
	})

	// Backfill legacy provider names referenced by the mapping but absent
	// from the "providers" section.
	for _, e := range r.mapping {
		if _, ok := r.providers[e.name]; ok {
			continue
		}
		addr, ok := builtinServers[e.name]
		if !ok {
			continue
		}
		host, port, _ := net.SplitHostPort(addr)
		conf := &config.DNSProvider{Server: host, Port: atoi(port)}
		p, err := newProvider(e.name, conf, r.rootCAs, r.log)
		if err == nil && p != nil {
			r.providers[e.name] = p
			r.order = append(r.order, e.name)
		}
	}

	for _, nn := range r.order {
		p := r.providers[nn]
		r.log.Info("dnsres: DNS provider", "name", nn, "type", p.typ, "server", p.describe())
	}
	r.log.Info("dnsres: default DNS for SNI hosts", "dns", r.forSNI.Name)
	return r
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// Lookup resolves host to addresses: preset IP first, then the mapped
// provider, then any other provider, then the system resolver.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	return r.resolve(ctx, host, false)
}

// LookupForSNI resolves a host that carries an SNI rule but no DNS mapping,
// through the ForSNI provider (default: the preset address list).
func (r *Resolver) LookupForSNI(ctx context.Context, host string) ([]net.IP, error) {
	return r.resolve(ctx, host, true)
}

// HasDNS reports whether host is covered by a preset list or a provider
// mapping. Hosts only carrying an SNI rule resolve through LookupForSNI.
func (r *Resolver) HasDNS(host string) bool {
	if r == nil {
		return false
	}
	h := hostmatch.Normalize(host)
	if h == "" {
		return false
	}
	if r.presetIdx.matchList(h) != nil {
		return true
	}
	for _, e := range r.mapping {
		if hostmatch.Match(e.pattern, h) {
			if _, ok := r.providers[e.name]; ok {
				return true
			}
		}
	}
	return false
}

// Note reports a dial result so the provider's IP preference rotates away
// addresses that keep failing, like the desktop kernel counts IP errors.
func (r *Resolver) Note(host, ip string, failed bool) {
	if r == nil || ip == "" || ip == host {
		return
	}
	h := hostmatch.Normalize(host)
	p := r.primary(h)
	if p == nil {
		return
	}
	p.count(h, ip, failed)
}

// Preset reports whether host has a preset address list.
func (r *Resolver) Preset(host string) bool {
	if r == nil {
		return false
	}
	return r.presetIdx.matchList(hostmatch.Normalize(host)) != nil
}

// resolve walks the selection chain. Hosts without preset/mapping go straight
// to the system DNS (desktop createDefaultLookupFunc); providers only join as
// a real fallback after the primary station failed, never as a latency tax in
// front of every plain lookup.
func (r *Resolver) resolve(ctx context.Context, host string, forSNI bool) ([]net.IP, error) {
	h := hostmatch.Normalize(host)
	if h == "" {
		return nil, errors.New("dnsres: empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		return []net.IP{ip}, nil
	}

	primary := r.primary(h)
	if forSNI {
		// Preset and mapping still win (desktop getDNSAndFamily runs before
		// the SNI fallback); ForSNI fills the gap for uncovered hosts.
		route := primary
		if route == nil {
			route = r.forSNI
		}
		if route != nil {
			if ips := r.viaProvider(ctx, route, h, 0); len(ips) > 0 {
				return ips, nil
			}
		}
		if route == r.preset || route == nil {
			return r.systemLookup(ctx, h)
		}
		return r.remainingProvidersAndSystem(ctx, h, route), nil
	}

	if primary != nil {
		if ips := r.viaProvider(ctx, primary, h, 0); len(ips) > 0 {
			return ips, nil
		}
		return r.remainingProvidersAndSystem(ctx, h, primary), nil
	}
	// No preset, no mapping: system DNS first; its result feeds the caller
	// directly. Only chances of real failure trigger provider attempts.
	ips, err := r.systemLookup(ctx, h)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}
	for _, name := range r.order {
		p := r.providers[name]
		if ips := r.viaProvider(ctx, p, h, 0); len(ips) > 0 {
			return ips, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("resolve %s: no addresses", h)
}

// LookupFallback resolves host while skipping the preset list. The kernel calls
// it when every preset address turned out to be dead: the preset list is a hint,
// not a hard override, and reaching the origin through normal DNS is better
// than failing every request for that host.
func (r *Resolver) LookupFallback(ctx context.Context, host string) ([]net.IP, error) {
	h := hostmatch.Normalize(host)
	if h == "" {
		return nil, errors.New("dnsres: empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		return []net.IP{ip}, nil
	}
	primary := r.primary(h)
	if primary == r.preset || primary == nil {
		// Encrypted transports first: the whole point of the built-in providers
		// is to obtain an answer plaintext DNS would poison, so a fallback that
		// starts with UDP defeats it. They are queried concurrently so one slow
		// or blocked provider cannot hold up the answer.
		candidates := make([]*Provider, 0, len(r.order))
		for _, p := range r.providersBySecurity() {
			if p != r.preset {
				candidates = append(candidates, p)
			}
		}
		if ips := r.raceProviders(ctx, candidates, h); len(ips) > 0 {
			return ips, nil
		}
		return r.systemLookup(ctx, h)
	}
	return r.remainingProvidersAndSystem(ctx, h, primary), nil
}

// raceProviders queries every provider at once and returns the first answer.
// A slow or blackholed provider therefore costs nothing as long as any other
// one replies; the losers are cancelled.
func (r *Resolver) raceProviders(ctx context.Context, providers []*Provider, host string) []net.IP {
	if len(providers) == 0 {
		return nil
	}
	if len(providers) == 1 {
		return r.viaProvider(ctx, providers[0], host, 0)
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	answers := make(chan []net.IP, len(providers))
	for _, p := range providers {
		go func(p *Provider) {
			ips := r.viaProvider(rctx, p, host, 0)
			select {
			case answers <- ips:
			case <-rctx.Done():
			}
		}(p)
	}

	for range providers {
		select {
		case ips := <-answers:
			if len(ips) > 0 {
				return ips
			}
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

// providersBySecurity lists the providers with DoT/DoH ahead of the plaintext
// ones, keeping the configured order inside each tier.
func (r *Resolver) providersBySecurity() []*Provider {
	encrypted := make([]*Provider, 0, len(r.order))
	plain := make([]*Provider, 0, len(r.order))
	for _, name := range r.order {
		p := r.providers[name]
		if p == nil {
			continue
		}
		if p.typ == typDoH || p.typ == typDoT {
			encrypted = append(encrypted, p)
		} else {
			plain = append(plain, p)
		}
	}
	return append(encrypted, plain...)
}

// remainingProvidersAndSystem tries every provider except the one already
// attempted (desktop getFallbackDnsList minus PreSet), then the system DNS.
func (r *Resolver) remainingProvidersAndSystem(ctx context.Context, h string, tried *Provider) []net.IP {
	for _, name := range r.order {
		p := r.providers[name]
		if p == nil || p == tried {
			continue
		}
		if ips := r.viaProvider(ctx, p, h, 0); len(ips) > 0 {
			return ips
		}
	}
	ips, err := r.systemLookup(ctx, h)
	if err != nil {
		r.log.Debug("dnsres: system fallback failed", "host", h, "err", err)
		return nil
	}
	return ips
}

// UsesPreset reports whether host is served by the preset address list, so the
// caller knows a failure there means the hint is stale rather than the network.
func (r *Resolver) UsesPreset(host string) bool {
	if r == nil {
		return false
	}
	return r.primary(hostmatch.Normalize(host)) == r.preset
}

// primary picks preset → mapped provider, or nil (system DNS).
func (r *Resolver) primary(h string) *Provider {
	if r == nil {
		return nil
	}
	if ips := r.presetIdx.matchList(h); ips != nil {
		return r.preset
	}
	if e, ok := r.mappedEntry(h); ok {
		return r.providers[e.name] // nil when the name is unknown
	}
	return nil
}

func (r *Resolver) mappedEntry(h string) (mappingEntry, bool) {
	for _, e := range r.mapping {
		if hostmatch.Match(e.pattern, h) {
			return e, true
		}
	}
	return mappingEntry{}, false
}

func (r *Resolver) viaProvider(ctx context.Context, p *Provider, h string, family int) []net.IP {
	if p == nil {
		return nil
	}
	ips, err := p.lookup(ctx, h, family)
	if err != nil {
		r.log.Warn("dnsres: provider lookup failed", "dns", p.Name, "host", h, "err", err)
		return nil
	}
	if len(ips) > 0 {
		r.log.Debug("dnsres: resolved", "dns", p.Name, "host", h, "ips", ips)
	}
	return ips
}

func (r *Resolver) systemLookup(ctx context.Context, h string) ([]net.IP, error) {
	ips, err := r.system.LookupIPAddr(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", h, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", h)
	}
	out := make([]net.IP, len(ips))
	for i, addr := range ips {
		out[i] = addr.IP
	}
	r.log.Debug("dnsres: system DNS", "host", h, "ips", out)
	return out, nil
}

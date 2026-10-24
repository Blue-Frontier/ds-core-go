package dnsres

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// dotPort is the default DNS-over-TLS port (RFC 7858).
const dotPort = 853

// presetEntry is one preSetIpList row.
type presetEntry struct {
	pattern string
	ips     []net.IP
}

// presetIndex holds the shared preSetIpList (longest pattern first).
type presetIndex struct {
	entries []presetEntry
}

func newPresetIndex(lists map[string]config.IPList) *presetIndex {
	p := &presetIndex{}
	for pattern, list := range lists {
		e := presetEntry{pattern: pattern}
		for _, raw := range list {
			if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
				e.ips = append(e.ips, ip)
			}
		}
		if len(e.ips) > 0 {
			p.entries = append(p.entries, e)
		}
	}
	slices.SortStableFunc(p.entries, func(a, b presetEntry) int {
		return cmp.Compare(len(b.pattern), len(a.pattern))
	})
	return p
}

// matchList returns the preset addresses whose pattern matches host, or nil.
func (p *presetIndex) matchList(host string) []net.IP {
	if p == nil {
		return nil
	}
	h := hostmatch.Normalize(host)
	if h == "" {
		return nil
	}
	for _, e := range p.entries {
		if hostmatch.Match(e.pattern, h) {
			return e.ips
		}
	}
	return nil
}

// Provider is one DNS service (DoH / DoT / TCP / UDP / PreSet) with its own
// cache and IP preference state.
type Provider struct {
	Name string
	typ  string

	preset  *presetIndex // checked first, as on the desktop kernel
	cache   *lru         // hostname -> *ipChoice
	log     *slog.Logger
	rootCAs *x509.CertPool

	server string // bare host, no scheme, no port
	port   int
	family int    // preferred address family of the DNS server connection
	sni    string // SNI rewrite of the DNS connection itself

	doh *dohClient

	mu sync.Mutex
}

// newProvider builds one provider from its configuration; (nil, nil) marks a
// definition without a usable server, (nil, err) a broken one.
func newProvider(name string, conf *config.DNSProvider, rootCAs *x509.CertPool, log *slog.Logger) (*Provider, error) {
	// The desktop kernel strippess all whitespace from the server string
	// before the scheme sniffing.
	raw := strings.ToLower(strings.Join(strings.Fields(conf.StdServer()), ""))
	if raw == "" {
		return nil, nil
	}

	p := &Provider{
		Name:    name,
		cache:   newLRU(conf.CacheSize),
		log:     log,
		family:  conf.Family,
		sni:     conf.SNIOverride(),
		rootCAs: rootCAs,
	}

	typ := classifyType(raw, conf.Type)
	if typ == "" {
		return nil, nil
	}
	p.typ = typ

	var server string
	switch typ {
	case typDoH:
		c, err := newDohClient(raw, p.sni, p.family, rootCAs)
		if err != nil {
			return nil, err
		}
		p.doh = c
		server = c.host()
		p.port = atoi(c.port())
	case typDoT:
		server = strings.TrimPrefix(raw, "tls://")
		server = strings.TrimPrefix(server, "dot://")
		p.port = defaultPortFor(dotPort, conf.Port)
	case typTCP:
		server = strings.TrimPrefix(raw, "tcp://")
		p.port = defaultPortFor(53, conf.Port)
	case typUDP:
		server = strings.TrimPrefix(raw, "udp://")
		p.port = defaultPortFor(53, conf.Port)
	}
	// IPv6 literals may carry bracketed ports; extract them.
	if i := strings.LastIndex(server, "]"); i >= 0 && strings.Contains(server[:i], "[") {
		if h, port, err := net.SplitHostPort(server); err == nil {
			server, p.port = h, atoi(port)
		} else {
			server = strings.Trim(server, "[]")
		}
	} else if !strings.HasPrefix(server, "[") {
		if h, port, err := net.SplitHostPort(server); err == nil && port != "" {
			server, p.port = h, atoi(port)
		}
	}
	server = strings.Trim(server, "[]")
	if net.ParseIP(server) == nil && server == "" {
		return nil, nil
	}
	p.server = server
	if p.family == 0 {
		if ip := net.ParseIP(server); ip != nil && ip.To4() == nil {
			p.family = 6
		}
	}
	return p, nil
}

// classifyType mirrors index.js: an explicit type wins (with the desktop
// kernel's aliases), otherwise the server scheme decides.
func classifyType(server, typ string) string {
	normalize := func(t string) string {
		switch t {
		case "https", "doh", "dns-over-https":
			return typDoH
		case "tls", "dot", "dns-over-tls":
			return typDoT
		case "tcp":
			return typTCP
		case "udp":
			return typUDP
		}
		return ""
	}
	if typ = strings.ToLower(strings.TrimSpace(typ)); typ != "" {
		return normalize(typ)
	}
	switch {
	case strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "http://"):
		return typDoH
	case strings.HasPrefix(server, "tls://") || strings.HasPrefix(server, "dot://"):
		return typDoT
	case strings.HasPrefix(server, "tcp://"):
		return typTCP
	case strings.HasPrefix(server, "udp://"):
		return typUDP
	case strings.Contains(server, "://"):
		// Desktop kernel throws; the Go kernel skips the provider instead.
		return ""
	default:
		return typUDP
	}
}

// defaultPortFor keeps an explicit port and otherwise falls back to def.
func defaultPortFor(def, explicit int) int {
	if explicit > 0 {
		return explicit
	}
	return def
}

// newPreSetProvider builds the static provider of the preSetIpList.
func newPreSetProvider(idx *presetIndex, log *slog.Logger) *Provider {
	return &Provider{
		Name:   "PreSet",
		typ:    typPreSet,
		preset: idx,
		cache:  newLRU(1024),
		log:    log,
	}
}

// describe renders server settings for the startup log.
func (p *Provider) describe() string {
	switch p.typ {
	case typDoH:
		return p.doh.server
	default:
		return net.JoinHostPort(p.server, strconv.Itoa(p.port))
	}
}

// lookup resolves host through preset, cache, then the transport. family
// forces 4 (A) or 6 (AAAA) when the mapping asks for it; 0 means A (as on the
// desktop kernel, where a missing family resolves IPv4 only).
func (p *Provider) lookup(ctx context.Context, host string, family int) ([]net.IP, error) {
	if p == nil {
		return nil, errors.New("dnsres: nil provider")
	}

	ips, err := p.query(ctx, host, family)
	if err != nil {
		return nil, err
	}

	// Cache the choice list (real addresses only; fallback to system DNS is
	// the resolver chain's job, not a fake candidate here).
	c := newIPChoice(ips)
	p.mu.Lock()
	p.cache.set(host, c)
	p.mu.Unlock()
	return stringsToIPs(c.orderedList()), nil
}

// query performs the real lookup, from the cache when possible.
func (p *Provider) query(ctx context.Context, host string, family int) ([]string, error) {
	p.mu.Lock()
	var cached []string
	if c := p.cache.get(host); c != nil {
		cached = c.orderedList()
	}
	p.mu.Unlock()
	if len(cached) > 0 {
		return cached, nil
	}

	ips, err := p.queryTransport(ctx, host, family)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// queryTransport consults the preset list, then the transport.
func (p *Provider) queryTransport(ctx context.Context, host string, family int) ([]string, error) {
	// Preset addresses bypass the transport (desktop _lookupWithPreSetIpList).
	if list := p.preset.matchList(host); list != nil {
		ips := make([]string, 0, len(list))
		for _, ip := range list {
			ips = append(ips, ip.String())
		}
		return ips, nil
	}

	switch p.typ {
	case typPreSet:
		// PreSet without a preset entry knows nothing: fall back to the
		// trailing hostname item (desktop DNSOverPreSetIpList._lookup).
		return nil, nil
	}

	qtype := uint16(typeA)
	if family == 6 {
		qtype = typeAAAA
	}
	pkg := encodeQuery(host, qtype)

	var raw []byte
	var err error
	switch p.typ {
	case typUDP:
		raw, err = queryUDP(ctx, p.server, strconv.Itoa(p.port), p.family, pkg)
	case typTCP:
		raw, err = queryTCP(ctx, p.server, strconv.Itoa(p.port), p.family, pkg)
	case typDoT:
		raw, err = queryDoT(ctx, p.server, strconv.Itoa(p.port), p.sni, p.family, p.rootCAs, pkg)
	case typDoH:
		var resp *response
		resp, err = p.doh.queryWire(ctx, pkg)
		if err == nil && resp.truncated {
			// Desktop kernel falls back to the JSON API when the wire
			// format cannot serve this query over this pipe.
			resp, err = p.doh.queryJSON(ctx, host, typeName(qtype))
		}
		if err == nil {
			return answerStrings(resp, qtype), nil
		}
	}
	if err != nil {
		return nil, err
	}
	resp, err := parseResponse(raw)
	if err != nil {
		return nil, err
	}
	if resp.rcode != 0 {
		return nil, nil // NXDOMAIN & friends: no addresses
	}
	return answerStrings(resp, qtype), nil
}

// answerStrings extracts the addresses of qtype records, in wire order.
func answerStrings(resp *response, qtype uint16) []string {
	if resp == nil {
		return nil
	}
	return resp.answerIPs(qtype)
}

// count reports a dial result for the choice of host.
func (p *Provider) count(host, ip string, isError bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.cache.get(host); c != nil {
		c.count(ip, isError)
	}
}

// typeName names a query type for the DoH JSON API.
func typeName(qtype uint16) string {
	if qtype == typeAAAA {
		return "AAAA"
	}
	return "A"
}

// stringsToIPs converts address strings, skipping unparseable ones.
func stringsToIPs(list []string) []net.IP {
	out := make([]net.IP, 0, len(list))
	for _, s := range list {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

package dnsres

import (
	"context"
	"net"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func testResolver(t *testing.T, cfg *config.Server) *Resolver {
	t.Helper()
	return New(cfg, WithLogger(discardLogger()))
}

// ---- UDP provider -------------------------------------------------------

func UDPProviderConf(t *testing.T, cfg testConfig) (string, *config.DNSProvider) {
	addr := startFakeUDPDNS(t, cfg)
	host, port := splitHostPortS(addr)
	return addr, &config.DNSProvider{Server: host, Port: atoi(port)}
}

// TestUnmappedHostGoesStraightToSystem: a host without preset or mapping must
// not pay the latency of trying providers *before* the system DNS (the phone
// smoke showed a quad9 timeout tax before the fix). Only after a real system
// failure do the providers join as the fallback.
func TestUnmappedHostGoesStraightToSystem(t *testing.T) {
	_, udp := UDPProviderConf(t, testConfig{replyA: []string{"192.0.2.9"}})
	s := &config.Server{
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{"unit": udp},
		},
	}
	r := testResolver(t, s)
	ctx := context.Background()

	// The system resolver answers for this name below, so the provider must
	// never be consulted.
	if ips, err := r.Lookup(ctx, "localhost"); err != nil || len(ips) == 0 {
		t.Fatalf("system lookup of localhost: %v %v", ips, err)
	}
	if p := r.providers["unit"]; p.counted() != 0 {
		t.Fatalf("unmapped host touched its provider %d times", p.counted())
	}

	// A name the system resolver cannot answer falls back to the provider.
	ips, err := r.Lookup(ctx, "unmapped.invalid")
	if err != nil {
		t.Fatalf("fallback to provider: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.9" {
		t.Fatalf("fallback ips = %v", ips)
	}
	if p := r.providers["unit"]; p.counted() != 1 {
		t.Fatalf("provider fallback uses = %d, want 1", p.counted())
	}
}

// TestProviderUDP answers through the canned UDP server and honors the
// mapping family.
func TestProviderUDP(t *testing.T) {
	_, udp := UDPProviderConf(t, testConfig{replyA: []string{"192.168.7.7"}})
	server := &config.Server{
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{"unit": udp},
			Mapping:   map[string]config.DNSMapping{"*.example.net": {DNSName: "unit"}},
		},
	}
	r := testResolver(t, server)
	ips, err := r.Lookup(context.Background(), "a.example.net")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "192.168.7.7" {
		t.Fatalf("ips = %v", ips)
	}
	if r.HasDNS("a.example.net") != true || r.HasDNS("other.net") != false {
		t.Fatalf("HasDNS wrong")
	}
}

// TestPreSetBeatsMapping mirrors getDNSAndFamily: preset first.
func TestPreSetBeatsMapping(t *testing.T) {
	_, udp := UDPProviderConf(t, testConfig{replyA: []string{"127.2.2.2"}})
	s := &config.Server{
		PreSetIPList: map[string]config.IPList{"preset.example": {"10.1.2.3"}},
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{"unit": udp},
			Mapping:   map[string]config.DNSMapping{"preset.example": {DNSName: "unit"}},
		},
	}
	r := testResolver(t, s)
	ips, err := r.Lookup(context.Background(), "preset.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "10.1.2.3" {
		t.Fatalf("ips = %v", ips)
	}
}

// TestIPPreferenceRotatesOnFailure: a failed preset address is skipped next
// time and later comes back after a success reset (desktop DynamicChoice).
func TestIPPreferenceRotatesOnFailure(t *testing.T) {
	s := &config.Server{
		PreSetIPList: map[string]config.IPList{"preset.example": {"10.0.0.1", "10.0.0.2"}},
	}
	r := testResolver(t, s)
	ctx := context.Background()

	ips, err := r.Lookup(ctx, "preset.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 2 || ips[0].String() != "10.0.0.1" || ips[1].String() != "10.0.0.2" {
		t.Fatalf("initial order = %v", ips)
	}

	// Proxy reports the first address failing before the second worked.
	r.Note("preset.example", "10.0.0.1", true)
	r.Note("preset.example", "10.0.0.2", false)

	ips, err = r.Lookup(ctx, "preset.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if ips[0].String() != "10.0.0.2" {
		t.Fatalf("after failure the order should lead with 10.0.0.2, got %v", ips)
	}
	if containsIP(ips, "10.0.0.1") != 1 {
		t.Fatalf("10.0.0.1 should still come back as backup, got %v", ips)
	}
}

func containsIP(ips []net.IP, s string) int {
	n := 0
	for _, ip := range ips {
		if ip.String() == s {
			n++
		}
	}
	return n
}

// TestIPPreferenceExhaustsKeepsCandidates: with the whole preset list dead
// every candidate stays eligible for a retry on the next lookup
// (sink-to-tail policy), which keeps dial attempts alive across requests.
func TestIPPreferenceExhaustsKeepsCandidates(t *testing.T) {
	s := &config.Server{
		PreSetIPList: map[string]config.IPList{"preset.example": {"10.0.0.1", "10.0.0.2"}},
	}
	r := testResolver(t, s)
	ctx := context.Background()

	r.Note("preset.example", "10.0.0.1", true)
	r.Note("preset.example", "10.0.0.2", true)

	ips, err := r.Lookup(ctx, "preset.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("both candidates must stay dialable for a retry, got %v", ips)
	}
	// HasDNS stays true so the SNI path can rely on the preset entry.
	if !r.HasDNS("preset.example") {
		t.Fatal("HasDNS lost the preset entry after failures")
	}
}

// ---- TCP provider -------------------------------------------------------

func TestProviderTCP(t *testing.T) {
	addr := startFakeTCPDNS(t, testConfig{replyA: []string{"203.0.113.9"}})
	host, port := splitHostPortS(addr)
	s := &config.Server{
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{"tcp": {Server: host, Port: atoi(port), Type: "tcp"}},
			Mapping:   map[string]config.DNSMapping{"tcp.example": {DNSName: "tcp"}},
		},
	}
	r := testResolver(t, s)
	ips, err := r.Lookup(context.Background(), "tcp.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.9" {
		t.Fatalf("ips = %v", ips)
	}
}

// ---- DNS-over-TLS with SNI rewrite ---------------------------------------

// TestProviderDotSNIRewrite: `tls://...` with an sni option connects with the
// spoofed SNI (verification skipped, as on the desktop kernel).
func TestProviderDotSNIRewrite(t *testing.T) {
	addr, _, sniSeen := startFakeDotDNS(t, testConfig{replyA: []string{"198.51.100.1"}})
	host, port := splitHostPortS(addr)
	s := &config.Server{
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{
				"dot": {Server: "tls://" + host, Port: atoi(port), SNI: "baidu.com", ServerName: "ignored-alias"},
			},
			Mapping: map[string]config.DNSMapping{"dot.example": {DNSName: "dot"}},
		},
	}
	r := testResolver(t, s)
	ips, err := r.Lookup(context.Background(), "dot.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "198.51.100.1" {
		t.Fatalf("ips = %v", ips)
	}
	if got := sniSeen(); got != "baidu.com" {
		t.Fatalf("SNI seen by server = %q, want baidu.com", got)
	}
}

// TestProviderDotVerified: without sni the certificate is verified against
// the server config name and must match (roots from the test cert).
func TestProviderDotVerified(t *testing.T) {
	addr, roots, _ := startFakeDotDNS(t, testConfig{replyA: []string{"198.51.100.2"}})
	host, port := splitHostPortS(addr)
	// The server is an IP literal carrying an IP SAN in the test certificate,
	// so verification goes through without an SNI rewrite.
	s := &config.Server{}
	r := New(s, WithRootCAs(roots), WithLogger(discardLogger()))
	p, err := newProvider("dot", &config.DNSProvider{Server: host, Port: atoi(port)}, roots, r.log)
	if err != nil || p == nil {
		t.Fatalf("newProvider: %v %v", p, err)
	}
	p.preset = r.presetIdx
	p.typ = typDoT
	ips, qerr := p.lookup(context.Background(), "map.example", 0)
	if qerr != nil {
		t.Fatalf("verified DoT lookup: %v", qerr)
	}
	if len(ips) != 1 || ips[0].String() != "198.51.100.2" {
		t.Fatalf("ips = %v", ips)
	}
}

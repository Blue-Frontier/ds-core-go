package proxy

import (
	"net"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func TestToNAT64(t *testing.T) {
	prefix := net.ParseIP("64:ff9b::")
	got := toNAT64(prefix, net.ParseIP("192.0.2.33"))
	if got == nil || got.String() != "64:ff9b::c000:221" {
		t.Fatalf("toNAT64 = %v", got)
	}
	if toNAT64(nil, net.ParseIP("192.0.2.33")) != nil {
		t.Fatal("nil prefix must not synthesise")
	}
}

// A host that is not covered keeps its native addresses.
func TestApplyNAT64OnlyRewritesIPv4(t *testing.T) {
	prefix := net.ParseIP("64:ff9b::")
	ips := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("2001:db8::1"),
	}
	out := applyNAT64(prefix, ips)
	if len(out) != 2 {
		t.Fatalf("len = %d", len(out))
	}
	if out[0].To4() != nil {
		t.Fatalf("first answer should be synthesised, got %v", out[0])
	}
	if out[1].String() != "2001:db8::1" {
		t.Fatalf("native IPv6 answer was altered: %v", out[1])
	}
}

// An empty prefix disables the feature, as on the desktop.
func TestNAT64RequiresPrefix(t *testing.T) {
	cfg := config.NAT64{Enabled: true, Domains: []string{"*chatgpt.com"}}
	if _, ok := nat64Prefix(cfg, "api.chatgpt.com"); ok {
		t.Fatal("empty prefix must not enable NAT64")
	}
	cfg.Prefix = "64:ff9b::"
	if _, ok := nat64Prefix(cfg, "api.chatgpt.com"); !ok {
		t.Fatal("covered host should be enabled")
	}
	if _, ok := nat64Prefix(cfg, "example.org"); ok {
		t.Fatal("uncovered host must not be enabled")
	}
}

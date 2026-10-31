package proxy

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// Cloudflare publishes 173.245.48.0/20; the preferred endpoint stands in for
// whatever the user configures.
const (
	cfRange     = "173.245.48.0/20"
	cfIP1       = "173.245.48.10"
	cfIP2       = "173.245.49.20"
	preferredIP = "104.16.0.1"
	plainIP     = "93.184.216.34"
)

func testCFRoute(cfg config.CloudflareRoute) *cfRoute {
	c := newCFRoute(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if c == nil {
		return nil
	}
	// Pretend the refresher already ran.
	c.ranges = []*net.IPNet{mustCIDR(cfRange)}
	c.preferredV4 = net.ParseIP(preferredIP)
	return c
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestCFRouteDisabledByDefault(t *testing.T) {
	if newCFRoute(config.CloudflareRoute{}, slog.Default()) != nil {
		t.Fatal("cloudflareRoute must stay off unless enabled")
	}
	if newCFRoute(config.CloudflareRoute{Enabled: true}, slog.Default()) != nil {
		t.Fatal("an empty preferredEndpoint cannot work")
	}
}

// A Cloudflare address is rewritten to the preferred endpoint.
func TestCFRouteRewritesCloudflareIP(t *testing.T) {
	c := testCFRoute(config.CloudflareRoute{Enabled: true, PreferredEndpoint: preferredIP})
	got, ok := c.rewrite(net.ParseIP(cfIP1), "shop.example.com")
	if !ok || got.String() != preferredIP {
		t.Fatalf("rewrite = %v, %v", got, ok)
	}

	other := net.ParseIP(plainIP)
	if got, ok := c.rewrite(other, "shop.example.com"); ok || !got.Equal(other) {
		t.Fatalf("non-CF address was rewritten: %v %v", got, ok)
	}
}

// The default mode is a blacklist: listed domains are not redirected.
func TestCFRouteBlacklistSkipsListedDomains(t *testing.T) {
	c := testCFRoute(config.CloudflareRoute{
		Enabled:           true,
		PreferredEndpoint: preferredIP,
		Domains:           config.StringList{"*.internal.example"},
	})
	cfIP := net.ParseIP(cfIP1)

	if _, ok := c.rewrite(cfIP, "api.internal.example"); ok {
		t.Fatal("blacklisted domain must not be rewritten")
	}
	if _, ok := c.rewrite(cfIP, "shop.example.com"); !ok {
		t.Fatal("unlisted domain should be rewritten")
	}
}

// Whitelist mode flips the rule: only listed domains are rewritten.
func TestCFRouteWhitelistOnlyListed(t *testing.T) {
	c := testCFRoute(config.CloudflareRoute{
		Enabled:           true,
		PreferredEndpoint: preferredIP,
		Mode:              "whitelist",
		Domains:           config.StringList{"shop.example.com"},
	})
	cfIP := net.ParseIP(cfIP1)

	if _, ok := c.rewrite(cfIP, "shop.example.com"); !ok {
		t.Fatal("whitelisted domain should be rewritten")
	}
	if _, ok := c.rewrite(cfIP, "other.example.com"); ok {
		t.Fatal("unlisted domain must not be rewritten")
	}
}

// apply keeps order and drops duplicates introduced by the rewrite.
func TestCFRouteApplyDedupes(t *testing.T) {
	c := testCFRoute(config.CloudflareRoute{Enabled: true, PreferredEndpoint: preferredIP})
	ips := []net.IP{
		net.ParseIP(cfIP1),
		net.ParseIP(cfIP2),
		net.ParseIP(plainIP),
	}
	out := c.apply(ips, "shop.example.com")
	if len(out) != 2 {
		t.Fatalf("got %d addresses, want 2: %v", len(out), out)
	}
	if out[0].String() != preferredIP || out[1].String() != plainIP {
		t.Fatalf("unexpected order: %v", out)
	}
}

// A nil route (feature off) passes addresses through untouched.
func TestCFRouteNilPassthrough(t *testing.T) {
	var c *cfRoute
	ips := []net.IP{net.ParseIP(cfIP1)}
	if got := c.apply(ips, "shop.example.com"); len(got) != 1 || !got[0].Equal(ips[0]) {
		t.Fatalf("nil route changed addresses: %v", got)
	}
}

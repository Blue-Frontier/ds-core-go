package dnsres

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// Providers are stored in a map, so their iteration order is not the file's
// order. The fallback must still reach for an encrypted transport before a
// plaintext one: a poisoned UDP answer is exactly what the built-in providers
// exist to avoid.
func TestProvidersBySecurityPutsEncryptedFirst(t *testing.T) {
	r := New(&config.Server{DNS: config.DNS{
		Providers: map[string]*config.DNSProvider{
			// Alphabetically these come first, but they are plaintext.
			"aaa-local":  {Server: "127.0.0.1"},
			"bbb-aliyun": {Server: "223.5.5.5"},
			"ccc-dot":    {Server: "tls://1.1.1.1"},
			"ddd-doh":    {Server: "https://cloudflare-dns.com/dns-query"},
		},
	}}, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	ordered := r.providersBySecurity()
	if len(ordered) != 4 {
		t.Fatalf("got %d providers, want 4", len(ordered))
	}

	for i, p := range ordered {
		encrypted := p.typ == typDoH || p.typ == typDoT
		if i < 2 && !encrypted {
			t.Fatalf("provider %d (%s) is plaintext, encrypted must come first", i, p.Name)
		}
		if i >= 2 && encrypted {
			t.Fatalf("provider %d (%s) is encrypted, it belongs before the plaintext ones", i, p.Name)
		}
	}
}

// A blackholed provider must not delay the answer: the race takes whichever
// provider replies first instead of walking the list.
func TestRaceProvidersDoesNotWaitForSlowOnes(t *testing.T) {
	r := New(&config.Server{
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{
				// 192.0.2.1 is TEST-NET: UDP queries go nowhere and time out.
				"aaa-dead": {Server: "192.0.2.1", Port: 53},
			},
		},
		PreSetIPList: map[string]config.IPList{
			"race.example": {"198.51.100.9"},
		},
	}, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	slow := r.providers["aaa-dead"]
	if slow == nil {
		t.Fatal("dead provider missing")
	}
	// The preset provider answers instantly from its table.
	fast := r.preset

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	ips := r.raceProviders(ctx, []*Provider{slow, fast}, "race.example")
	elapsed := time.Since(start)

	if len(ips) != 1 || ips[0].String() != "198.51.100.9" {
		t.Fatalf("race returned %v", ips)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("race waited %v, the instant answer should have won", elapsed)
	}
}

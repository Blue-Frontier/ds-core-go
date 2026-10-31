package proxy_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func cacheRule(days int) config.Rule {
	return config.Rule{CacheConfig: config.CacheConfig{CacheDays: days}}
}

// A conditional GET inside the window is answered with 304 and never reaches
// the origin.
func TestCacheAnswers304WithinWindow(t *testing.T) {
	var hits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "fresh")
	}))
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": cacheRule(1)}}, rootsFor(upstream))

	req, _ := http.NewRequest(http.MethodGet, "https://"+upstream.Listener.Addr().String()+"/asset.js", nil)
	req.Header.Set("If-Modified-Since", time.Now().UTC().Format(http.TimeFormat))

	resp, err := clientFor(addr, ca).Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", resp.StatusCode)
	}
	if got := resp.Header.Get("DS-Interceptor"); got != "cache: 86400" {
		t.Fatalf("marker = %q", got)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("origin was hit %d times", n)
	}
}

// Outside the window the request goes upstream as usual.
func TestCacheExpiredGoesUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fresh")
	}))
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": cacheRule(1)}}, rootsFor(upstream))

	req, _ := http.NewRequest(http.MethodGet, "https://"+upstream.Listener.Addr().String()+"/asset.js", nil)
	req.Header.Set("If-Modified-Since", time.Now().Add(-72*time.Hour).UTC().Format(http.TimeFormat))

	resp, err := clientFor(addr, ca).Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from origin", resp.StatusCode)
	}
}

// The response's cache headers are rewritten to the configured lifetime.
func TestCacheRewritesResponseHeaders(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=10")
		fmt.Fprint(w, "body")
	}))
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": cacheRule(1)}}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/a")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=86401, immutable" {
		t.Fatalf("cache-control = %q", got)
	}
	if got := resp.Header.Get("DS-Cache-Response-Interceptor"); got != "86400" {
		t.Fatalf("marker = %q", got)
	}
	if resp.Header.Get("Last-Modified") == "" || resp.Header.Get("Expires") == "" {
		t.Fatal("last-modified/expires not set")
	}
}

// A longer origin lifetime is kept when immutable is disabled, with a skip note.
func TestCacheSkipsWhenOriginLifetimeLonger(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=999999")
		fmt.Fprint(w, "body")
	}))
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	no := false
	rule := cacheRule(1)
	rule.Immutable = &no

	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": rule}}, rootsFor(upstream))
	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/a")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Cache-Control"); got != "max-age=999999" {
		t.Fatalf("cache-control = %q, want the origin value untouched", got)
	}
	if got := resp.Header.Get("DS-Cache-Response-Interceptor"); !strings.HasPrefix(got, "skip:") {
		t.Fatalf("marker = %q", got)
	}
}

// A stubbed success inherits the rule's cache lifetime.
func TestSuccessCarriesCacheControl(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {`^/tick$`: {
			Success:     &config.Synthetic{Enabled: true},
			CacheConfig: config.CacheConfig{CacheDays: 1},
		}},
	}, nil)

	resp, err := clientFor(addr, ca).Get("https://example.com/tick")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=86401, immutable" {
		t.Fatalf("cache-control = %q", got)
	}
}

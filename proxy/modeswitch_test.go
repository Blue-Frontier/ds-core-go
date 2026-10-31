package proxy_test

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// A rule that would answer locally must be ignored when the master switch is
// off, matching the desktop's "safe" mode (server.intercept.enabled = false).
func TestInterceptMasterSwitch(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	intercepts := map[string]map[string]config.Rule{
		host: {".*": {Abort: &config.Synthetic{Enabled: true}}},
	}
	off := false

	target := "https://" + upstream.Listener.Addr().String() + "/blocked"

	// Switch off: the request reaches the origin.
	addr, ca := startProxyFull(t, intercepts, roots, &config.Server{
		Intercept: config.InterceptSwitch{Enabled: &off},
	})
	resp, err := clientFor(addr, ca).Get(target)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "origin" {
		t.Fatalf("switch off: status=%d body=%q, want the origin response", resp.StatusCode, body)
	}

	// Switch on (default): the abort rule answers locally.
	addr2, ca2 := startProxy(t, intercepts, roots)
	resp2, err := clientFor(addr2, ca2).Get(target)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("switch on: status=%d, want 403", resp2.StatusCode)
	}
}

// The response timeout follows the desktop: per-host mapping, then the
// configured default, then 20s.
func TestRequestTimeoutMapping(t *testing.T) {
	_, _, srv := startProxyServer(t, nil, nil, &config.Server{
		Setting: config.Setting{
			DefaultTimeout: 15000,
			TimeoutMapping: map[string]config.HostTimeout{
				"github.com":    {Timeout: 30000},
				"*.example.com": {Timeout: 25000},
			},
		},
	})

	cases := []struct {
		host string
		want time.Duration
	}{
		{"github.com", 30 * time.Second},
		// Exact keys do not cover subdomains; the desktop's own matchUtilTest
		// vectors confirm this ("aaa.com" does not match "aaaa.com").
		{"api.github.com", 15 * time.Second},
		{"www.example.com", 25 * time.Second},
		{"unrelated.test", 15 * time.Second},
	}
	for _, c := range cases {
		if got := srv.RequestTimeout(c.host); got != c.want {
			t.Errorf("RequestTimeout(%s) = %v, want %v", c.host, got, c.want)
		}
	}
}

// Without configuration the desktop's 20 second budget applies.
func TestRequestTimeoutDefault(t *testing.T) {
	_, _, srv := startProxyServer(t, nil, nil, &config.Server{})
	if got := srv.RequestTimeout("anything.example"); got != 20*time.Second {
		t.Fatalf("default timeout = %v, want 20s", got)
	}
}

var _ = url.Parse

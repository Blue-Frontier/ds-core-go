package proxy_test

import (
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

func startProxyWithConfig(t *testing.T, cfg *config.Config, roots *x509.CertPool) (string, *certcache.Authority) {
	t.Helper()
	authority, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache.New: %v", err)
	}
	srv, err := proxy.New(cfg, authority, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	srv.UpstreamRootCAs = roots

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: srv}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	return ln.Addr().String(), authority
}

// A matched host must be fetched through the relay: rewritten path, password
// header, and the DS-Overwall marker on the way back.
func TestOverwallRoutesThroughRelay(t *testing.T) {
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s pass=%s host=%s", r.URL.RequestURI(), r.Header.Get("dspassword"), r.Host)
	}))
	defer relay.Close()

	_, portStr, _ := net.SplitHostPort(relay.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	cfg := &config.Config{
		Server: config.Server{
			Intercepts: map[string]map[string]config.Rule{"example.com": {".*": {}}},
		},
		Plugin: config.Plugin{Overwall: config.Overwall{
			Enabled: true,
			Targets: map[string]any{"example.com": true},
			ServerDefault: map[string]config.OverwallServer{
				"127.0.0.1": {ID: 0, Port: port, Path: "_go_over_wall_", Password: "pw"},
			},
		}},
	}

	addr, ca := startProxyWithConfig(t, cfg, rootsFor(relay))
	resp, err := clientFor(addr, ca).Get("https://example.com/x/y?q=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "path=/_go_over_wall_/example.com/x/y?q=1 pass=pw host=127.0.0.1" {
		t.Fatalf("relay saw %q", body)
	}
	if got := resp.Header.Get("DS-Overwall"); got != "config:0" {
		t.Fatalf("marker = %q", got)
	}
}

// target: false opts the host out, so the request never reaches the relay.
func TestOverwallFalseSkipsHost(t *testing.T) {
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("relay must not be reached")
	}))
	defer relay.Close()

	_, portStr, _ := net.SplitHostPort(relay.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	cfg := &config.Config{
		Server: config.Server{
			Intercepts: map[string]map[string]config.Rule{"example.com": {".*": {}}},
		},
		Plugin: config.Plugin{Overwall: config.Overwall{
			Enabled: true,
			Targets: map[string]any{"relay-off.invalid": false},
			ServerDefault: map[string]config.OverwallServer{
				"127.0.0.1": {ID: 0, Port: port, Path: "p", Password: "pw"},
			},
		}},
	}

	addr, ca := startProxyWithConfig(t, cfg, rootsFor(relay))
	resp, err := clientFor(addr, ca).Get("https://relay-off.invalid/x")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 (the host does not resolve)", resp.StatusCode)
		}
	}
	if got := resp.Header.Get("DS-Overwall"); got != "" && resp != nil {
		t.Fatalf("marker = %q, want none", got)
	}
}

// The plugin is off unless the configuration enables it.
func TestOverwallDisabledByDefault(t *testing.T) {
	cfg := &config.Config{
		Server: config.Server{
			Intercepts: map[string]map[string]config.Rule{"example.com": {".*": {}}},
		},
		Plugin: config.Plugin{Overwall: config.Overwall{
			Targets: map[string]any{"example.com": true},
			ServerDefault: map[string]config.OverwallServer{
				"127.0.0.1": {ID: 0, Port: 1, Path: "p", Password: "pw"},
			},
		}},
	}
	addr, ca := startProxyWithConfig(t, cfg, nil)
	resp, err := clientFor(addr, ca).Get("https://relay-off.invalid/x")
	if err == nil {
		defer resp.Body.Close()
		if got := resp.Header.Get("DS-Overwall"); got != "" {
			t.Fatalf("marker = %q, want none", got)
		}
	}
}

package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

func startProxy(t *testing.T, intercepts map[string]map[string]config.Rule, upstreamRoots *x509.CertPool) (addr string, ca *certcache.Authority) {
	t.Helper()

	authority, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache.New: %v", err)
	}
	cfg := &config.Config{}
	cfg.Server.Intercepts = intercepts

	srv, err := proxy.New(cfg, authority, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	srv.UpstreamRootCAs = upstreamRoots

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: srv}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { _ = httpSrv.Close() })

	return ln.Addr().String(), authority
}

func clientFor(addr string, ca *certcache.Authority) *http.Client {
	proxyURL, _ := url.Parse("http://" + addr)
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: ca.RootPool()},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestMITMPassesThroughAndKeepsPath(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok:%s", r.URL.Path)
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {}}, roots)
	client := clientFor(addr, ca)

	resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/hello/world?q=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if string(body) != "ok:/hello/world" {
		t.Fatalf("body = %q", body)
	}
}

func TestMITMRedirectRule(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // must not be reached
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	intercepts := map[string]map[string]config.Rule{
		host: {
			`^(/[^/]+){2}/releases/download/.*$`: {Redirect: "ghp.ci/https://github.com"},
		},
	}
	addr, ca := startProxy(t, intercepts, roots)
	client := clientFor(addr, ca)

	resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/owner/repo/releases/download/v1/tool.zip")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	want := "https://ghp.ci/https://github.com/owner/repo/releases/download/v1/tool.zip"
	if got := resp.Header.Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestPlainHTTPProxying(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain:%s", r.URL.Path)
	}))
	defer plain.Close()

	addr, ca := startProxy(t, nil, nil)
	client := clientFor(addr, ca)

	resp, err := client.Get(plain.URL + "/x/y")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "plain:/x/y" {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

func TestClientWithoutTrustedCAFails(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	addr, _ := startProxy(t, map[string]map[string]config.Rule{host: {}}, roots)

	// A client that does not trust the kernel CA must reject the MITM cert.
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	if _, err := client.Get("https://" + upstream.Listener.Addr().String() + "/"); err == nil {
		t.Fatal("expected certificate verification error")
	}
}

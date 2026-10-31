package proxy_test

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func rootsFor(s *httptest.Server) *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return roots
}

func TestResponseReplaceRewritesHeaders(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=999")
		w.Header().Set("X-Keep", "yes")
		_, _ = fmt.Fprint(w, "body")
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {".*": {ResponseReplace: &config.ResponseReplace{Headers: map[string]any{
			"Cache-Control": "no-store",
			"x-keep":        "[remove]",
			"X-Added":       "1",
			"X-Int":         float64(7),
		}}}},
	}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q", got)
	}
	if got := resp.Header.Get("X-Keep"); got != "" {
		t.Fatalf("x-keep should be removed, got %q", got)
	}
	if got := resp.Header.Get("X-Added"); got != "1" {
		t.Fatalf("x-added = %q", got)
	}
	if got := resp.Header.Get("X-Int"); got != "7" {
		t.Fatalf("x-int = %q", got)
	}
	if got := resp.Header.Get("DS-ResponseReplace-Interceptor"); got != "headers" {
		t.Fatalf("marker = %q", got)
	}
}

// doDownload turns the response into an attachment and drops the cache headers.
func TestResponseReplaceDownload(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")
		_, _ = fmt.Fprint(w, "binary")
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {`^/pkg/tool\.zip$`: {ResponseReplace: &config.ResponseReplace{DoDownload: true}}},
	}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/pkg/tool.zip")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="tool.zip"` {
		t.Fatalf("content-disposition = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content-type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Fatalf("cache-control should be removed, got %q", got)
	}
	if got := resp.Header.Get("Expires"); got != "" {
		t.Fatalf("expires should be removed, got %q", got)
	}
	if got := resp.Header.Get("DS-ResponseReplace-Interceptor"); got != "download:tool.zip,headers" {
		t.Fatalf("marker = %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) == "" {
		t.Fatal("body was dropped")
	}
}

// Non-200 responses are left alone, as on the desktop.
func TestResponseReplaceIgnoresNon200(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Keep", "yes")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {".*": {ResponseReplace: &config.ResponseReplace{Headers: map[string]any{
			"x-keep": "[remove]",
		}}}},
	}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/missing")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Keep"); got != "yes" {
		t.Fatalf("x-keep = %q, want untouched", got)
	}
}

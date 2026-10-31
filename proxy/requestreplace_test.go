package proxy_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// requestReplace rewrites the headers the origin sees and reports it.
func TestRequestReplaceHeaders(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "token=%s ua=%q", r.Header.Get("X-Token"), r.Header.Get("User-Agent"))
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {".*": {RequestReplace: &config.RequestReplace{Headers: map[string]any{
			"X-Token":    "abc",
			"user-agent": "[remove]",
		}}}},
	}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/h")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `token=abc ua=""` {
		t.Fatalf("upstream saw %q", body)
	}
	if got := resp.Header.Get("DS-RequestReplace-Interceptor"); got != "headers" {
		t.Fatalf("marker = %q", got)
	}
}

// "?DS_DOWNLOAD" is stripped before the origin, and the paired responseReplace
// turns the answer into an attachment. Matching must see the query string, or
// the anchored rule would never fire.
func TestRequestReplaceDownloadMarker(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		fmt.Fprintf(w, "path=%s", r.URL.RequestURI())
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {`^.*\?DS_DOWNLOAD$`: {
			RequestReplace:  &config.RequestReplace{DoDownload: true},
			ResponseReplace: &config.ResponseReplace{},
		}},
	}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/pkg/tool.zip?DS_DOWNLOAD")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "path=/pkg/tool.zip" {
		t.Fatalf("origin saw %q, want the marker stripped", body)
	}
	if got := resp.Header.Get("DS-RequestReplace-Interceptor"); got != "path:remove-DS_DOWNLOAD" {
		t.Fatalf("marker = %q", got)
	}
	if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="tool.zip"` {
		t.Fatalf("content-disposition = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Fatalf("cache-control should be removed, got %q", got)
	}
}

// Without the marker the rule must not fire: the anchored pattern includes the
// query string.
func TestRequestReplaceDownloadNeedsMarker(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain")
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {`^.*\?DS_DOWNLOAD$`: {
			RequestReplace:  &config.RequestReplace{DoDownload: true},
			ResponseReplace: &config.ResponseReplace{},
		}},
	}, rootsFor(upstream))

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/pkg/tool.zip")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("DS-RequestReplace-Interceptor"); got != "" {
		t.Fatalf("marker = %q, want none", got)
	}
	if got := resp.Header.Get("Content-Disposition"); got != "" {
		t.Fatalf("content-disposition = %q, want none", got)
	}
}

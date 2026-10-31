package proxy_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// abort must answer without contacting the origin (no DNS, no dial).
func TestAbortRuleAnswersLocally(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {`^/blocked$`: {Abort: &config.Synthetic{Enabled: true}}},
	}, nil)

	resp, err := clientFor(addr, ca).Get("https://example.com/blocked")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("DS-Interceptor"); got != "abort" {
		t.Fatalf("DS-Interceptor = %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "abort") {
		t.Fatalf("body = %q", body)
	}
}

// The object form carries status and body overrides.
func TestSuccessRuleWithCustomStatus(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {
			`^/beacon$`: {
				Success: &config.Synthetic{Enabled: true, Status: 204},
			},
		},
	}, nil)

	resp, err := clientFor(addr, ca).Get("https://example.com/beacon")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("204 must have no body, got %q", body)
	}
}

// A rule written as "true" keeps the interceptor's default status, which is
// what the desktop does (it never reads a sibling "status" in that branch).
func TestSuccessTrueKeepsDefaultStatus(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {`^/tick$`: {Success: &config.Synthetic{Enabled: true}}},
	}, nil)

	resp, err := clientFor(addr, ca).Get("https://example.com/tick")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// The CORS preflight is answered locally, echoing the caller's origin.
func TestOptionsRuleAnswersPreflight(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {`^/api$`: {Options: true}},
	}, nil)

	req, _ := http.NewRequest(http.MethodOptions, "https://example.com/api", nil)
	req.Header.Set("Origin", "https://site.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := clientFor(addr, ca).Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://site.example" {
		t.Fatalf("allow-origin = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "POST" {
		t.Fatalf("allow-methods = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "content-type" {
		t.Fatalf("allow-headers = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("allow-credentials = %q", got)
	}
}

// A non-preflight request must not be swallowed by the options interceptor.
func TestOptionsRuleIgnoresPlainGet(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {`^/api$`: {Options: true}},
	}, nil)

	resp, err := clientFor(addr, ca).Get("https://example.com/api")
	if err != nil {
		// The origin does not exist; a dial failure is the expected outcome.
		return
	}
	defer resp.Body.Close()
	if resp.Header.Get("DS-Interceptor") == "options" {
		t.Fatal("GET must not be answered by the options interceptor")
	}
}

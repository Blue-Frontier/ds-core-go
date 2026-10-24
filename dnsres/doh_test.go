package dnsres

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

type fakeDohS struct {
	url      string
	roots    *x509.CertPool
	sniSeen  string
	requests int
}

// newFakeDohServer spins a DoH over TLS test server with canned answers.
func newFakeDohServer(t *testing.T, cfg testConfig, wantJSON bool) *fakeDohS {
	t.Helper()
	s := &fakeDohS{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			s.sniSeen = r.TLS.ServerName
		}
		s.requests++
		if wantJSON || strings.HasPrefix(r.URL.RawQuery, "name=") {
			q := r.URL.Query()
			ips := cfg.replyA
			if q.Get("type") == "AAAA" {
				ips = cfg.replyAAA
			}
			w.Header().Set("content-type", "application/dns-json")
			_ = json.NewEncoder(w).Encode(dohJSONResult{Answers: jsonAnswers(q.Get("name"), ips)})
			return
		}
		pkg, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(dnsWireResponse(pkg, cfg))
	}))
	t.Cleanup(ts.Close)
	s.url = ts.URL
	s.roots = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return s
}

func jsonAnswers(name string, ips []string) []dohJSONAnswer {
	out := make([]dohJSONAnswer, 0, len(ips))
	for _, ip := range ips {
		t := 1
		if strings.Contains(ip, ":") {
			t = 28
		}
		out = append(out, dohJSONAnswer{Name: name, Type: t, TTL: 60, Data: ip})
	}
	return out
}

// TestDoHWireFormat: POST application/dns-message round trip.
func TestDoHWireFormat(t *testing.T) {
	s := newFakeDohServer(t, testConfig{replyA: []string{"203.0.113.42"}}, false)
	r := New(&config.Server{}, WithRootCAs(&x509.CertPool{}), WithLogger(discardLogger()))
	p, err := newProvider("doh", &config.DNSProvider{Server: s.url}, s.roots, r.log)
	if err != nil || p == nil {
		t.Fatalf("newProvider: %v %v", p, err)
	}
	p.preset = r.presetIdx
	ips, qerr := p.lookup(context.Background(), "map.example", 0)
	if qerr != nil {
		t.Fatalf("DoH lookup: %v", qerr)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.42" {
		t.Fatalf("ips = %v", ips)
	}
	if got := s.sniSeen; got != "" {
		t.Fatalf("IP-literal DoH servers must not carry an SNI extension (RFC 6066), got %q", got)
	}
}

// TestDoHSNIRewrite: with the provider sni option, the DoH connection's TLS
// ClientHello carries the spoofed name (cert verification skipped, matching
// the desktop kernel's rejectUnauthorized:false).
func TestDoHSNIRewrite(t *testing.T) {
	s := newFakeDohServer(t, testConfig{replyA: []string{"203.0.113.43"}}, false)
	p, err := newProvider("doh", &config.DNSProvider{Server: s.url, SNI: "baidu.com"}, nil, discardLogger())
	if err != nil || p == nil {
		t.Fatalf("newProvider: %v %v", p, err)
	}
	ips, qerr := p.lookup(context.Background(), "map.example", 0)
	if qerr != nil {
		t.Fatalf("DoH lookup: %v", qerr)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.43" {
		t.Fatalf("ips = %v", ips)
	}
	if got := s.sniSeen; got != "baidu.com" {
		t.Fatalf("SNI seen by server = %q, want baidu.com", got)
	}
}

// TestDoHJSON: the RFC 8427 style JSON API parses into A/AAAA answers.
func TestDoHJSON(t *testing.T) {
	s := newFakeDohServer(t, testConfig{replyA: []string{"203.0.113.44"}}, true)
	p, err := newProvider("doh-json", &config.DNSProvider{Server: s.url}, s.roots, discardLogger())
	if err != nil || p == nil {
		t.Fatalf("newProvider: %v %v", p, err)
	}
	resp, qerr := p.doh.queryJSON(context.Background(), "map.example", "A")
	if qerr != nil {
		t.Fatalf("queryJSON: %v", qerr)
	}
	ips := answerStrings(resp, typeA)
	if len(ips) != 1 || ips[0] != "203.0.113.44" {
		t.Fatalf("json ips = %v", ips)
	}
}

// TestParseDohJSON rejects bad status codes and decodes answers.
func TestParseDohJSON(t *testing.T) {
	if _, err := parseDohJSON([]byte(`{"Status": 2}`)); err == nil {
		t.Fatal("error status accepted")
	}
	resp, err := parseDohJSON([]byte(`{"Status":0,"TC":false,"Answer":[{"name":"a.example","type":1,"TTL":60,"data":"1.2.3.4"}]}`))
	if err != nil {
		t.Fatalf("parseDohJSON: %v", err)
	}
	ips := answerStrings(resp, typeA)
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("ips = %v", ips)
	}
}

// TestNormalizeDoHServer covers the desktop kernel's shaping rules.
func TestNormalizeDoHServer(t *testing.T) {
	cases := []struct{ in, want string }{
		{"9.9.9.9", "https://9.9.9.9/dns-query"},
		{"https://cloudflare-dns.com/dns-query", "https://cloudflare-dns.com/dns-query"},
	}
	for _, c := range cases {
		got, err := normalizeDoHServer(c.in)
		if err != nil {
			t.Fatalf("normalize %q: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("normalize %q = %q, want %q", c.in, got, c.want)
		}
	}
}

package proxy_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func mustRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

// h2Client dials the proxy, sends CONNECT, and negotiates HTTP/2 on the tunnel.
func h2Client(t *testing.T, proxyAddr string, roots *x509.CertPool) *http2.Transport {
	t.Helper()
	return &http2.Transport{
		DialTLSContext: nil,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				return nil, err
			}
			if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
				raw.Close()
				return nil, err
			}
			br := bufio.NewReader(raw)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err != nil {
				raw.Close()
				return nil, err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				raw.Close()
				return nil, fmt.Errorf("CONNECT: %s", resp.Status)
			}
			host, _, _ := net.SplitHostPort(addr)
			tc := tls.Client(raw, &tls.Config{
				ServerName: host,
				RootCAs:    roots,
				NextProtos: []string{"h2"},
			})
			if err := tc.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
}

// The client side of the proxy must speak HTTP/2 when the browser asks for it.
func TestH2UpstreamPassThrough(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok:%s", r.URL.Path)
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": {}}}, roots)

	resp, err := h2Client(t, addr, ca.RootPool()).RoundTrip(
		mustRequest(t, "https://"+upstream.Listener.Addr().String()+"/hello"),
	)
	if err != nil {
		t.Fatalf("h2 request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s, want HTTP/2", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok:/hello" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

// Local responders answer over h2 as well.
func TestH2AbortRule(t *testing.T) {
	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		"example.com": {`^/blocked$`: {Abort: &config.Synthetic{Enabled: true}}},
	}, nil)

	resp, err := h2Client(t, addr, ca.RootPool()).RoundTrip(mustRequest(t, "https://example.com/blocked"))
	if err != nil {
		t.Fatalf("h2 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s", resp.Proto)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("DS-Interceptor"); got != "abort" {
		t.Fatalf("marker = %q", got)
	}
}

// The kernel's own stats endpoint answers over HTTP/2 too, without dialing.
func TestH2StatsEndpoint(t *testing.T) {
	addr, ca := startProxy(t, nil, nil)
	resp, err := h2Client(t, addr, ca.RootPool()).RoundTrip(mustRequest(t, "https://stats.invalid/__ds_stats__"))
	if err != nil {
		t.Fatalf("h2 stats: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s", resp.Proto)
	}
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"requests"`) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

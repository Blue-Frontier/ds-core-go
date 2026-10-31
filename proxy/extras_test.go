package proxy_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
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

// startProxyServer is startProxyFull but also returns the server, so tests can
// seed the script store or inspect counters.
func startProxyServer(t *testing.T, intercepts map[string]map[string]config.Rule, upstreamRoots *x509.CertPool, serverCfg *config.Server) (string, *certcache.Authority, *proxy.Server) {
	t.Helper()

	serverCfg.Intercepts = intercepts
	cfg := &config.Config{Server: *serverCfg}

	authority, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache.New: %v", err)
	}
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
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	return ln.Addr().String(), authority, srv
}

func hostOf(t *testing.T, addr string) string {
	t.Helper()
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return h
}

// An HTML response matching a script rule gets the tag injected before </head>
// and its CSP widened to allow 'self'.
func TestHTMLScriptInjection(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src cdn.example.com")
		_, _ = io.WriteString(w, "<html><head><title>t</title></head><body>ok</body></html>")
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host := hostOf(t, upstream.Listener.Addr().String())

	addr, ca, srv := startProxyServer(t, map[string]map[string]config.Rule{
		host: {".*": {Script: config.StringList{"k1"}}},
	}, roots, &config.Server{})
	srv.Scripts.Put("k1", []byte("console.log('k1')"))

	client := clientFor(addr, ca)
	resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "/____ds_script____/k1") {
		t.Fatalf("script tag missing from body: %s", body)
	}
	if !strings.Contains(string(body), "</head>") {
		t.Fatalf("head lost in rewrite: %s", body)
	}
	if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'self'") {
		t.Fatalf("CSP not widened correctly: %q", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); strings.Contains(got, "script-src'self'") {
		t.Fatalf("CSP directive lost its separator: %q", got)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("Content-Length %d != body %d", resp.ContentLength, len(body))
	}
}

// The injected path is answered by the kernel without touching the origin.
func TestInjectedScriptServedLocally(t *testing.T) {
	var hits int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><head></head><body>x</body></html>")
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host := hostOf(t, upstream.Listener.Addr().String())

	addr, ca, srv := startProxyServer(t, map[string]map[string]config.Rule{
		host: {".*": {Script: config.StringList{"k2"}}},
	}, roots, &config.Server{})
	srv.Scripts.Put("k2", []byte("var k2=1;"))

	client := clientFor(addr, ca)
	resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/____ds_script____/k2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "var k2=1;" {
		t.Fatalf("body = %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if hits != 0 {
		t.Fatalf("origin was contacted %d times for a kernel-served script", hits)
	}
}

// A white-listed host must be tunneled: the client sees the origin's own
// certificate, not the kernel CA's, so a client trusting only the origin still
// verifies successfully.
func TestWhiteListHostIsTunneledNotMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tunneled")
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host := hostOf(t, upstream.Listener.Addr().String())

	addr, _, _ := startProxyServer(t, nil, roots, &config.Server{
		WhiteList: map[string]bool{host: true},
	})

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots}, // origin cert only
		},
	}
	resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("tunneled GET failed (kernel may have MITM'd): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunneled" {
		t.Fatalf("body = %q", body)
	}
}

// Connection: Upgrade is relayed as a 101 and then piped verbatim.
func TestWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "want upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, conn) // echo
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	addr, ca, _ := startProxyServer(t, map[string]map[string]config.Rule{host: {}}, roots, &config.Server{})

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()

	if _, err := raw.Write([]byte("CONNECT " + net.JoinHostPort(host, port) + " HTTP/1.1\r\nHost: " + net.JoinHostPort(host, port) + "\r\n\r\n")); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	tlsConn := tls.Client(raw, &tls.Config{RootCAs: ca.RootPool(), ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}

	req := "GET /ws HTTP/1.1\r\nHost: " + net.JoinHostPort(host, port) +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	tbr := bufio.NewReader(tlsConn)
	up, err := http.ReadResponse(tbr, nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if up.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", up.StatusCode)
	}

	payload := []byte("ping-frame")
	if _, err := tlsConn.Write(payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tbr, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
}

// Stats must count what the kernel actually served.
func TestStatsCountRequests(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	host := hostOf(t, upstream.Listener.Addr().String())

	addr, ca, srv := startProxyServer(t, map[string]map[string]config.Rule{host: {}}, roots, &config.Server{})
	client := clientFor(addr, ca)

	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := srv.Stats.Requests.Load(); got < 2 {
		t.Fatalf("requests = %d, want >= 2", got)
	}
	if got := srv.Stats.Responses.Load(); got < 2 {
		t.Fatalf("responses = %d, want >= 2", got)
	}
	if srv.Stats.Snapshot() == "{}" {
		t.Fatal("snapshot is empty")
	}
}

// tlsServerForName serves HTTPS with a certificate valid only for dnsName, so a
// request dialed as 127.0.0.1 cannot verify unless the rule names that host.
func tlsServerForName(t *testing.T, dnsName string) (string, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hs := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "verifyok")
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}}},
	}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = hs.Close() })

	return ln.Addr().String(), cert
}

// verifyHost declares which name the origin chain must match, which is what
// SNI-swapping rules need.
func TestVerifyHostOverridesChainCheck(t *testing.T) {
	const name = "only-this.example"
	upAddr, cert := tlsServerForName(t, name)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	host := hostOf(t, upAddr)

	// The desktop's sni.js swaps in an unverifying agent, so a plain SNI override
	// never checks the chain: the disguised name cannot match the certificate.
	t.Run("a plain sni rule does not verify the chain", func(t *testing.T) {
		addr, ca, _ := startProxyServer(t, map[string]map[string]config.Rule{
			host: {".*": {SNI: name}},
		}, roots, &config.Server{})
		resp, err := clientFor(addr, ca).Get("https://" + upAddr + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "verifyok" {
			t.Fatalf("status=%d body=%q", resp.StatusCode, body)
		}
	})

	// A proxy rule keeps verification against the target it dials, which is why
	// the configuration pairs "proxy" with "verifyHost".
	t.Run("a proxy rule without verifyHost rejects the mismatched chain", func(t *testing.T) {
		addr, ca, _ := startProxyServer(t, map[string]map[string]config.Rule{
			host: {".*": {Proxy: hostOf(t, upAddr), SNI: name}},
		}, roots, &config.Server{})
		resp, err := clientFor(addr, ca).Get("https://" + upAddr + "/")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", resp.StatusCode)
			}
		}
	})

	t.Run("with verifyHost the same chain passes", func(t *testing.T) {
		addr, ca, _ := startProxyServer(t, map[string]map[string]config.Rule{
			host: {".*": {SNI: name, VerifyHost: name}},
		}, roots, &config.Server{})
		resp, err := clientFor(addr, ca).Get("https://" + upAddr + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "verifyok" {
			t.Fatalf("status=%d body=%q", resp.StatusCode, body)
		}
	})
}

// The stats endpoint is answered by the kernel and must not dial upstream; the
// host name here does not even resolve.
func TestStatsEndpointServedLocally(t *testing.T) {
	addr, _, _ := startProxyServer(t, nil, nil, &config.Server{})

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("http://stats.invalid/__ds_stats__")
	if err != nil {
		t.Fatalf("GET stats: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"requests"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

package proxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

func startProxy(t *testing.T, intercepts map[string]map[string]config.Rule, upstreamRoots *x509.CertPool) (addr string, ca *certcache.Authority) {
	t.Helper()
	return startProxyFull(t, intercepts, upstreamRoots, &config.Server{})
}

func startProxyFull(t *testing.T, intercepts map[string]map[string]config.Rule, upstreamRoots *x509.CertPool, serverCfg *config.Server) (addr string, ca *certcache.Authority) {
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

// TestSNIRuleUsesForSNIProvider: a host with an sni rule but no DNS mapping
// resolves through the ForSNI provider (marked `forSNI`), keeping such hosts
// off the plain system DNS. The fake provider answers with the test TLS
// upstream address, so the MITM request through sni.example proves the whole
// dialUpstream chain (ForSNI resolution + SNI rewrite + verify) works.
func TestSNIRuleUsesForSNIProvider(t *testing.T) {
	addr, roots, handlerCh := startTLSTestServer(t, []string{"sni.example"}, nil)
	upHost, upPort, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	_, _, _ = upHost, upPort, handlerCh

	// A local UDP test DNS answering every name with the upstream IP.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer pc.Close()
	go serveFixedUDP(pc, upHost)

	dHost, dPort, _ := net.SplitHostPort(pc.LocalAddr().String())

	serverCfg := &config.Server{
		DNS: config.DNS{
			Providers: map[string]*config.DNSProvider{"forSniD": {Server: dHost, Port: atoiP(dPort), ForSNI: true}},
		},
	}
	intercepts := map[string]map[string]config.Rule{
		"sni.example": {".*": {SNI: "baidu.com"}},
	}
	proxyAddr, ca := startProxyFull(t, intercepts, roots, serverCfg)
	client := clientFor(proxyAddr, ca)
	client.Timeout = 5 * time.Second

	resp, err := client.Get("https://sni.example" + ":" + upPort + "/p")
	if err != nil {
		t.Fatalf("GET via sni.example: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "ok:sni.example") {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

// startTLSTestServer runs a TLS HTTP server with a self-signed certificate
// valid for the given DNS names. Returns listen addr and the trust root.
func startTLSTestServer(t *testing.T, names []string, handler http.Handler) (string, *x509.CertPool, chan<- string) {
	t.Helper()
	certDER, key, err := genCertDER(names)
	if err != nil {
		t.Fatalf("genCertDER: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	writeHost := make(chan string, 16)
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeHost <- r.Host
			fmt.Fprintf(w, "ok:%s", r.Host)
		})
	}
	go func() {
		s := &http.Server{Handler: handler}
		_ = s.Serve(tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		}))
	}()
	return ln.Addr().String(), roots, writeHost
}

// genCertDER creates a self-signed certificate covering the given names.
func genCertDER(names []string) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

// serveFixedUDP answers every query with a fixed A record.
func serveFixedUDP(pc net.PacketConn, ip string) {
	buf := make([]byte, 4096)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := buf[:n]
		r := append([]byte(nil), q[:12]...)
		r[2], r[3] = 0x80, 0x00
		r[6], r[7] = 0, 1
		r[8], r[9] = 0, 0
		r = append(r, q[12:]...) // question section

		rr := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04}
		rr = append(rr, net.ParseIP(ip).To4()...)
		r = append(r, rr...)
		_, _ = pc.WriteTo(r, raddr)
	}
}

// atoiP converts a port string into an int.
func atoiP(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

package proxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// TestQuicUpstreamCarriesTheRequest is the end-to-end proof for the HTTP/3 path:
// a real HTTP/3 origin, a proxy told to use it for that host, and a request that
// must arrive over UDP rather than the TCP fallback.
func TestQuicUpstreamCarriesTheRequest(t *testing.T) {
	cert, roots := h3TestCert(t)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	origin := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "h3-ok")
		}),
	}
	go func() { _ = origin.Serve(pc) }()
	t.Cleanup(func() { _ = origin.Close() })
	upAddr := pc.LocalAddr().String()

	// The rule has to exist, otherwise the proxy blind-tunnels and never parses
	// the request; the host list is what opts this host into HTTP/3.
	host := hostOf(t, upAddr)
	addr, ca, _ := startProxyServer(t, map[string]map[string]config.Rule{
		host: {".*": {}},
	}, roots, &config.Server{Setting: config.Setting{
		QuicUpstream: config.QuicSetting{
			Enabled: true,
			Hosts:   config.StringList{host},
		},
	}})

	resp, err := clientFor(addr, ca).Get("https://" + upAddr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := resp.Header.Get("DS-Upstream"); got != "h3" {
		t.Fatalf("DS-Upstream = %q, want h3 (status %d, body %q)", got, resp.StatusCode, body)
	}
	if string(body) != "h3-ok" {
		t.Fatalf("body = %q, want h3-ok", body)
	}
}

// TestQuicUpstreamFallsBackWhenDisabled pins the other half: with the feature
// off, the same request must still succeed over TCP.
func TestQuicUpstreamFallsBackWhenDisabled(t *testing.T) {
	const name = "example.test"
	upAddr, cert := tlsServerForName(t, name)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	host := hostOf(t, upAddr)

	// The origin presents a certificate for name while the client dials an
	// address, so the rule has to say which name to verify — the same shape the
	// real configuration uses for SNI-swapping rules.
	addr, ca, _ := startProxyServer(t, map[string]map[string]config.Rule{
		host: {".*": {SNI: name, VerifyHost: name}},
	}, roots, &config.Server{})

	resp, err := clientFor(addr, ca).Get("https://" + upAddr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("DS-Upstream"); got != "" {
		t.Fatalf("DS-Upstream = %q, want empty when the feature is off", got)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "verifyok" {
		t.Fatalf("body = %q", body)
	}
}

// h3TestCert mints a self-signed certificate for 127.0.0.1 and the pool that
// trusts it, which is all an HTTP/3 test origin needs.
func h3TestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
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
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

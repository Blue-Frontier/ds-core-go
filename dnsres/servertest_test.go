package dnsres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"
)

// discardLogger keeps test output quiet.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---- canned DNS test servers -------------------------------------------

// testConfig is the canned answer set of a fake DNS server.
type testConfig struct {
	replyA   []string // A answers
	replyAAA []string // AAAA answers
}

// dnsWireResponse assembles a response message for a query, reusing the
// header id + question section of the request and pointing answer names at
// the question name (offset 12).
func dnsWireResponse(pkg []byte, cfg testConfig) []byte {
	r := append([]byte(nil), pkg[:msgHeaderLen]...)
	copy(r[0:2], pkg[0:2])
	r[2], r[3] = 0x80, 0x00 // response, rcode 0
	binary.BigEndian.PutUint16(r[6:8], uint16(len(cfg.replyA)))
	binary.BigEndian.PutUint16(r[8:10], uint16(len(cfg.replyAAA)))
	r = append(r, pkg[msgHeaderLen:]...)

	addRecords := func(qtype uint16, ips []string) {
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			var data []byte
			if qtype == typeA {
				data = parsed.To4()
			} else {
				data = parsed.To16()
			}
			rr := []byte{0xc0, 0x0c}
			rr = append(rr, 0x00, 0x00, 0x00, 0x01) // empty type, class IN
			rr[2] = byte(qtype >> 8)
			rr[3] = byte(qtype & 0xff)
			rr = append(rr, 0x00, 0x00, 0x00, 0x3c) // ttl 60
			rr = append(rr, 0x00, byte(len(data)))
			rr = append(rr, data...)
			r = append(r, rr...)
		}
	}
	addRecords(typeA, cfg.replyA)
	addRecords(typeAAAA, cfg.replyAAA)
	return r
}

// startFakeUDPDNS serves canned answers over UDP.
func startFakeUDPDNS(t *testing.T, cfg testConfig) string {
	pc, _ := startFakeUDPDNSCounted(t, cfg)
	return pc
}

// startFakeUDPDNSCounted additionally reports how many queries it answered.
func startFakeUDPDNSCounted(t *testing.T, cfg testConfig) (addr string, count func() int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	var requests int
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			requests++
			_, _ = pc.WriteTo(dnsWireResponse(buf[:n], cfg), raddr)
		}
	}()
	return pc.LocalAddr().String(), func() int { return requests }
}

// startFakeTCPDNS serves canned answers over plain TCP, joined host:port.
func startFakeTCPDNS(t *testing.T, cfg testConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveFrameListener(ln, nil, cfg, nil)
	return ln.Addr().String()
}

// startFakeDotDNS serves canned answers over DNS-over-TLS and reports the
// ClientHello SNI of every connection.
func startFakeDotDNS(t *testing.T, cfg testConfig) (addr string, roots *x509.CertPool, sni func() string) {
	t.Helper()
	tlsConf, roots := selfSignedTLS(t, "dot.example.com")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	names := make(chan string, 16)
	go serveFrameListener(ln, tlsConf, cfg, names)
	return ln.Addr().String(), roots, func() string {
		select {
		case n := <-names:
			return n
		case <-time.After(2 * time.Second):
			return "<no-sni>"
		}
	}
}

// serveFrameListener accepts TCP connections, optionally TLS wrapped, reads
// framed queries and answers with the canned data. SNI observations go to the
// optional channel.
func serveFrameListener(ln net.Listener, tlsConf *tls.Config, cfg testConfig, sni chan<- string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if tlsConf != nil {
			tc := tls.Server(conn, tlsConf)
			go func() {
				if werr := tc.Handshake(); werr != nil {
					conn.Close()
					return
				}
				if name := tc.ConnectionState().ServerName; sni != nil && name != "" {
					select {
					case sni <- name:
					default:
					}
				}
				serveframed(tc, cfg)
			}()
			continue
		}
		go serveframed(conn, cfg)
	}
}

// serveframed reads one framed query and answers it repeatedly.
func serveframed(conn net.Conn, cfg testConfig) {
	defer conn.Close()
	for {
		var lenBuf [2]byte
		if _, err := readFull(conn, lenBuf[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := readFull(conn, msg); err != nil {
			return
		}
		out := dnsWireResponse(msg, cfg)
		framed := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(framed, uint16(len(out)))
		copy(framed[2:], out)
		if _, err := conn.Write(framed); err != nil {
			return
		}
	}
}

// readFull reads exactly len(buf) bytes.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// splitHostPortS splits "127.0.0.1:8080" into its parts.
func splitHostPortS(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return host, port
}

// selfSignedTLS builds a server TLS config with a fresh self-signed cert and
// a root pool trusting it.
func selfSignedTLS(t *testing.T, host string) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{Raw: der}) // pool accepts the raw DER
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, roots
}

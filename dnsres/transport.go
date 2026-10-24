package dnsres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Upstream transports. Faithful to the desktop kernel's four DNS flavors
// (`DNSOverUDP`, `DNSOverTCP`, `DNSOverTLS`, `DNSOverHTTPS`), including the
// `sni` server option: the TLS ClientHello of the DNS connection itself is
// rewritten (the encrypted DNS server is reached through SNI spoofing, its
// certificate is then not verified — the desktop kernel sets
// rejectUnauthorized:false for the same reason).

const (
	queryTimeout = 8 * time.Second
	dotTimeout   = 4 * time.Second
	dohTimeout   = 5 * time.Second
)

// tlsSettings returns the TLS config for a secure DNS connection. serverHost
// is the name the certificate must carry (plain DNS server name); override is
// the SNI spoofing target ("" = none).
func tlsSettings(serverHost, override string, rootCAs *x509.CertPool, port string) (*tls.Config, string, error) {
	addr := net.JoinHostPort(serverHost, port)
	if override != "" {
		return &tls.Config{
			ServerName:         override,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}, addr, nil
	}
	return &tls.Config{
		ServerName: serverHost,
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}, addr, nil
}

// dialNetwork maps the configured family to dialer networks.
func dialNetwork(family int) string {
	switch family {
	case 4:
		return "tcp4"
	case 6:
		return "tcp6"
	}
	return "tcp"
}

// queryUDP sends one DNS packet over UDP and collects the single reply.
func queryUDP(ctx context.Context, server string, port string, family int, pkg []byte) ([]byte, error) {
	raddr, err := familyAddr(ctx, server, port, family)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "udp", raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(queryTimeout)
	if d0, ok := ctx.Deadline(); ok && d0.Before(deadline) {
		deadline = d0
	}
	_ = conn.SetDeadline(deadline)

	_, err = conn.Write(pkg)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// queryTCP sends a length-framed DNS query over TCP.
func queryTCP(ctx context.Context, server string, port string, family int, pkg []byte) ([]byte, error) {
	raddr, err := familyAddr(ctx, server, port, family)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, dialNetwork(family), raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(queryTimeout)
	if d0, ok := ctx.Deadline(); ok && d0.Before(deadline) {
		deadline = d0
	}
	_ = conn.SetDeadline(deadline)
	return framedExchange(conn, pkg)
}

// queryDoT opens a TLS connection to the DNS server (SNI rewritten when the
// provider configures an override) and sends a framed query.
func queryDoT(ctx context.Context, server, port, override string, family int, rootCAs *x509.CertPool, pkg []byte) ([]byte, error) {
	cfg, addr, err := tlsSettings(server, override, rootCAs, port)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, dialNetwork(family), addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	deadline := time.Now().Add(dotTimeout)
	if d0, ok := ctx.Deadline(); ok && d0.Before(deadline) {
		deadline = d0
	}
	_ = raw.SetDeadline(deadline)

	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("dot handshake %s: %w", addr, err)
	}
	defer tc.Close()
	return framedExchange(tc, pkg)
}

// framedExchange writes a 2-byte length framed message and reads one frame.
func framedExchange(conn net.Conn, pkg []byte) ([]byte, error) {
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(pkg)))
	if _, err := conn.Write(head[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(pkg); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, msg); err != nil && err != io.EOF {
		return nil, err
	}
	return msg, nil
}

// familyAddr resolves addr once via the system resolver, honoring the family
// preference. DNS server names are resolved outside ds DNS on purpose (the
// bootstrap configuration uses plain system DNS), as on the desktop.
func familyAddr(ctx context.Context, server, port string, family int) (string, error) {
	hostport := net.JoinHostPort(server, port)
	if ip := net.ParseIP(server); ip != nil {
		switch {
		case family == 4 && ip.To4() == nil:
			return "", fmt.Errorf("dnsres: %s is not an IPv4 address", server)
		case family == 6 && ip.To4() != nil:
			return "", fmt.Errorf("dnsres: %s is not an IPv6 address", server)
		}
		return hostport, nil
	}
	ips, err := net.LookupIP(server)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if family == 6 && ip.To4() != nil {
			continue
		}
		if family == 4 && ip.To4() == nil {
			continue
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	return hostport, nil
}

package dnsres

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DNS-over-HTTPS (RFC 8484 wire format POST/GET), with the SNI rewrite option
// of the desktop kernel: when the provider configures `sni`, the TLS
// connection to the DoH endpoint carries the spoofed name and skips
// verifying the certificate, so the encrypted DNS service can be reached even
// when its address is only reachable under another SNI.

// dohClient queries one DoH endpoint. The http.Transport keeps connections
// alive (keepAlive:true, timeout 4000 on the desktop kernel).
type dohClient struct {
	server  string // normalized base URL, always ending in the api path
	hostU   string // URL hostname
	portU   string // URL port ("" when implicit)
	sni     string
	family  int
	rootCAs *x509.CertPool
	tr      *http.Transport
}

// normalizeDoHServer mirrors index.js: an explicit https type with a bare
// host gets the scheme added, a host without path gets /dns-query.
func normalizeDoHServer(server string) (string, error) {
	server = strings.TrimSpace(strings.Join(strings.Fields(server), ""))
	if server == "" {
		return "", fmt.Errorf("dnsres: empty DoH server")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("dnsres: bad DoH server %q", server)
	}
	if u.Path == "" || u.Path == "null" {
		u.Path = "/dns-query"
	}
	return u.String(), nil
}

// host returns the URL hostname of the DoH server.
func (c *dohClient) host() string { return c.hostU }

// port returns the URL port of the DoH server ("" when implicit).
func (c *dohClient) port() string { return c.portU }

func newDohClient(server, sni string, family int, rootCAs *x509.CertPool) (*dohClient, error) {
	base, err := normalizeDoHServer(server)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	secure := strings.EqualFold(u.Scheme, "https")
	host := u.Hostname()
	tr := &http.Transport{
		MaxIdleConns:        8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			ServerName: host,
			RootCAs:    rootCAs,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			net2 := dialNetwork(family)
			if net2 == "tcp" {
				net2 = network
			}
			return d.DialContext(ctx, net2, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			net2 := dialNetwork(family)
			if net2 == "tcp" {
				net2 = network
			}
			raw, err := d.DialContext(ctx, net2, addr)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			}
			if sni != "" {
				cfg.ServerName = sni
				cfg.InsecureSkipVerify = true
			} else {
				cfg.ServerName = host
				cfg.RootCAs = rootCAs
			}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	if !secure {
		// Plain HTTP DoH endpoints never hit DialTLSContext; keep SNI
		// irrelevant there.
		tr.DialTLSContext = nil
	}
	return &dohClient{server: base, hostU: u.Hostname(), portU: u.Port(), sni: sni, family: family, rootCAs: rootCAs, tr: tr}, nil
}

// queryWire sends an application/dns-message POST and returns the raw DNS
// response body.
func (c *dohClient) queryWire(ctx context.Context, pkg []byte) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server, bytes.NewReader(pkg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")

	body, ct, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	if ct != "" && strings.Contains(ct, "json") {
		return parseDohJSON(body)
	}
	return parseResponse(body)
}

// queryJSON sends the ?name=...&type=... JSON API request (used by endpoints
// whose default answer is json, e.g. RFC 8427 servers).
func (c *dohClient) queryJSON(ctx context.Context, hostname, typ string) (*response, error) {
	u, err := url.Parse(c.server)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("name", hostname)
	q.Set("type", typ)
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")

	body, ct, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	if ct == "" || !strings.Contains(ct, "json") {
		// JSON API endpoint answered with the wire format instead.
		return parseResponse(body)
	}
	return parseDohJSON(body)
}

func (c *dohClient) do(ctx context.Context, req *http.Request) ([]byte, string, error) {
	client := &http.Client{Transport: c.tr, Timeout: dohTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("DoH service returned status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return body, resp.Header.Get("content-type"), nil
}

// dohJSONAnswer mirrors RFC 8427's shape (desktop kernel `_parseJsonResponse`).
type dohJSONAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohJSONResult struct {
	Status  int             `json:"Status"`
	TC      bool            `json:"TC"`
	Answers []dohJSONAnswer `json:"Answer"`
}

// parseDohJSON converts the JSON API answer into the same shape as wire
// format A/AAAA records.
func parseDohJSON(body []byte) (*response, error) {
	var raw dohJSONResult
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("content returned by the DoH service is not valid JSON: %w", err)
	}
	if raw.Status != 0 {
		return nil, fmt.Errorf("DoH service returned error status: %d", raw.Status)
	}
	r := &response{truncated: raw.TC}
	for _, a := range raw.Answers {
		if ip := net.ParseIP(strings.TrimSpace(a.Data)); ip != nil {
			switch {
			case ip.To4() != nil:
				r.answers = append(r.answers, answer{name: a.Name, typ: typeA, ttl: uint32(a.TTL), data: ip.To4()})
			case len(ip.To16()) == net.IPv6len:
				r.answers = append(r.answers, answer{name: a.Name, typ: typeAAAA, ttl: uint32(a.TTL), data: ip.To16()})
			}
		}
	}
	return r, nil
}

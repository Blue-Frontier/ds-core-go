// Package proxy is the kernel's HTTP proxy: it terminates TLS for CONNECT
// tunnels using certificates from certcache, applies intercept rules to the
// decrypted requests and re-encrypts them towards the origin.
//
// Scope of this first cut: HTTP/1.1 only, one request per upstream connection,
// no response rewriting (script injection) yet. That is enough to reproduce the
// path based rules of the desktop kernel - redirects to mirrors, upstream host
// swaps and SNI overrides - which is what the mobile port needs first.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/dnsres"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
	"github.com/Blue-Frontier/ds-core-go/rules"
)

// errClose stops the keep-alive loop after honouring "Connection: close".
var errClose = errors.New("connection closed")

// Server serves the proxy protocol.
type Server struct {
	Table *rules.Table
	CA    *certcache.Authority
	DNS   *dnsres.Resolver
	Log   *slog.Logger

	// UpstreamRootCAs overrides the system root pool used to verify origin
	// certificates. Tests and private CAs use it.
	UpstreamRootCAs *x509.CertPool
	// DialTimeout bounds the TCP connect and TLS handshake to the origin.
	DialTimeout time.Duration
}

// New builds a proxy server from configuration.
func New(cfg *config.Config, ca *certcache.Authority, log *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("proxy: nil config")
	}
	table, err := rules.Compile(cfg.Server.Intercepts)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		Table: table,
		CA:    ca,
		DNS:   dnsres.New(&cfg.Server, dnsres.WithLogger(log)),
		Log:   log,
		// DialTimeout bounds the TCP connect (and per-candidate TLS handshake)
		// to the origin: 5s so blocked IPs fail fast and the working candidate
		// is reached within the client's patience; failures sink to the tail
		// via DNS.Note and good IPs lead on later connections.
		DialTimeout: 5 * time.Second,
	}, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handlePlainHTTP(w, r)
}

// handleConnect terminates the client TLS and proxies the decrypted stream.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitTarget(r.Host, "443")
	if err != nil {
		http.Error(w, "bad CONNECT target: "+err.Error(), http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	s.Log.Debug("connect", "host", host, "port", port)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		conn.Close()
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host // IP targets carry no SNI
			}
			return s.CA.LeafFor(name)
		},
	})
	if err := tlsConn.HandshakeContext(r.Context()); err != nil {
		s.Log.Debug("client handshake failed", "host", host, "err", err)
		conn.Close()
		return
	}

	s.serveStream(tlsConn, nil, nil, host, port, "https")
}

// handlePlainHTTP serves absolute-form requests (proxy style, no TLS).
func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Host == "" {
		http.Error(w, "proxy request requires an absolute URL", http.StatusBadRequest)
		return
	}
	host, port, err := splitTarget(r.URL.Host, "80")
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	s.serveStream(conn, rw.Reader, r, host, port, "http")
}

// serveStream runs the request loop over a (possibly decrypted) connection.
func (s *Server) serveStream(conn net.Conn, br *bufio.Reader, first *http.Request, host, port, scheme string) {
	defer conn.Close()
	if br == nil {
		br = bufio.NewReader(conn)
	}

	if first != nil {
		if err := s.serveOne(conn, first, host, port, scheme); err != nil {
			return
		}
	}
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if err := s.serveOne(conn, req, host, port, scheme); err != nil {
			return
		}
	}
}

func (s *Server) serveOne(conn net.Conn, req *http.Request, host, port, scheme string) error {
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()

	path := "/"
	if req.URL != nil && req.URL.Path != "" {
		path = req.URL.Path
	}
	s.Log.Debug("request", "method", req.Method, "host", host, "path", path)
	action, matched := s.Table.Match(host, path)

	// Redirect rules answer locally without touching the origin.
	if matched && action.Rule.Redirect != "" {
		target := "https://" + action.Rule.Redirect + requestURI(req)
		_, _ = io.Copy(io.Discard, req.Body)
		s.Log.Info("redirect", "host", host, "path", path, "to", target)
		_, err := fmt.Fprintf(conn,
			"HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", target)
		return err
	}

	dstHost := host
	if matched && action.Rule.Proxy != "" {
		dstHost = hostmatch.Normalize(action.Rule.Proxy)
	}

	upstream, upstreamIP, err := s.dialUpstream(req.Context(), dstHost, port, scheme, action, matched)
	if err != nil {
		s.Log.Warn("upstream failed", "host", host, "err", err)
		return s.writeError(conn, http.StatusBadGateway, err)
	}
	defer upstream.Close()

	out := req.Clone(req.Context())
	out.URL.Scheme = scheme
	out.URL.Host = net.JoinHostPort(dstHost, port)
	out.RequestURI = ""
	out.Close = true
	stripHopHeaders(out.Header)

	// A successful TLS handshake does not mean the origin answers: some
	// addresses are quietly blackholed after the handshake (every packet on
	// the established flow is dropped). Bound the response-header window; on
	// a timeout demote the address and redial once - the next race dial then
	// leads with the other candidates. The body itself is unbounded after the
	// headers arrive.
	const respHeaderTimeout = 10 * time.Second
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		tw := time.Now()
		err := out.Write(upstream)
		if err == nil {
			s.Log.Debug("upstream request written", "host", host, "ms", time.Since(tw).Milliseconds())
			upstream.SetReadDeadline(time.Now().Add(respHeaderTimeout))
			tr := time.Now()
			resp, err = http.ReadResponse(bufio.NewReader(upstream), out)
			if err == nil {
				s.Log.Debug("response received", "host", host, "status", resp.StatusCode, "ms", time.Since(tr).Milliseconds())
				upstream.SetReadDeadline(time.Time{})
				defer resp.Body.Close()
				break
			}
		}
		// Dead address: demote it so the follow-up dial skips it.
		s.DNS.Note(dstHost, upstreamIP, true)
		upstream.Close()
		if attempt >= 1 {
			s.Log.Warn("upstream failed", "host", host, "err", err)
			return s.writeError(conn, http.StatusBadGateway, err)
		}
		s.Log.Debug("upstream retry", "host", host, "ip", upstreamIP, "err", err)
		upstream, upstreamIP, err = s.dialUpstream(req.Context(), dstHost, port, scheme, action, matched)
		if err != nil {
			s.Log.Warn("upstream failed", "host", host, "err", err)
			return s.writeError(conn, http.StatusBadGateway, err)
		}
		defer upstream.Close()
	}

	if err := resp.Write(conn); err != nil {
		return err
	}
	s.Log.Debug("response written", "host", host, "status", resp.StatusCode)
	if req.Close {
		return errClose
	}
	return nil
}

// dialUpstream resolves and connects to the origin, applying SNI overrides.
//
// Resolution mirrors the desktop kernel's selection order: preset IP list
// wins, then the per-host provider mapping (DoH/DoT/TCP/UDP), and hosts that
// only carry an SNI rule go through the ForSNI provider so their address
// comes from the protected DNS pipe instead of the plain system DNS (which is
// what makes `sni` usable in the first place).
func (s *Server) dialUpstream(ctx context.Context, host, port, scheme string, action rules.Action, matched bool) (net.Conn, string, error) {
	ips, err := s.resolve(ctx, host, action, matched)
	if err != nil {
		return nil, "", err
	}

	// Race dial: GFW-dropped addresses sit ahead of reachable ones in fresh
	// lists, and serial dialing spends 5s on each before reaching them -
	// past the client's patience. Dial+TLS one batch at a time in parallel
	// and take the first usable connection; failures are reported to the
	// DNS preference (they sink to the tail) as usual.
	const batchSize = 6
	for start := 0; start < len(ips); start += batchSize {
		end := start + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		up, connIdx, lastErr := s.raceDial(ctx, host, port, scheme, action, matched, ips, start, end)
		if up != nil {
			s.DNS.Note(host, ips[connIdx].String(), false)
			return up, ips[connIdx].String(), nil
		}
		for i := start; i < end; i++ {
			s.DNS.Note(host, ips[i].String(), true)
		}
		if lastErr == nil {
			lastErr = errors.New("no usable address")
		}
	}
	return nil, "", errors.New("no usable address")
}

// raceDial runs dial+TLS for ips[start:end] simultaneously and returns the
// first connection that becomes fully usable (TCP plus, for https, a verified
// handshake). Losers are cancelled; ones that already failed are reported via
// DNS.Note so the address preference demotes them relative to the winner.
func (s *Server) raceDial(ctx context.Context, host, port, scheme string, action rules.Action, matched bool, ips []net.IP, start, end int) (net.Conn, int, error) {
	// ctx time-bounds the whole batch: dial and handshake budgets.
	bctx, cancel := context.WithTimeout(ctx, s.DialTimeout*time.Duration(end-start))
	defer cancel()
	dialer := &net.Dialer{Timeout: s.DialTimeout}
	batchAt := time.Now()

	type attempt struct {
		idx  int
		conn net.Conn
		err  error
	}
	results := make(chan attempt, end-start)

	for i := start; i < end; i++ {
		go func(idx int, ip net.IP) {
			ta := time.Now()
			sn, err := s.dialOne(bctx, dialer, host, port, scheme, action, matched, ip)
			if err != nil {
				s.Log.Debug("dial attempt failed", "host", host, "ip", ip.String(), "ms", time.Since(ta).Milliseconds(), "err", err)
			}
			results <- attempt{idx: idx, conn: sn, err: err}
		}(i, ips[i])
	}

	var conn net.Conn
	connIdx := -1
	var lastErr error
	seen := make(map[int]bool)
	for len(seen) < end-start {
		r := <-results
		seen[r.idx] = true
		if r.err != nil {
			if r.idx < connIdx || connIdx < 0 {
				lastErr = r.err
			}
			if r.idx != connIdx {
				continue // winner already found; nothing more to do
			}
			break // winner's own attempt failed; keep draining
		}
		if connIdx < 0 {
			// First usable connection wins the batch.
			cancel()
			conn = r.conn
			connIdx = r.idx
		} else {
			r.conn.Close() // a duplicate usable connection; discard
		}
	}
	// Demote batch candidates that reported failure up to (but not incl.)
	// the winner index, mirroring the serial order semantics.
	if connIdx >= 0 {
		for i := start; i < connIdx; i++ {
			s.DNS.Note(host, ips[i].String(), true)
		}
		s.Log.Debug("dial winner", "host", host, "ip", ips[connIdx].String(), "ms", time.Since(batchAt).Milliseconds())
	} else {
		connIdx = start // so the caller's fallback Note loop covers the batch
	}
	return conn, connIdx, lastErr
}

// dialOne opens one candidate: TCP dial then, for https, the SNI override and
// upstream chain verification exactly as the desktop kernel does.
func (s *Server) dialOne(ctx context.Context, dialer *net.Dialer, host, port, scheme string, action rules.Action, matched bool, ip net.IP) (net.Conn, error) {
	addr := net.JoinHostPort(ip.String(), port)
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if scheme != "https" {
		return raw, nil
	}

	sni := ""
	if matched {
		sni = strings.TrimSpace(action.Rule.SNI)
	}
	cfg := &tls.Config{
		ServerName: host,
		RootCAs:    s.UpstreamRootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if sni != "" {
		// The origin is asked for a different name than the one the client
		// wants; the chain is checked against the real host below.
		cfg.ServerName = sni
		cfg.InsecureSkipVerify = true
	}

	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if sni == "" {
		return tc, nil
	}
	if err := verifyFor(tc.ConnectionState(), host, s.UpstreamRootCAs); err != nil {
		tc.Close()
		return nil, err
	}
	return tc, nil
}

// resolve runs the DNS selection for an upstream dial.
func (s *Server) resolve(ctx context.Context, host string, action rules.Action, matched bool) ([]net.IP, error) {
	sniRule := matched && strings.TrimSpace(action.Rule.SNI) != ""
	if sniRule && !s.DNS.HasDNS(host) {
		ips, err := s.DNS.LookupForSNI(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", host)
		}
		return ips, nil
	}
	ips, err := s.DNS.Lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	return ips, nil
}

func (s *Server) writeError(conn net.Conn, code int, err error) error {
	body := err.Error()
	_, werr := fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
	return werr
}

// verifyFor checks the presented chain against the host the client asked for.
func verifyFor(state tls.ConnectionState, host string, roots *x509.CertPool) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
	})
	return err
}

func splitTarget(hostport, defaultPort string) (host, port string, err error) {
	if hostport == "" {
		return "", "", errors.New("empty target")
	}
	h, p, err := net.SplitHostPort(hostport)
	if err == nil {
		return hostmatch.Normalize(h), p, nil
	}
	return hostmatch.Normalize(hostport), defaultPort, nil
}

func requestURI(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	if r.URL != nil {
		return r.URL.RequestURI()
	}
	return "/"
}

func stripHopHeaders(h http.Header) {
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
}

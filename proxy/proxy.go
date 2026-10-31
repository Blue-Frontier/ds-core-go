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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/dnsres"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
	"github.com/Blue-Frontier/ds-core-go/rules"
	"github.com/Blue-Frontier/ds-core-go/scriptstore"
)

// errClose stops the keep-alive loop after honouring "Connection: close".
var errClose = errors.New("connection closed")

// Server serves the proxy protocol.
type Server struct {
	CA  *certcache.Authority
	Log *slog.Logger

	// Scripts supplies the JavaScript injected into matching HTML responses.
	Scripts *scriptstore.Store
	// Stats counts traffic for the GUI / mobile API.
	Stats *Stats

	// UpstreamRootCAs overrides the system root pool used to verify origin
	// certificates. Tests and private CAs use it.
	UpstreamRootCAs *x509.CertPool
	// DialTimeout bounds the TCP connect and TLS handshake to the origin.
	DialTimeout time.Duration

	// cfMu guards the cloudflareRoute refresher tied to the active state.
	cfMu     sync.Mutex
	cfCancel context.CancelFunc

	// pool keeps upstream sockets alive between requests.
	pool *connPool

	// presetMu guards the "preset addresses are dead" memory.
	presetMu   sync.Mutex
	presetDead map[string]time.Time

	// state holds everything derived from the configuration. Swapping the
	// pointer is how a reload takes effect: in-flight requests keep using the
	// snapshot they started with.
	state atomic.Pointer[state]
}

// state is one compiled configuration snapshot.
type state struct {
	table         *rules.Table
	dns           *dnsres.Resolver
	whiteList     map[string]bool
	excludeIPList map[string]bool
	insecure      map[string]bool
	overwall      *overwall
	nat64         config.NAT64
	ech           *echState
	cf            *cfRoute
	// interceptEnabled is the master switch ("server.intercept.enabled").
	interceptEnabled bool
	// defaultTimeout and timeoutMapping configure the response timeout.
	defaultTimeout int
	timeoutMapping map[string]int
	// allowTls12 and verifySsl mirror "server.setting".
	allowTls12  bool
	verifySsl   bool
	tlsVersions map[string]uint16
	// scriptEnabled gates the injection middleware ("server.setting.script").
	scriptEnabled bool
}

func (s *Server) st() *state { return s.state.Load() }

// Table returns the rules currently in force.
func (s *Server) Table() *rules.Table {
	if st := s.state.Load(); st != nil {
		return st.table
	}
	return &rules.Table{}
}

// filterDisabled drops the rules switched off in the UI.
func filterDisabled(in map[string]map[string]config.Rule, disabled []config.DisabledRule) map[string]map[string]config.Rule {
	off := make(map[string]map[string]bool, len(disabled))
	for _, d := range disabled {
		if off[d.Host] == nil {
			off[d.Host] = make(map[string]bool)
		}
		off[d.Host][d.Pattern] = true
	}
	out := make(map[string]map[string]config.Rule, len(in))
	for host, rules := range in {
		skip := off[host]
		if skip == nil {
			out[host] = rules
			continue
		}
		kept := make(map[string]config.Rule, len(rules))
		for pattern, rule := range rules {
			if skip[pattern] {
				continue
			}
			kept[pattern] = rule
		}
		if len(kept) > 0 {
			out[host] = kept
		}
	}
	return out
}

// buildState compiles one configuration snapshot.
func buildState(cfg *config.Config, scripts *scriptstore.Store, log *slog.Logger) (*state, error) {
	// Rewrite absolute script URLs to store keys before compiling the rules so
	// injection can point at the kernel's own /____ds_script____/ path.
	source := cfg.Server.Intercepts
	if len(cfg.Disabled) > 0 {
		source = filterDisabled(source, cfg.Disabled)
	}
	intercepts := prepareScripts(source, scripts)
	table, err := rules.Compile(intercepts)
	if err != nil {
		return nil, err
	}

	insecure := make(map[string]bool)
	for target, opt := range cfg.Server.Compatible.Request {
		if opt.RejectUnauthorized != nil && !*opt.RejectUnauthorized {
			insecure[strings.ToLower(strings.TrimSpace(target))] = true
		}
	}

	return &state{
		table:            table,
		dns:              dnsres.New(&cfg.Server, dnsres.WithLogger(log)),
		whiteList:        cfg.Server.WhiteList,
		excludeIPList:    cfg.Proxy.ExcludeIPList,
		insecure:         insecure,
		overwall:         newOverwall(cfg.Plugin.Overwall),
		nat64:            cfg.Server.DNS.NAT64,
		ech:              newECH(cfg.Server.DNS.ECH),
		interceptEnabled: cfg.Server.Intercept.EnabledOrDefault(),
		defaultTimeout:   cfg.Server.Setting.DefaultTimeout,
		timeoutMapping:   timeoutMap(cfg.Server.Setting.TimeoutMapping),
		allowTls12:       cfg.Server.Setting.AllowTls12 != nil && *cfg.Server.Setting.AllowTls12,
		verifySsl:        cfg.Server.Setting.VerifySsl == nil || *cfg.Server.Setting.VerifySsl,
		tlsVersions:      tlsVersionMap(cfg.Server.Setting.TLSVersionMapping),
		scriptEnabled:    cfg.Server.Setting.Script.EnabledOrDefault(),
	}, nil
}

// Reload swaps in a freshly compiled configuration without touching listeners
// or the certificate authority.
func (s *Server) Reload(cfg *config.Config) error {
	st, err := buildState(cfg, s.Scripts, s.Log)
	if err != nil {
		return err
	}
	s.stopCF()
	s.state.Store(st)
	s.startCF(st)
	if rewritten := st.table.Rewritten; len(rewritten) > 0 {
		s.Log.Info("rules rewritten (lookahead -> exclusions)", "count", len(rewritten))
	}
	if skipped := st.table.Skipped; len(skipped) > 0 {
		s.Log.Warn("rules skipped (regex unsupported by RE2)", "count", len(skipped), "first", skipped[0])
	}
	return nil
}

// Watch reloads the configuration whenever one of paths changes on disk. A
// configuration that fails to parse is reported and the previous snapshot stays
// in force. The returned function stops the watcher.
func (s *Server) Watch(interval time.Duration, paths []string, load func() (*config.Config, error)) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		last := fileStamps(paths)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				now := fileStamps(paths)
				if equalStamps(last, now) {
					continue
				}
				last = now
				cfg, err := load()
				if err != nil {
					s.Log.Warn("config reload skipped", "err", err)
					continue
				}
				if err := s.Reload(cfg); err != nil {
					s.Log.Warn("config reload failed", "err", err)
					continue
				}
				s.Log.Info("config reloaded", "rules", s.Table().Hosts())
			}
		}
	}()
	return func() { close(stop) }
}

type fileStamp struct {
	size  int64
	mtime int64
}

func fileStamps(paths []string) []fileStamp {
	out := make([]fileStamp, len(paths))
	for i, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		out[i] = fileStamp{size: info.Size(), mtime: info.ModTime().UnixNano()}
	}
	return out
}

func equalStamps(a, b []fileStamp) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// New builds a proxy server from configuration.
func New(cfg *config.Config, ca *certcache.Authority, log *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("proxy: nil config")
	}
	if log == nil {
		log = slog.Default()
	}

	scripts := scriptstore.New(nil)
	st, err := buildState(cfg, scripts, log)
	if err != nil {
		return nil, err
	}

	// Warm the script store off the request path; a repo page should not wait
	// on a userscript download before its first resource can load.
	if len(scripts.Keys()) > 0 {
		go prefetchScripts(scripts, log)
	}
	if rewritten := st.table.Rewritten; len(rewritten) > 0 {
		log.Info("rules rewritten (lookahead -> exclusions)", "count", len(rewritten))
	}
	if skipped := st.table.Skipped; len(skipped) > 0 {
		log.Warn("rules skipped (regex unsupported by RE2)", "count", len(skipped), "first", skipped[0])
	}

	srv := &Server{
		CA:      ca,
		Log:     log,
		Scripts: scripts,
		Stats:   newStats(),
		// DialTimeout bounds the TCP connect (and per-candidate TLS handshake)
		// to the origin: 5s so blocked IPs fail fast and the working candidate
		// is reached within the client's patience; failures sink to the tail
		// via DNS.Note and good IPs lead on later connections.
		DialTimeout: 8 * time.Second,
		pool:        newConnPool(),
	}
	srv.state.Store(st)
	srv.startCF(st)

	// "IP测速": warm the address ranking for the configured hosts.
	if st := cfg.Server.DNS.SpeedTest; st.Enabled && len(st.HostnameList) > 0 {
		go srv.prewarm(st.HostnameList)
	}
	return srv, nil
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

	// whiteList / excludeIpList hosts are relayed as opaque bytes: the desktop
	// kernel never proxies them, and terminating their TLS would break pinned
	// clients and be pointless for tunnelled protocols.
	if s.isBypassed(host) {
		s.Log.Debug("bypass tunnel", "host", host)
		s.blindTunnel(conn, host, port)
		conn.Close()
		return
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		conn.Close()
		return
	}

	// Offer HTTP/2 first: mobile browsers negotiate it, and the desktop kernel
	// does the same (node:http2 with allowHTTP1).
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
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

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		s.Log.Debug("client protocol", "host", host, "alpn", "h2")
		s.serveH2(tlsConn, host, port, "https")
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
		if err := s.serveOne(conn, br, first, host, port, scheme); err != nil {
			return
		}
	}
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if err := s.serveOne(conn, br, req, host, port, scheme); err != nil {
			return
		}
	}
}

func (s *Server) serveOne(conn net.Conn, br *bufio.Reader, req *http.Request, host, port, scheme string) error {
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()

	started := time.Now()
	path := "/"
	if req.URL != nil && req.URL.Path != "" {
		path = req.URL.Path
	}
	s.Log.Debug("request", "method", req.Method, "host", host, "path", path)
	s.Stats.Requests.Add(1)
	s.Stats.NoteHost(host)

	// Injected scripts are served from the kernel itself, under the page's own
	// origin, so the page CSP only has to allow 'self'.
	if s.serveStats(conn, path) {
		return nil
	}
	if s.serveScript(conn, path) {
		return nil
	}

	// The desktop matches against rOptions.path, which is the path *plus* the
	// query string; rules that anchor on "?..." depend on it.
	matchPath := path
	if req.URL != nil {
		matchPath = req.URL.RequestURI()
	}
	// The safe mode turns the rule engine off: every request goes to the origin
	// untouched, exactly like the desktop's server.intercept.enabled = false.
	var action rules.Action
	matched := false
	if s.st().interceptEnabled {
		action, matched = s.st().table.Match(host, matchPath)
	}

	// abort / success / CORS preflight answer locally, ahead of redirect.
	if matched && s.serveLocal(conn, req, action.Rule) {
		return nil
	}
	// A conditional GET inside the cache window is answered with 304.
	if matched && s.serveCached(conn, req, action.Rule) {
		return nil
	}

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

	// The overwall plugin routes matched hosts through its relay server, which
	// takes precedence over the rule's own proxy target.
	relay, relayMark, isRelay := s.overwallFor(host)
	if isRelay && scheme == "https" {
		dstHost = relay.domain
		port = strconv.Itoa(relay.port)
	} else {
		isRelay = false
	}

	// Protocol upgrades (WebSocket) keep their headers and become a pipe once
	// the origin answers 101.
	if req.Header.Get("Upgrade") != "" {
		return s.serveUpgrade(conn, br, req, dstHost, port, scheme, action, matched)
	}

	out := req.Clone(req.Context())
	out.URL.Scheme = scheme
	out.URL.Host = net.JoinHostPort(dstHost, port)
	out.RequestURI = ""
	// Keep-alive upstream: the desktop reuses pooled sockets, and a fresh
	// handshake per asset is what makes pages feel slow. The response decides
	// whether the socket actually goes back to the pool.
	out.Close = false
	stripHopHeaders(out.Header)
	if isRelay {
		out.URL.Path = overwallPath(relay, host, req.URL.Path)
		out.Host = dstHost
		out.Header.Set("dspassword", relay.password)
	}

	// Request-header overrides and the "?DS_DOWNLOAD" marker, applied to the
	// request the origin will see.
	reqActions, download := "", false
	if matched && action.Rule.RequestReplace != nil {
		reqActions, download = s.applyRequestReplace(out, action.Rule)
		out.RequestURI = ""
	}

	// Injection needs to decode the body, and the standard library only knows
	// gzip/deflate. Narrow the request for hosts that inject so the origin can
	// never answer with br/zstd, which would force us to skip the rewrite.
	if len(action.Rule.Script) > 0 || strings.TrimSpace(action.Rule.TampermonkeyScript) != "" {
		out.Header.Set("Accept-Encoding", "gzip, deflate")
	}

	insecure := s.st().insecure[strings.ToLower(net.JoinHostPort(dstHost, port))]
	key := upstreamKey(dstHost, port, scheme, action, matched, insecure)

	var upstream net.Conn
	var upstreamIP string
	reused := false
	if cached := s.pool.get(key); cached != nil {
		upstream, reused = cached, true
		s.Log.Debug("pool hit", "host", host, "key", key)
	} else {
		var usedHost string
		var err error
		upstream, upstreamIP, usedHost, err = s.dialWithBackup(req.Context(), dstHost, port, scheme, action, matched)
		if err != nil {
			s.Log.Warn("upstream failed", "host", host, "err", err)
			return s.writeError(conn, http.StatusBadGateway, err)
		}
		if usedHost != dstHost {
			s.Log.Info("proxy backup used", "host", host, "target", usedHost)
			dstHost = usedHost
			out.URL.Host = net.JoinHostPort(usedHost, port)
			out.Host = usedHost
		}
	}

	// parked is set when the socket goes back to the pool; otherwise it closes.
	parked := false
	defer func() {
		if !parked && upstream != nil {
			upstream.Close()
		}
	}()

	// The response is fetched and its body read *before* a single byte reaches
	// the client, so a stalled upstream (a usable handshake and even usable
	// response headers do not guarantee the body keeps flowing) can still be
	// retried on another address instead of hanging the browser forever.
	var resp *http.Response
	var head []byte
	var complete bool
	for attempt := 0; ; attempt++ {
		// Race-dial/TLS set deadlines on the winner's socket; clear them so the
		// response-header and body budgets below are the only ones in force.
		upstream.SetDeadline(time.Time{})

		werr := out.Write(upstream)
		if werr != nil && reused {
			// A parked socket can be reaped by the origin or the network while
			// idle. That is the one failure mode pooling introduces, and the
			// retry below dials a fresh connection.
			s.Log.Debug("pooled connection stale", "host", host, "err", werr)
			reused = false
		}
		if werr == nil {
			s.Log.Debug("upstream request written", "host", host)
			upstream.SetReadDeadline(time.Now().Add(s.requestTimeout(dstHost)))
			tr := time.Now()
			resp, werr = http.ReadResponse(bufio.NewReader(upstream), out)
			if werr == nil {
				s.Log.Debug("response received", "host", host, "status", resp.StatusCode,
					"ms", time.Since(tr).Milliseconds())
				// Bodies are read with a per-read idle budget; HEAD carries none.
				if req.Method == http.MethodHead {
					head, complete = nil, true
					werr = nil
				} else {
					ir := &idleReader{r: resp.Body, conn: upstream, idle: bodyIdle}
					head, complete, werr = readPrefetch(ir)
					if werr != nil {
						s.Stats.Stalls.Add(1)
						s.Log.Debug("body stalled", "host", host, "ip", upstreamIP,
							"got", len(head), "err", werr)
					}
				}
				if werr == nil {
					// Only a fully drained body can be closed here: when the
					// prefetch stops at the size cap the rest still has to be
					// streamed below, and closing it would truncate every
					// response larger than prefetchMax to exactly that size.
					if complete {
						resp.Body.Close()
					}
					break
				}
				resp.Body.Close()
			}
		}

		// Dead address: demote it so the follow-up dial skips it.
		if upstreamIP != "" {
			s.st().dns.Note(dstHost, upstreamIP, true)
		}
		upstream.Close()
		if attempt >= 1 {
			s.Log.Warn("upstream failed", "host", host, "err", werr)
			return s.writeError(conn, http.StatusBadGateway, werr)
		}
		var derr error
		upstream, upstreamIP, _, derr = s.dialWithBackup(req.Context(), dstHost, port, scheme, action, matched)
		if derr != nil {
			s.Log.Warn("upstream failed", "host", host, "err", derr)
			return s.writeError(conn, http.StatusBadGateway, derr)
		}
	}

	// Rewrite HTML with the configured scripts before framing. Injection needs
	// the complete body, which prefetch guarantees for responses under 1 MiB;
	// larger ones stream untouched.
	if matched {
		head = s.maybeInject(host, req, action.Rule, resp, head, complete)
		if action.Rule.RequestReplace != nil {
			if resp.Header == nil {
				resp.Header = make(http.Header)
			}
			resp.Header.Set("DS-RequestReplace-Interceptor", reqActions)
			s.Log.Info("requestReplace intercept", "path", matchPath, "actions", reqActions)
		}
		s.applyCacheHeaders(resp, action.Rule)
		s.applyResponseReplace(req, resp, action.Rule, download)
	}
	if isRelay {
		resp.Header.Set("DS-Overwall", relayMark)
	}

	// Frame the body: a fully prefetched body becomes a plain Content-Length
	// response (no chunk re-framing), anything larger streams the remainder
	// under the same idle budget.
	if complete {
		resp.Body = io.NopCloser(bytes.NewReader(head))
		resp.TransferEncoding = nil
		resp.ContentLength = int64(len(head))
		if resp.Header == nil {
			resp.Header = make(http.Header)
		}
		resp.Header.Del("Transfer-Encoding")
		resp.Header.Set("Content-Length", strconv.Itoa(len(head)))
	} else {
		resp.Body = &streamBody{head: head, rest: &idleReader{r: resp.Body, conn: upstream, idle: bodyIdle}}
	}
	defer resp.Body.Close()

	tw := time.Now()
	if err := resp.Write(&countingWriter{w: conn, n: &s.Stats.BytesOut}); err != nil {
		s.Stats.Errors.Add(1)
		return err
	}
	s.Stats.Responses.Add(1)
	s.Stats.NoteResult(host, responseSize(resp, head), time.Since(started), resp.StatusCode >= 400)
	s.Log.Debug("response written", "host", host, "status", resp.StatusCode,
		"bytes", len(head), "ms", time.Since(tw).Milliseconds())

	// Park the socket when the origin left it usable and the body was fully
	// consumed; otherwise the deferred cleanup closes it.
	if keepAlive(resp) {
		_ = upstream.SetDeadline(time.Time{})
		s.pool.put(key, upstream)
		parked = true
	}
	if req.Close {
		return errClose
	}
	return nil
}

const (
	// respHeaderTimeout bounds the wait for the status line + headers.
	respHeaderTimeout = 10 * time.Second
	// bodyIdle aborts a transfer whose body stops producing bytes for this
	// long; without it a blackholed upstream blocks the browser indefinitely.
	bodyIdle = 15 * time.Second
	// prefetchMax is how much of a body is read before the client sees any of
	// it, so a stall can still be recovered by redialing. Larger bodies stream.
	prefetchMax = 1 << 20
)

// idleReader re-arms a read deadline before every Read, so progress keeps the
// transfer alive while a standstill trips it.
type idleReader struct {
	r    io.Reader
	conn net.Conn
	idle time.Duration
}

func (ir *idleReader) Read(p []byte) (int, error) {
	if ir.conn != nil && ir.idle > 0 {
		_ = ir.conn.SetReadDeadline(time.Now().Add(ir.idle))
	}
	return ir.r.Read(p)
}

// streamBody replays the prefetched head, then continues from the live body.
type streamBody struct {
	head []byte
	rest io.Reader
}

func (sb *streamBody) Read(p []byte) (int, error) {
	if len(sb.head) > 0 {
		n := copy(p, sb.head)
		sb.head = sb.head[n:]
		return n, nil
	}
	return sb.rest.Read(p)
}

func (sb *streamBody) Close() error { return nil }

// readPrefetch buffers up to prefetchMax body bytes. It reports complete=true
// when the whole body was read (the reader hit EOF before the cap).
func readPrefetch(r io.Reader) (head []byte, complete bool, err error) {
	buf := make([]byte, 32<<10)
	head = make([]byte, 0, 64<<10)
	for {
		if len(head) >= prefetchMax {
			return head, false, nil
		}
		n, rerr := r.Read(buf)
		if n > 0 {
			head = append(head, buf[:n]...)
		}
		if rerr == io.EOF {
			return head, true, nil
		}
		if rerr != nil {
			return head, false, rerr
		}
	}
}

// dialWithBackup tries the primary target and then each configured backup, as
// the desktop's proxy interceptor does with its backup list.
func (s *Server) dialWithBackup(ctx context.Context, host, port, scheme string, action rules.Action, matched bool) (net.Conn, string, string, error) {
	candidates := []string{host}
	if matched && action.Rule.Proxy != "" {
		for _, b := range action.Rule.Backup {
			if b = hostmatch.Normalize(b); b != "" && b != host {
				candidates = append(candidates, b)
			}
		}
	}
	var lastErr error
	for _, candidate := range candidates {
		conn, ip, err := s.dialUpstream(ctx, candidate, port, scheme, action, matched)
		if err == nil {
			return conn, ip, candidate, nil
		}
		lastErr = err
	}
	return nil, "", host, lastErr
}

// dialUpstream resolves and connects to the origin, applying SNI overrides.//
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

	// The preset list is a hint, not a hard override. Once its addresses are
	// known dead they are skipped for a while: otherwise every request pays the
	// full dial budget before reaching the DNS fallback.
	fresh := !s.st().dns.UsesPreset(host) || !s.presetConsideredDead(host)
	if fresh {
		if up, ip, ok := s.raceAll(ctx, host, port, scheme, action, matched, ips); ok {
			return up, ip, nil
		}
		if s.st().dns.UsesPreset(host) {
			s.markPresetDead(host)
		}
	}

	if alt, aerr := s.st().dns.LookupFallback(ctx, host); aerr == nil && len(alt) > 0 && !sameIPSet(alt, ips) {
		s.Log.Debug("preset addresses failed, retrying via DNS", "host", host, "count", len(alt))
		if up, ip, ok := s.raceAll(ctx, host, port, scheme, action, matched, alt); ok {
			return up, ip, nil
		}
	}

	// Last resort: the preset list we skipped, in case DNS is the broken side.
	// Either way the mark has been proven a guess, so drop it and let the next
	// request lead with the preset again.
	if !fresh {
		s.clearPresetDead(host)
		if up, ip, ok := s.raceAll(ctx, host, port, scheme, action, matched, ips); ok {
			return up, ip, nil
		}
	}
	return nil, "", errors.New("no usable address")
}

// raceAll dials the candidates batch by batch, returning the first usable
// connection. Failures feed the DNS preference so dead addresses sink.
func (s *Server) raceAll(ctx context.Context, host, port, scheme string, action rules.Action, matched bool, ips []net.IP) (net.Conn, string, bool) {
	const batchSize = 6
	for start := 0; start < len(ips); start += batchSize {
		end := start + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		up, connIdx, lastErr := s.raceDial(ctx, host, port, scheme, action, matched, ips, start, end)
		if up != nil {
			s.st().dns.Note(host, ips[connIdx].String(), false)
			return up, ips[connIdx].String(), true
		}
		for i := start; i < end; i++ {
			s.st().dns.Note(host, ips[i].String(), true)
		}
		if lastErr == nil {
			s.Log.Debug("race dial failed", "host", host, "from", start, "to", end)
		}
	}
	return nil, "", false
}

// sameIPSet reports whether two candidate lists hold the same addresses.
func sameIPSet(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, ip := range a {
		seen[ip.String()] = struct{}{}
	}
	for _, ip := range b {
		if _, ok := seen[ip.String()]; !ok {
			return false
		}
	}
	return true
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
			s.st().dns.Note(host, ips[i].String(), true)
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
	verifyHost := host
	if matched {
		sni = strings.TrimSpace(action.Rule.SNI)
		if vh := strings.TrimSpace(action.Rule.VerifyHost); vh != "" {
			verifyHost = vh
		}
	}
	insecure := s.st().insecure[strings.ToLower(net.JoinHostPort(host, port))]

	minVersion, verify := s.upstreamTLS(host)
	cfg := &utls.Config{
		ServerName: host,
		RootCAs:    s.UpstreamRootCAs,
		MinVersion: minVersion,
		NextProtos: []string{"http/1.1"},
	}
	if !verify {
		// "server.setting.verifySsl = false" turns verification off upstream,
		// as the desktop's createHttpsAgent does.
		cfg.InsecureSkipVerify = true
	}
	// Encrypted Client Hello: Go uses the ECHConfigList from the host's HTTPS
	// record, and ECH requires TLS 1.3. A rejected ECH falls back to a plain
	// handshake because no rejection callback is installed.
	if list := s.echConfigList(ctx, host); len(list) > 0 {
		cfg.EncryptedClientHelloConfigList = list
		cfg.MinVersion = tls.VersionTLS13
		s.Log.Debug("ech enabled", "host", host, "bytes", len(list))
	}
	manualVerify := false
	switch {
	case insecure:
		cfg.InsecureSkipVerify = true
	case sni != "" && action.Rule.Proxy == "":
		// A disguised SNI cannot match the origin certificate, and the desktop's
		// sni.js switches to an unverifying agent for exactly this case. Without
		// that, every "sni: baidu.com" rule would fail its chain check.
		cfg.ServerName = sni
		cfg.InsecureSkipVerify = true
	case sni != "" || verifyHost != host:
		// A proxy rule keeps verification, but against the target the origin
		// actually serves (verifyHost, defaulting to that target).
		if sni != "" {
			cfg.ServerName = sni
		}
		cfg.InsecureSkipVerify = true
		manualVerify = true
	}

	// A browser user agent over a Go TLS handshake is exactly the mismatch
	// anti-bot systems look for: Google answered the WebView's searches with
	// /sorry/index while the same URL served fine to a plain client. Speaking
	// Chrome's ClientHello removes the contradiction. The preset advertises h2,
	// which this upstream path cannot speak, so ALPN is pinned to http/1.1.
	uconn := utls.UClient(raw, cfg, utls.HelloChrome_133)
	if spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133); err == nil {
		pinned := false
		for i, ext := range spec.Extensions {
			if _, ok := ext.(*utls.ALPNExtension); ok {
				spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
				pinned = true
				break
			}
		}
		if !pinned {
			spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		}
		uconn = utls.UClient(raw, cfg, utls.HelloCustom)
		if err := uconn.ApplyPreset(&spec); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if !manualVerify {
		return uconn, nil
	}
	if err := verifyFor(tlsStateOf(uconn.ConnectionState()), verifyHost, s.UpstreamRootCAs); err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// tlsStateOf adapts the uTLS handshake state to the standard type the
// verification helper consumes.
func tlsStateOf(s utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:            s.Version,
		HandshakeComplete:  s.HandshakeComplete,
		CipherSuite:        s.CipherSuite,
		NegotiatedProtocol: s.NegotiatedProtocol,
		ServerName:         s.ServerName,
		PeerCertificates:   s.PeerCertificates,
		VerifiedChains:     s.VerifiedChains,
	}
}

// resolve runs the DNS selection for an upstream dial.
func (s *Server) resolve(ctx context.Context, host string, action rules.Action, matched bool) ([]net.IP, error) {
	sniRule := matched && strings.TrimSpace(action.Rule.SNI) != ""
	if sniRule && !s.st().dns.HasDNS(host) {
		ips, err := s.st().dns.LookupForSNI(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", host)
		}
		return ips, nil
	}
	ips, err := s.st().dns.Lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	// DNS64: an IPv6-only network cannot reach the A records of these hosts, so
	// the answers are rewritten into the configured NAT64 prefix.
	if prefix, ok := nat64Prefix(s.st().nat64, host); ok {
		ips = applyNAT64(prefix, ips)
	}
	// cloudflareRoute: dial the preferred endpoint when the host resolves to a
	// Cloudflare address, exactly as the desktop rewrites it at lookup time.
	ips = s.st().cf.apply(ips, host)
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

// startCF runs the cloudflareRoute refresher for the given snapshot.
func (s *Server) startCF(st *state) {
	if st == nil || st.cf == nil {
		return
	}
	s.cfMu.Lock()
	defer s.cfMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	s.cfCancel = cancel
	st.cf.start(ctx)
}

// stopCF ends the refresher tied to the previous snapshot.
func (s *Server) stopCF() {
	s.cfMu.Lock()
	cancel := s.cfCancel
	s.cfCancel = nil
	s.cfMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// responseSize approximates the bytes a response carried, for traffic ranking.
func responseSize(resp *http.Response, head []byte) int {
	if resp != nil && resp.ContentLength > 0 {
		return int(resp.ContentLength)
	}
	return len(head)
}

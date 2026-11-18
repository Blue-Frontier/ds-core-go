package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
	"github.com/Blue-Frontier/ds-core-go/rules"
)

// errNoQuicCandidate means the name resolved to nothing usable.
var errNoQuicCandidate = errors.New("quic: no candidate address")

// quicFailFor is how long a host is left on the TCP path after an HTTP/3
// attempt failed. Without it a user who opted in on a network that filters UDP
// would pay the handshake timeout on every single request.
const quicFailFor = 5 * time.Minute

// quicRecentlyFailed reports whether host is still inside its cool-off window.
func (s *Server) quicRecentlyFailed(host string) bool {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()
	at, ok := s.quicFail[host]
	return ok && time.Since(at) < quicFailFor
}

// noteQuicResult records a failure, or clears the record when it worked.
func (s *Server) noteQuicResult(host string, err error) {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()
	if s.quicFail == nil {
		s.quicFail = make(map[string]time.Time)
	}
	if err == nil {
		delete(s.quicFail, host)
		return
	}
	s.quicFail[host] = time.Now()
}

// quicState is the compiled form of "server.setting.quicUpstream".
type quicState struct {
	enabled bool
	hosts   []string
}

func newQuicState(cfg config.QuicSetting) quicState {
	return quicState{
		enabled: bool(cfg.Enabled) && len(cfg.Hosts) > 0,
		hosts:   cfg.Hosts,
	}
}

// allows reports whether the HTTP/3 path may be used for host.
func (q quicState) allows(host string) bool {
	if !q.enabled {
		return false
	}
	for _, pattern := range q.hosts {
		if hostmatch.Match(pattern, host) {
			return true
		}
	}
	return false
}

// quicCandidatesKey carries the addresses the kernel resolved for a host into
// Transport.Dial. Without it http3 resolves the name itself, and on a network
// that poisons DNS it then dials an address that answers nothing — which is
// exactly how the first device test failed.
type quicCandidatesKey struct{}

func withQuicCandidates(ctx context.Context, ips []net.IP) context.Context {
	if len(ips) == 0 {
		return ctx
	}
	return context.WithValue(ctx, quicCandidatesKey{}, ips)
}

// quicCandidates resolves host the same way the TCP path does, so both
// transports agree on where a name points.
func (s *Server) quicCandidates(ctx context.Context, host string, action rules.Action, matched bool) []net.IP {
	if ip := net.ParseIP(hostmatch.Normalize(host)); ip != nil {
		return []net.IP{ip}
	}
	ips, err := s.resolve(ctx, host, action, matched)
	if err != nil {
		s.Log.Debug("quic resolve failed", "host", host, "err", err)
		return nil
	}
	return ips
}

// quicTransport returns the shared HTTP/3 transport, creating it once.
//
// The transport is process-wide on purpose: a QUIC connection is expensive to
// set up, and reusing it is the whole point of the HTTP/3 path. Certificate
// verification follows the same switch as the TCP path.
func (s *Server) quicTransport(insecure bool) *http3.Transport {
	s.quicMu.Lock()
	defer s.quicMu.Unlock()
	if s.quicTr != nil {
		return s.quicTr
	}
	s.quicTr = &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            s.UpstreamRootCAs,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: insecure,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
		},
	}
	s.quicTr.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		ips, _ := ctx.Value(quicCandidatesKey{}).([]net.IP)
		if len(ips) == 0 {
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// The certificate still has to be checked against the name the client
		// asked for, not against the address that was dialed.
		cfgTLS := tlsCfg.Clone()
		cfgTLS.ServerName = host
		var last error
		for _, ip := range ips {
			conn, derr := quic.DialAddr(ctx, net.JoinHostPort(ip.String(), port), cfgTLS, cfg)
			if derr == nil {
				return conn, nil
			}
			last = derr
		}
		if last == nil {
			last = errNoQuicCandidate
		}
		return nil, last
	}
	return s.quicTr
}

// serveQUIC fetches the request over HTTP/3 and writes the response to conn.
//
// It reports handled=false when the caller should fall back to the TCP path, so
// a network that filters UDP simply keeps working the way it did. Only a
// response that was fully written counts as handled: a half-written reply
// cannot be retried, but nothing was written yet when RoundTrip fails.
func (s *Server) serveQUIC(
	conn net.Conn,
	req, out *http.Request,
	host string,
	action rules.Action,
	matched bool,
	reqActions string,
	download bool,
	insecure bool,
	started time.Time,
) (bool, error) {
	ctx, cancel := context.WithTimeout(req.Context(), s.requestTimeout(host))
	defer cancel()

	// The transport must dial the addresses the kernel resolved, not whatever
	// the platform resolver returns for this name.
	ctx = withQuicCandidates(ctx, s.quicCandidates(ctx, host, action, matched))

	// RoundTrip needs an absolute https URL and no RequestURI; the tunnel-built
	// request already has both, but the body must be readable exactly once.
	hreq := out.Clone(ctx)
	hreq.URL.Scheme = "https"
	hreq.RequestURI = ""

	resp, err := s.quicTransport(insecure).RoundTrip(hreq)
	s.noteQuicResult(host, err)
	if err != nil {
		s.Log.Debug("quic upstream failed, falling back", "host", host, "err", err)
		return false, nil
	}
	defer resp.Body.Close()

	// Prefetch the same way the TCP path does, so injection and framing behave
	// identically whichever transport carried the response.
	var head []byte
	complete := false
	if req.Method == http.MethodHead {
		complete = true
	} else if resp.ContentLength >= 0 && resp.ContentLength <= prefetchMax {
		head, err = io.ReadAll(resp.Body)
		if err != nil {
			s.Stats.Stalls.Add(1)
			s.Log.Debug("quic body stalled", "host", host, "got", len(head), "err", err)
			return false, nil
		}
		complete = true
	} else {
		buf := make([]byte, prefetchMax)
		n, rerr := io.ReadFull(resp.Body, buf)
		if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
			s.Stats.Stalls.Add(1)
			return false, nil
		}
		head = buf[:n]
	}

	if matched {
		head = s.maybeInject(host, req, action.Rule, resp, head, complete)
		if action.Rule.RequestReplace != nil {
			if resp.Header == nil {
				resp.Header = make(http.Header)
			}
			resp.Header.Set("DS-RequestReplace-Interceptor", reqActions)
		}
		s.applyCacheHeaders(resp, action.Rule)
		s.applyResponseReplace(req, resp, action.Rule, download)
	}

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
		resp.Body = &streamBody{head: head, rest: resp.Body}
	}
	resp.Header.Set("DS-Upstream", "h3")

	if err := resp.Write(&countingWriter{w: conn, n: &s.Stats.BytesOut}); err != nil {
		s.Stats.Errors.Add(1)
		return true, err
	}
	s.Stats.Responses.Add(1)
	s.Stats.NoteResult(host, responseSize(resp, head), time.Since(started), resp.StatusCode >= 400)
	s.Log.Debug("response written (h3)", "host", host, "status", resp.StatusCode, "bytes", len(head))
	return true, nil
}

// serveQUICH2 is serveQUIC for the HTTP/2 path, which answers through a
// ResponseWriter instead of a raw connection.
func (s *Server) serveQUICH2(
	w http.ResponseWriter,
	req, out *http.Request,
	host string,
	action rules.Action,
	matched bool,
	reqActions string,
	download bool,
	insecure bool,
	started time.Time,
) bool {
	ctx, cancel := context.WithTimeout(req.Context(), s.requestTimeout(host))
	defer cancel()

	ctx = withQuicCandidates(ctx, s.quicCandidates(ctx, host, action, matched))

	hreq := out.Clone(ctx)
	hreq.URL.Scheme = "https"
	hreq.RequestURI = ""

	resp, err := s.quicTransport(insecure).RoundTrip(hreq)
	s.noteQuicResult(host, err)
	if err != nil {
		s.Log.Debug("quic upstream failed over h2, falling back", "host", host, "err", err)
		return false
	}
	defer resp.Body.Close()

	var head []byte
	complete := false
	if req.Method == http.MethodHead {
		complete = true
	} else if resp.ContentLength >= 0 && resp.ContentLength <= prefetchMax {
		head, err = io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		complete = true
	}

	if matched {
		head = s.maybeInject(host, req, action.Rule, resp, head, complete)
		if action.Rule.RequestReplace != nil {
			if resp.Header == nil {
				resp.Header = make(http.Header)
			}
			resp.Header.Set("DS-RequestReplace-Interceptor", reqActions)
		}
		s.applyCacheHeaders(resp, action.Rule)
		s.applyResponseReplace(req, resp, action.Rule, download)
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Set("DS-Upstream", "h3")
	w.WriteHeader(resp.StatusCode)
	if len(head) > 0 {
		if _, werr := w.Write(head); werr != nil {
			s.Stats.Errors.Add(1)
			return true
		}
	}
	if !complete {
		if _, werr := io.Copy(w, resp.Body); werr != nil {
			s.Stats.Errors.Add(1)
		}
	}
	s.Stats.Responses.Add(1)
	s.Stats.NoteResult(host, responseSize(resp, head), time.Since(started), resp.StatusCode >= 400)
	s.Log.Debug("response written (h3/h2 path)", "host", host, "status", resp.StatusCode, "bytes", len(head))
	return true
}

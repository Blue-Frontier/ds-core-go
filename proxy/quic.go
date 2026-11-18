package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
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

	// RoundTrip needs an absolute https URL and no RequestURI; the tunnel-built
	// request already has both, but the body must be readable exactly once.
	hreq := out.Clone(ctx)
	hreq.URL.Scheme = "https"
	hreq.RequestURI = ""

	resp, err := s.quicTransport(insecure).RoundTrip(hreq)
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

	hreq := out.Clone(ctx)
	hreq.URL.Scheme = "https"
	hreq.RequestURI = ""

	resp, err := s.quicTransport(insecure).RoundTrip(hreq)
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

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/Blue-Frontier/ds-core-go/hostmatch"
	"github.com/Blue-Frontier/ds-core-go/rules"
)

// serveH2 terminates an HTTP/2 connection from the client. The desktop kernel
// does the same (node:http2 with allowHTTP1), so browsers negotiate h2 here.
func (s *Server) serveH2(conn net.Conn, host, port, scheme string) {
	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Handler: &h2Handler{s: s, host: host, port: port, scheme: scheme},
	})
}

// h2Handler proxies each HTTP/2 stream through the same rule engine as the
// HTTP/1.1 path.
type h2Handler struct {
	s      *Server
	host   string
	port   string
	scheme string
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s := h.s
	start := time.Now()
	host := h.host
	if req.Host != "" {
		if hh, _, err := net.SplitHostPort(req.Host); err == nil {
			host = hh
		} else {
			host = req.Host
		}
	}
	if strings.Contains(host, ":") {
		host = hostmatch.Normalize(host)
	}

	path := "/"
	if req.URL != nil && req.URL.Path != "" {
		path = req.URL.Path
	}
	matchPath := path
	if req.URL != nil {
		matchPath = req.URL.RequestURI()
	}
	s.Stats.Requests.Add(1)
	s.Stats.NoteHost(host)
	s.Log.Debug("request h2", "method", req.Method, "host", host, "path", path)

	// The kernel's own endpoints answer before any rule, as on the h1 path.
	if path == statsPath {
		body := s.statsPayload()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
		return
	}
	if body, ok := s.scriptPayload(path); ok {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86401, immutable")
		w.Header().Set("DS-Middleware", "ds_script")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		s.Stats.Responses.Add(1)
		return
	}

	var action rules.Action
	matched := false
	if s.st().interceptEnabled {
		action, matched = s.st().table.Match(host, matchPath)
	}

	if matched {
		// Local answers first: options/success/abort, then the cache window.
		if status, headers, body, ok := localResponse(req, action.Rule); ok {
			copyHeader(w.Header(), headers)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(status)
			if len(body) > 0 {
				_, _ = w.Write(body)
			}
			return
		}
		if maxAge, ok := cacheHit(req, action.Rule); ok {
			w.Header().Set("DS-Interceptor", fmt.Sprintf("cache: %d", maxAge))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if action.Rule.Redirect != "" {
			w.Header().Set("Location", "https://"+action.Rule.Redirect+matchPath)
			w.WriteHeader(http.StatusFound)
			return
		}
	}

	dstHost := host
	if matched && action.Rule.Proxy != "" {
		dstHost = hostmatch.Normalize(action.Rule.Proxy)
	}
	relay, relayMark, isRelay := s.overwallFor(host)
	if isRelay && h.scheme == "https" {
		dstHost = relay.domain
		h.port = strconv.Itoa(relay.port)
	} else {
		isRelay = false
	}

	out := req.Clone(req.Context())
	out.URL.Scheme = h.scheme
	out.URL.Host = net.JoinHostPort(dstHost, h.port)
	out.RequestURI = ""
	// Keep-alive upstream so the pool can serve the next stream.
	out.Close = false
	stripHopHeaders(out.Header)
	if isRelay {
		out.URL.Path = overwallPath(relay, host, req.URL.Path)
		out.Host = dstHost
		out.Header.Set("dspassword", relay.password)
	}

	reqActions, download := "", false
	if matched && action.Rule.RequestReplace != nil {
		reqActions, download = s.applyRequestReplace(out, action.Rule)
		out.RequestURI = ""
	}

	insecure := s.st().insecure[strings.ToLower(net.JoinHostPort(dstHost, h.port))]
	key := upstreamKey(dstHost, h.port, h.scheme, action, matched, insecure)

	var upstream net.Conn
	var upstreamIP string
	reused := false
	if cached := s.pool.get(key); cached != nil {
		upstream, reused = cached, true
		s.Log.Debug("pool hit h2", "host", host, "key", key)
	} else {
		var usedHost string
		var err error
		upstream, upstreamIP, usedHost, err = s.dialWithBackup(req.Context(), dstHost, h.port, h.scheme, action, matched)
		if err != nil {
			s.Log.Warn("upstream failed", "host", host, "err", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if usedHost != dstHost {
			dstHost = usedHost
			out.URL.Host = net.JoinHostPort(usedHost, h.port)
			out.Host = usedHost
		}
	}

	parked := false
	defer func() {
		if !parked && upstream != nil {
			upstream.Close()
		}
	}()

	resp, head, complete, err := s.roundTrip(upstream, upstreamIP, out, req, dstHost, h.port, action, matched)
	if err != nil && reused {
		// A parked socket may have been reaped while idle; dial once more.
		s.Log.Debug("pooled connection stale h2", "host", host, "err", err)
		upstream.Close()
		var usedHost string
		upstream, upstreamIP, usedHost, err = s.dialWithBackup(req.Context(), dstHost, h.port, h.scheme, action, matched)
		if err == nil {
			if usedHost != dstHost {
				dstHost = usedHost
				out.URL.Host = net.JoinHostPort(usedHost, h.port)
				out.Host = usedHost
			}
			resp, head, complete, err = s.roundTrip(upstream, upstreamIP, out, req, dstHost, h.port, action, matched)
		}
	}
	if err != nil {
		s.Log.Warn("upstream failed", "host", host, "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if matched {
		head = s.maybeInject(host, req, action.Rule, resp, head, complete)
		if action.Rule.RequestReplace != nil {
			resp.Header.Set("DS-RequestReplace-Interceptor", reqActions)
		}
		s.applyCacheHeaders(resp, action.Rule)
		s.applyResponseReplace(req, resp, action.Rule, download)
	}
	if isRelay {
		resp.Header.Set("DS-Overwall", relayMark)
	}

	// HTTP/2 forbids the connection-specific headers a h1 origin may send.
	for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade"} {
		resp.Header.Del(key)
	}
	copyHeader(w.Header(), resp.Header)
	if complete {
		w.Header().Set("Content-Length", strconv.Itoa(len(head)))
	} else {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)
	if len(head) > 0 {
		if _, err := w.Write(head); err != nil {
			s.Stats.Errors.Add(1)
			return
		}
	}
	if !complete {
		_, _ = io.Copy(w, &idleReader{r: resp.Body, conn: upstream, idle: bodyIdle})
	}
	s.Stats.Responses.Add(1)
	s.Stats.NoteResult(host, responseSize(resp, head), time.Since(start), resp.StatusCode >= 400)

	// Park the upstream socket for the next stream when the origin allows it.
	if keepAlive(resp) {
		_ = upstream.SetDeadline(time.Time{})
		s.pool.put(key, upstream)
		parked = true
	}
}

// roundTrip writes the request and reads the response, retrying once on a dead
// address so an HTTP/2 stream gets the same resilience as HTTP/1.1.
func (s *Server) roundTrip(upstream net.Conn, upstreamIP string, out, req *http.Request, dstHost, port string, action rulesAction, matched bool) (*http.Response, []byte, bool, error) {
	upstream.SetDeadline(time.Time{})
	if err := out.Write(upstream); err != nil {
		return nil, nil, false, err
	}
	upstream.SetReadDeadline(time.Now().Add(s.requestTimeout(dstHost)))
	resp, err := http.ReadResponse(bufio.NewReader(upstream), out)
	if err != nil {
		return nil, nil, false, err
	}
	if req.Method == http.MethodHead {
		resp.Body.Close()
		return resp, nil, true, nil
	}
	head, complete, err := readPrefetch(&idleReader{r: resp.Body, conn: upstream, idle: bodyIdle})
	if err != nil {
		s.Stats.Stalls.Add(1)
		resp.Body.Close()
		return nil, nil, false, err
	}
	if complete {
		resp.Body.Close()
	}
	return resp, head, complete, nil
}

// rulesAction aliases the compiled action so the helper signature stays short.
type rulesAction = rules.Action

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

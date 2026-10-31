package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/scriptstore"
)

// scriptPathPrefix is where injected tags point; the kernel answers it itself
// so the script stays same-origin and passes the page's CSP after rewrite.
const scriptPathPrefix = "/____ds_script____/"

var (
	cspScriptSrcRe = regexp.MustCompile(`(?i)(script-src(?:-elem)?)(\s+)([^;]*)`)
	cspNonceRe     = regexp.MustCompile(`(?i)nonce-([^'"\s;]+)`)
)

// prefetchScripts warms the store so the first injected page does not stall on
// a script download. Failures are only logged: the tag still points at the
// kernel and a later request retries.
func prefetchScripts(store *scriptstore.Store, log interface {
	Warn(string, ...any)
}) {
	for _, key := range store.Keys() {
		if store.Has(key) {
			continue
		}
		if _, err := store.Get(key); err != nil {
			log.Warn("script prefetch failed", "key", key, "err", err)
		}
	}
}

// prepareScripts deep-copies the intercept table, replacing absolute script
// URLs with store keys so injection can reference the kernel's own path. The
// parsed configuration is left untouched.
func prepareScripts(src map[string]map[string]config.Rule, store *scriptstore.Store) map[string]map[string]config.Rule {
	out := make(map[string]map[string]config.Rule, len(src))
	for host, paths := range src {
		np := make(map[string]config.Rule, len(paths))
		for pat, rule := range paths {
			r := rule
			if len(rule.Script) > 0 {
				r.Script = rule.Script.Clone()
				for i, s := range r.Script {
					if isAbsURL(s) {
						r.Script[i] = store.RegisterURL(s)
					}
				}
			}
			if isAbsURL(rule.TampermonkeyScript) {
				r.TampermonkeyScript = store.RegisterURL(rule.TampermonkeyScript)
			}
			np[pat] = r
		}
		out[host] = np
	}
	return out
}

func isAbsURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// serveScript answers /____ds_script____/<key> from the store. It reports
// whether it handled the request.
func (s *Server) serveScript(conn net.Conn, path string) bool {
	if body, ok := s.scriptPayload(path); ok {
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\n"+
				"Content-Type: application/javascript; charset=utf-8\r\n"+
				"Content-Length: %d\r\n"+
				"Cache-Control: public, max-age=86401, immutable\r\n"+
				"DS-Middleware: ds_script\r\n"+
				"Connection: keep-alive\r\n\r\n", len(body))
		_, _ = conn.Write(body)
		s.Stats.Responses.Add(1)
		return true
	}
	return false
}

// scriptPayload returns the stored JavaScript for a kernel script URL, if any.
func (s *Server) scriptPayload(path string) ([]byte, bool) {
	if !strings.HasPrefix(path, scriptPathPrefix) {
		return nil, false
	}
	key := strings.TrimPrefix(path, scriptPathPrefix)
	if i := strings.IndexByte(key, '?'); i >= 0 {
		key = key[:i]
	}
	if s.Scripts != nil {
		if body, err := s.Scripts.Get(key); err == nil {
			return body, true
		}
	}
	return nil, false
}

// scriptRef resolves a configured script reference into the src to inject:
// URLs and site-relative paths are used verbatim, store keys go through the
// kernel's prefix.
func (s *Server) scriptRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	if strings.Contains(ref, "/") {
		return ref, true
	}
	if s.Scripts != nil && (s.Scripts.Registered(ref) || s.Scripts.Has(ref)) {
		return scriptPathPrefix + ref, true
	}
	return "", false
}

func scriptTag(src, nonce string) string {
	return `<script crossorigin="anonymous" defer="defer" type="application/javascript" src="` +
		html.EscapeString(src) + `"` + nonce + `></script>` + "\r\n\t"
}

// buildTags mirrors the desktop script interceptor: the userscript runtime
// first, then the configured scripts, plus GitHub's fake asset which keeps its
// asynchronous loader from deriving a wrong base path.
func (s *Server) buildTags(host string, rule config.Rule, nonce string) string {
	var b strings.Builder
	if tm := strings.TrimSpace(rule.TampermonkeyScript); tm != "" {
		if src, ok := s.scriptRef(tm); ok {
			b.WriteString(scriptTag(src, nonce))
		}
	}
	for _, sc := range rule.Script {
		if sc == "global" || sc == "tampermonkey" {
			continue
		}
		if src, ok := s.scriptRef(sc); ok {
			b.WriteString(scriptTag(src, nonce))
		}
	}
	if host == "github.com" {
		b.WriteString(scriptTag("https://github.githubassets.com/assets/fakefile.js", nonce))
	}
	return b.String()
}

// cspWithSelf widens script-src (or script-src-elem) with 'self' so the
// same-origin injected tags are allowed, prepending the directive when the
// policy only has default-src.
func cspWithSelf(policy string) string {
	loc := cspScriptSrcRe.FindStringSubmatchIndex(policy)
	if loc == nil {
		return "script-src 'self'; " + policy
	}
	// Group layout is (whole)(directive)(whitespace)(value); insert straight
	// after the directive name so the separator is never lost.
	if strings.Contains(policy[loc[6]:loc[7]], "'self'") {
		return policy
	}
	nameEnd := loc[3]
	return policy[:nameEnd] + " 'self'" + policy[nameEnd:]
}

func cspNonce(policy string) string {
	m := cspNonceRe.FindStringSubmatch(policy)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func decodeBody(enc string, b []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return b, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			defer zr.Close()
			return io.ReadAll(zr)
		}
		fr := flate.NewReader(bytes.NewReader(b))
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", enc)
	}
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// insertBeforeTag splices tags ahead of the first </head> (then </body>).
func insertBeforeTag(body []byte, tags string) []byte {
	lower := bytes.ToLower(body)
	for _, tag := range []string{"</head>", "</body>"} {
		if i := bytes.Index(lower, []byte(tag)); i >= 0 {
			out := make([]byte, 0, len(body)+len(tags))
			out = append(out, body[:i]...)
			out = append(out, []byte(tags)...)
			out = append(out, body[i:]...)
			return out
		}
	}
	return body
}

// maybeInject rewrites an HTML response body with the configured scripts. The
// body must be fully prefetched; larger responses are streamed and skipped.
func (s *Server) maybeInject(host string, req *http.Request, rule config.Rule, resp *http.Response, body []byte, complete bool) []byte {
	if s.Scripts == nil || !complete || len(body) == 0 {
		return body
	}
	// "server.setting.script.enabled = false" turns the injection middleware
	// off, exactly like the desktop's createRequestHandler gate.
	if st := s.st(); st != nil && !st.scriptEnabled {
		return body
	}
	if len(rule.Script) == 0 && strings.TrimSpace(rule.TampermonkeyScript) == "" {
		return body
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml+xml") {
		return body
	}
	if host == "github.com" && strings.EqualFold(req.Header.Get("turbo-frame"), "repo-content-turbo-frame") {
		return body
	}

	enc := resp.Header.Get("Content-Encoding")
	plain, err := decodeBody(enc, body)
	if err != nil {
		s.Log.Warn("script inject skipped", "host", host, "err", err)
		return body
	}

	nonce := ""
	for _, csp := range resp.Header.Values("Content-Security-Policy") {
		if n := cspNonce(csp); n != "" {
			nonce = ` nonce="` + n + `"`
			break
		}
	}
	tags := s.buildTags(host, rule, nonce)
	if tags == "" {
		return body
	}

	injected := insertBeforeTag(plain, tags)
	if len(injected) == len(plain) {
		return body // no </head> or </body>: leave it alone
	}

	if csps := resp.Header.Values("Content-Security-Policy"); len(csps) > 0 {
		resp.Header.Del("Content-Security-Policy")
		for _, c := range csps {
			resp.Header.Add("Content-Security-Policy", cspWithSelf(c))
		}
	}

	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip", "x-gzip", "deflate":
		injected = gzipBytes(injected)
		resp.Header.Set("Content-Encoding", "gzip")
	default:
		resp.Header.Del("Content-Encoding")
	}

	s.Stats.Injected.Add(1)
	s.Log.Debug("script injected", "host", host, "tags", strings.Count(tags, "<script"))
	return injected
}

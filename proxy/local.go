package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// headerRemove is the desktop's marker for "delete this header"; JSON5 cannot
// carry a null value, so the configuration uses this string instead.
const headerRemove = "[remove]"

// localResponse builds the reply an abort, success or CORS preflight rule
// produces. It is shared by the HTTP/1.1 and HTTP/2 paths so both answer
// identically. The order follows the desktop interceptor priorities:
// options (101), success (102), abort (103).
func localResponse(req *http.Request, rule config.Rule) (int, http.Header, []byte, bool) {
	preflight := bool(rule.Options) && req.Method == http.MethodOptions && req.Header.Get("Origin") != ""
	switch {
	case preflight:
		status, h, body := preflightResponse(req, rule)
		return status, h, body, true
	case rule.Success != nil:
		status, h, body := syntheticResponse(req, rule.Success, http.StatusOK, "success", rule.MaxAge())
		return status, h, body, true
	case rule.Abort != nil:
		status, h, body := syntheticResponse(req, rule.Abort, http.StatusForbidden, "abort", 0)
		return status, h, body, true
	}
	return 0, nil, nil, false
}

// serveLocal answers a request without contacting the origin.
func (s *Server) serveLocal(conn net.Conn, req *http.Request, rule config.Rule) bool {
	status, headers, body, ok := localResponse(req, rule)
	if !ok {
		return false
	}
	// The origin never sees a locally answered request, but its body has to be
	// consumed so the connection can carry the next one.
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
	}
	_ = writeSyntheticResponse(conn, status, flatten(headers), string(body))
	s.Log.Info("local intercept", "kind", headers.Get("DS-Interceptor"),
		"path", requestURI(req), "status", status)
	return true
}

// preflightResponse answers a CORS preflight with the origin echoed back.
func preflightResponse(req *http.Request, rule config.Rule) (int, http.Header, []byte) {
	allowHeaders := req.Header.Get("Access-Control-Request-Headers")
	if allowHeaders == "" {
		allowHeaders = listOr(rule.OptionsAllowHeaders, "*")
	}
	allowMethods := req.Header.Get("Access-Control-Request-Method")
	if allowMethods == "" {
		allowMethods = listOr(rule.OptionsAllowMethods, "GET,POST,PUT,DELETE,HEAD,OPTIONS,PATCH")
	}
	maxAge := rule.OptionsMaxAge
	if maxAge <= 0 {
		maxAge = 2592000 // the desktop default: one month
	}

	h := make(http.Header)
	h.Set("DS-Interceptor", "options")
	h.Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
	h.Set("Access-Control-Allow-Headers", allowHeaders)
	h.Set("Access-Control-Allow-Methods", allowMethods)
	h.Set("Access-Control-Max-Age", strconv.Itoa(maxAge))
	h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	h.Set("Vary", "Origin")
	if rule.OptionsCredentials == nil || *rule.OptionsCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	return http.StatusOK, h, nil
}

// syntheticResponse renders an abort/success reply.
func syntheticResponse(req *http.Request, act *config.Synthetic, defStatus int, kind string, maxAge int) (int, http.Header, []byte) {
	status := act.Status
	if status == 0 {
		status = defStatus
	}

	h := make(http.Header)
	for k, v := range act.Headers {
		h.Set(k, v)
	}
	h.Set("DS-Interceptor", kind)

	body := firstNonEmpty(act.HTML, act.JSON, act.Script, act.CSS, act.Text, act.Body)
	if body == "" && status != http.StatusNoContent {
		body = fmt.Sprintf(
			"DevSidecar %d: Request %s.\n\n  This request is matched by %s intercept.\n\n"+
				"  因配置%s拦截器，本请求直接返回%d。\n",
			status, kind, kind, kind, status)
	}

	if status != http.StatusNoContent {
		if h.Get("Content-Type") == "" {
			h.Set("Content-Type", contentTypeFor(act))
		}
		if ct := h.Get("Content-Type"); ct != "" && !strings.Contains(ct, "charset") {
			h.Set("Content-Type", ct+"; charset=utf-8")
		}
	}

	// A stubbed response inherits the rule's cache lifetime (desktop simpleHandle).
	if maxAge > 0 {
		h.Set("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", maxAge+1))
	}

	// Browsers reject credentialed cross-origin reads without the matching
	// allow-origin header, so echo the caller's origin when none is configured.
	if origin := req.Header.Get("Origin"); origin != "" {
		if h.Get("Access-Control-Allow-Origin") == "" {
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Origin", origin)
		}
	}

	if status == http.StatusNoContent {
		body = ""
	}
	return status, h, []byte(body)
}

// writeSyntheticResponse serialises a complete HTTP/1.1 response onto conn.
func writeSyntheticResponse(conn net.Conn, status int, headers map[string]string, body string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if status != http.StatusNoContent && status != http.StatusNotModified {
		headers["Content-Length"] = strconv.Itoa(len(body))
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, headers[k])
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	_, err := io.WriteString(conn, b.String())
	return err
}

// flatten reduces a header map to its first value per key, for the raw writer.
func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func contentTypeFor(act *config.Synthetic) string {
	switch {
	case act.HTML != "":
		return "text/html"
	case act.JSON != "":
		return "application/json"
	case act.Script != "":
		return "application/javascript"
	case act.CSS != "":
		return "text/css"
	default:
		return "text/plain"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// listOr joins a configured list, falling back to def when it is empty.
func listOr(list []string, def string) string {
	if len(list) == 0 {
		return def
	}
	return strings.Join(list, ",")
}

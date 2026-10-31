package proxy

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

var maxAgeRe = regexp.MustCompile(`(?i)max-age=(\d+)`)

// serveCached answers a conditional GET while the rule's cache window is open.
// The desktop kernel does not keep a local store: it trusts If-Modified-Since
// and replies 304, leaving the body to the browser cache.
// cacheHit reports whether a conditional GET is still inside the cache window,
// returning that window in seconds. Shared by the HTTP/1.1 and HTTP/2 paths.
func cacheHit(req *http.Request, rule config.Rule) (int, bool) {
	if req.Method != http.MethodGet {
		return 0, false
	}
	maxAge := rule.MaxAge()
	if maxAge <= 0 {
		return 0, false
	}
	if cacheDisabled(req.Header) {
		return 0, false
	}
	lastModified, ok := parseIfModifiedSince(req.Header.Get("If-Modified-Since"))
	if !ok {
		return 0, false
	}
	if time.Since(lastModified) > time.Duration(maxAge)*time.Second {
		return 0, false
	}
	return maxAge, true
}

func (s *Server) serveCached(conn net.Conn, req *http.Request, rule config.Rule) bool {
	maxAge, ok := cacheHit(req, rule)
	if !ok {
		return false
	}
	headers := map[string]string{"DS-Interceptor": fmt.Sprintf("cache: %d", maxAge)}
	_ = writeSyntheticResponse(conn, http.StatusNotModified, headers, "")
	s.Log.Info("cache intercept", "path", requestURI(req), "maxAge", maxAge)
	return true
}

// applyCacheHeaders rewrites the cache headers of a cacheable response.
func (s *Server) applyCacheHeaders(resp *http.Response, rule config.Rule) {
	maxAge := rule.MaxAge()
	if maxAge <= 0 || resp.StatusCode < rule.MinStatusCode() || resp.StatusCode > rule.MaxStatusCode() {
		return
	}
	if excludedStatus(resp.StatusCode, rule.ExcludeStatus) {
		return
	}

	immutable := rule.Immutable == nil || *rule.Immutable

	// A longer origin lifetime wins when immutable is on; otherwise the desktop
	// leaves the response alone and says so.
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		if m := maxAgeRe.FindStringSubmatch(cc); m != nil {
			if origin, err := strconv.Atoi(m[1]); err == nil && origin > maxAge {
				if immutable && !strings.Contains(cc, "immutable") {
					maxAge = origin
				} else {
					resp.Header.Set("DS-Cache-Response-Interceptor",
						fmt.Sprintf("skip: %d > %d", origin, maxAge))
					return
				}
			}
		}
	}

	now := time.Now()
	typ := rule.ControlType
	if typ == "" {
		typ = "public"
	}
	suffix := ""
	if immutable {
		suffix = ", immutable"
	}
	resp.Header.Set("Cache-Control", fmt.Sprintf("%s, max-age=%d%s", typ, maxAge+1, suffix))
	resp.Header.Set("Last-Modified", now.UTC().Format(http.TimeFormat))
	resp.Header.Set("Expires", now.Add(time.Duration(maxAge)*time.Second).UTC().Format(http.TimeFormat))
	resp.Header.Set("DS-Cache-Response-Interceptor", strconv.Itoa(maxAge))
}

// cacheDisabled reports a client request that forbids caching.
func cacheDisabled(h http.Header) bool {
	blocked := func(v string) bool {
		v = strings.ToLower(v)
		return strings.Contains(v, "no-cache") || strings.Contains(v, "no-store")
	}
	return blocked(h.Get("Cache-Control")) || blocked(h.Get("Pragma"))
}

// parseIfModifiedSince accepts both an HTTP date and a plain millisecond stamp,
// mirroring the desktop parser.
func parseIfModifiedSince(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.UnixMilli(ms), true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func excludedStatus(status int, list []string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == strconv.Itoa(status) {
			return true
		}
	}
	return false
}

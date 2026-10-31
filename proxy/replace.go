package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
)

var (
	dsDownloadCheck = regexp.MustCompile(`(?i)DS_DOWNLOAD`)
	dsDownloadStrip = regexp.MustCompile(`(?i)[?&/]?DS_DOWNLOAD(=[^?&/]+)?$`)
)

// applyRequestReplace mirrors the desktop requestReplace interceptor: header
// overrides, plus stripping the "?DS_DOWNLOAD" marker before the origin sees
// it. It returns the action list and whether a download was requested.
func (s *Server) applyRequestReplace(out *http.Request, rule config.Rule) (string, bool) {
	act := rule.RequestReplace
	actions := ""
	for k, v := range act.Headers {
		val := headerValue(v)
		if val == headerRemove {
			if strings.EqualFold(k, "User-Agent") {
				// Request.Write re-adds a default User-Agent when the header is
				// absent; a present-but-empty value is what keeps it off the wire.
				out.Header["User-Agent"] = []string{""}
			} else {
				out.Header.Del(k)
			}
			continue
		}
		out.Header.Set(k, val)
	}
	if len(act.Headers) > 0 {
		actions = "headers"
	}

	download := false
	if act.DoDownload {
		full := out.URL.RequestURI()
		if dsDownloadCheck.MatchString(full) {
			if loc := dsDownloadStrip.FindStringIndex(full); loc != nil {
				full = full[:loc[0]] + full[loc[1]:]
				if u, err := url.ParseRequestURI(full); err == nil {
					out.URL.Path, out.URL.RawQuery = u.Path, u.RawQuery
				}
			}
			download = true
			if actions != "" {
				actions += ","
			}
			actions += "path:remove-DS_DOWNLOAD"
		}
	}
	return actions, download
}

// applyResponseReplace mirrors the desktop responseReplace interceptor: it only
// acts on 200 responses, rewrites or drops headers, and can turn the response
// into a download. download reports a "?DS_DOWNLOAD" request seen upstream.
func (s *Server) applyResponseReplace(req *http.Request, resp *http.Response, rule config.Rule, download bool) {
	act := rule.ResponseReplace
	if act == nil || resp.StatusCode != http.StatusOK {
		return
	}

	replace := make(map[string]string, len(act.Headers)+4)
	for k, v := range act.Headers {
		replace[strings.ToLower(k)] = headerValue(v)
	}

	actions := ""
	if act.DoDownload || download {
		filename := filenameFromPath(req.URL.Path)
		replace["content-disposition"] = `attachment; filename="` + filename + `"`
		if _, ok := replace["content-type"]; !ok {
			replace["content-type"] = "application/octet-stream"
		}
		// Without an explicit cacheDays the download must not be cached.
		if rule.CacheDays <= 0 {
			replace["cache-control"] = headerRemove
			replace["last-modified"] = headerRemove
			replace["expires"] = headerRemove
		}
		actions = "download:" + filename
	}

	if applyHeaders(resp.Header, replace) {
		if actions != "" {
			actions += ","
		}
		actions += "headers"
	}
	if actions != "" {
		resp.Header.Set("DS-ResponseReplace-Interceptor", actions)
		s.Log.Info("response intercept", "path", requestURI(req), "actions", actions)
	}
}

// applyHeaders sets or deletes headers, reporting whether anything changed.
func applyHeaders(h http.Header, replace map[string]string) bool {
	changed := false
	for k, v := range replace {
		if v == headerRemove {
			if len(h.Values(k)) > 0 {
				h.Del(k)
				changed = true
			}
			continue
		}
		if cur := h.Values(k); len(cur) == 1 && cur[0] == v {
			continue
		}
		h.Set(k, v)
		changed = true
	}
	return changed
}

// filenameFromPath takes the last path segment, as the desktop does.
func filenameFromPath(p string) string {
	trimmed := strings.TrimSuffix(p, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	if trimmed == "" {
		return "UNKNOWN_FILENAME"
	}
	return trimmed
}

// headerValue renders a configured header value the way Node would coerce it.
func headerValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

package proxy

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// overwall routes matched hosts through the plugin's relay server, as the
// desktop's overwall middleware does: the request is rewritten to
// "<server>/<path>/<hostname><original path>" and carries the relay password.
type overwall struct {
	servers   map[int]relayServer
	targets   []targetRule
	defaultID int
}

type relayServer struct {
	id       int
	domain   string
	port     int
	path     string
	password string
}

type targetRule struct {
	pattern string
	value   any
}

func newOverwall(cfg config.Overwall) *overwall {
	if !cfg.Enabled {
		return nil
	}
	o := &overwall{servers: map[int]relayServer{}}
	add := func(m map[string]config.OverwallServer) {
		domains := make([]string, 0, len(m))
		for d := range m {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		for _, d := range domains {
			s := m[d]
			port := s.Port
			if port == 0 {
				port = 443
			}
			o.servers[s.ID] = relayServer{
				id: s.ID, domain: d, port: port, path: s.Path, password: s.Password,
			}
		}
	}
	add(cfg.ServerDefault)
	add(cfg.Server)
	if len(o.servers) == 0 {
		return nil
	}
	// The desktop prefers server 1 (user-defined) and falls back to 0 (built in).
	if _, ok := o.servers[1]; ok {
		o.defaultID = 1
	}
	for pattern, value := range cfg.Targets {
		o.targets = append(o.targets, targetRule{pattern: pattern, value: value})
	}
	// Longer patterns are more specific; try them first.
	sort.Slice(o.targets, func(i, j int) bool {
		return len(o.targets[i].pattern) > len(o.targets[j].pattern)
	})
	return o
}

// match reports the relay for host. ok is false when the host is not routed:
// an explicit false skips the host entirely, a null entry would fall through to
// the PAC list, which the kernel does not parse.
func (o *overwall) match(host string) (relayServer, string, bool) {
	for _, t := range o.targets {
		if !hostmatch.Match(t.pattern, host) {
			continue
		}
		switch v := t.value.(type) {
		case bool:
			if !v {
				return relayServer{}, "", false
			}
			return o.pick(o.defaultID)
		case map[string]any:
			if enabled, ok := v["enabled"].(bool); ok && !enabled {
				return relayServer{}, "", false
			}
			id := o.defaultID
			if n, ok := v["serverId"].(float64); ok {
				id = int(n)
			}
			return o.pick(id)
		}
		return relayServer{}, "", false
	}
	return relayServer{}, "", false
}

func (o *overwall) pick(id int) (relayServer, string, bool) {
	s, ok := o.servers[id]
	if !ok {
		return relayServer{}, "", false
	}
	return s, "config:" + strconv.Itoa(id), true
}

// overwallFor reports the relay for host, if the plugin routes it.
func (s *Server) overwallFor(host string) (relayServer, string, bool) {
	st := s.st()
	if st == nil || st.overwall == nil {
		return relayServer{}, "", false
	}
	return st.overwall.match(host)
}

// OverwallInfo reports whether the plugin is active and how many targets it has.
func (s *Server) OverwallInfo() (bool, int) {
	st := s.st()
	if st == nil || st.overwall == nil {
		return false, 0
	}
	return true, len(st.overwall.targets)
}

// overwallPath builds the relay path for an original request.
func overwallPath(relay relayServer, host, path string) string {
	return "/" + strings.Trim(relay.path, "/") + "/" + host + path
}

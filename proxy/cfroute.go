package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

// cloudflareIPsURL publishes the ranges Cloudflare serves from.
const cloudflareIPsURL = "https://api.cloudflare.com/client/v4/ips"

// cfRoute rewrites Cloudflare-resolved addresses to a preferred endpoint, which
// is the desktop's "cloudflareRoute" feature. It is off unless configured.
type cfRoute struct {
	cfg config.CloudflareRoute
	log *slog.Logger

	mu          sync.RWMutex
	ranges      []*net.IPNet
	preferredV4 net.IP
	preferredV6 net.IP
	ready       bool
}

// newCFRoute builds the rewrite table; it returns nil when the feature is off.
func newCFRoute(cfg config.CloudflareRoute, log *slog.Logger) *cfRoute {
	if !cfg.Enabled || strings.TrimSpace(cfg.PreferredEndpoint) == "" {
		return nil
	}
	return &cfRoute{cfg: cfg, log: log}
}

// start refreshes the Cloudflare ranges hourly and the preferred address every
// five minutes, matching the desktop's cadence.
func (c *cfRoute) start(ctx context.Context) {
	go func() {
		c.refreshRanges(ctx)
		c.refreshPreferred(ctx)
		ranges := time.NewTicker(time.Hour)
		pref := time.NewTicker(5 * time.Minute)
		defer ranges.Stop()
		defer pref.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ranges.C:
				c.refreshRanges(ctx)
			case <-pref.C:
				c.refreshPreferred(ctx)
			}
		}
	}()
}

// refreshRanges pulls the v4/v6 ranges the endpoint must belong to.
func (c *cfRoute) refreshRanges(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareIPsURL, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.log.Warn("cloudflareRoute ranges failed", "err", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}

	var payload struct {
		Result struct {
			IPv4CIDRs []string `json:"ipv4_cidrs"`
			IPv6CIDRs []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		c.log.Warn("cloudflareRoute ranges unparsable", "err", err)
		return
	}

	var nets []*net.IPNet
	for _, cidr := range append(payload.Result.IPv4CIDRs, payload.Result.IPv6CIDRs...) {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	if len(nets) == 0 {
		return
	}
	c.mu.Lock()
	c.ranges = nets
	c.mu.Unlock()
	c.log.Info("cloudflareRoute ranges loaded", "cidrs", len(nets))
}

// refreshPreferred resolves the configured endpoint to concrete addresses.
func (c *cfRoute) refreshPreferred(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint := strings.TrimSpace(c.cfg.PreferredEndpoint)
	var v4, v6 net.IP
	if ip := net.ParseIP(endpoint); ip != nil {
		if ip.To4() != nil {
			v4 = ip
		} else {
			v6 = ip
		}
	} else {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", endpoint)
		if err != nil {
			c.log.Warn("cloudflareRoute preferred lookup failed", "endpoint", endpoint, "err", err)
			return
		}
		for _, ip := range ips {
			if ip.To4() != nil && v4 == nil {
				v4 = ip
			} else if ip.To4() == nil && v6 == nil {
				v6 = ip
			}
		}
	}
	if v4 == nil && v6 == nil {
		return
	}
	c.mu.Lock()
	c.preferredV4, c.preferredV6 = v4, v6
	c.ready = true
	c.mu.Unlock()
	c.log.Info("cloudflareRoute preferred resolved", "endpoint", endpoint, "v4", v4, "v6", v6)
}

// covers reports whether host is subject to rewriting.
func (c *cfRoute) covers(host string) bool {
	listed := false
	for _, pattern := range c.cfg.Domains {
		if hostmatch.Match(pattern, host) {
			listed = true
			break
		}
	}
	// The desktop defaults to blacklist: listed domains are skipped.
	if strings.EqualFold(c.cfg.Mode, "whitelist") {
		return listed
	}
	return !listed
}

// rewrite replaces a Cloudflare address with the preferred one. Non-Cloudflare
// addresses and uncovered hosts are returned untouched.
func (c *cfRoute) rewrite(ip net.IP, host string) (net.IP, bool) {
	if c == nil {
		return ip, false
	}
	c.mu.RLock()
	ranges, v4, v6 := c.ranges, c.preferredV4, c.preferredV6
	c.mu.RUnlock()
	if len(ranges) == 0 || (v4 == nil && v6 == nil) {
		return ip, false
	}
	if !c.covers(host) {
		return ip, false
	}
	inRange := false
	for _, n := range ranges {
		if n.Contains(ip) {
			inRange = true
			break
		}
	}
	if !inRange {
		return ip, false
	}
	replacement := v4
	if ip.To4() == nil && v6 != nil {
		replacement = v6
	}
	if replacement == nil {
		return ip, false
	}
	return replacement, true
}

// apply rewrites every candidate address, preserving order and duplicates.
func (c *cfRoute) apply(ips []net.IP, host string) []net.IP {
	if c == nil {
		return ips
	}
	out := make([]net.IP, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if next, ok := c.rewrite(ip, host); ok {
			ip = next
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
	}
	return out
}

func (c *cfRoute) String() string {
	if c == nil {
		return "off"
	}
	return fmt.Sprintf("endpoint=%s mode=%s", c.cfg.PreferredEndpoint, c.cfg.Mode)
}

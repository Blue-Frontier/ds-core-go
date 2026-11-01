package dnsres

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// choiceCache persists the per-host IP statistics so a process that starts
// fresh does not begin from the DNS order every time. The desktop kernel keeps
// its process alive for days and never needed this; the Android build starts
// the kernel on every launch, so without a cache the first request of a session
// tries dead addresses first and can burn the dial budget ("no usable
// address" right after opening the app).

const (
	choiceCacheTTL      = 7 * 24 * time.Hour
	choiceCacheMaxHosts = 2000
	choiceCacheFlushGap = 5 * time.Second
)

type choiceEntry struct {
	Total  int   `json:"total"`
	Errors int   `json:"errors"`
	TS     int64 `json:"ts"` // unix seconds of the last update
}

type choiceCache struct {
	mu        sync.Mutex
	path      string
	hosts     map[string]map[string]*choiceEntry
	dirty     bool
	lastFlush time.Time
}

// loadChoiceCache reads the on-disk statistics. A missing or unreadable file
// simply yields an empty cache: the guess order is an optimisation, never a
// correctness requirement.
func loadChoiceCache(path string) *choiceCache {
	c := &choiceCache{path: path, hosts: map[string]map[string]*choiceEntry{}}
	if path == "" {
		return c
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var stored map[string]map[string]*choiceEntry
	if err := json.Unmarshal(raw, &stored); err != nil {
		return c
	}
	cutoff := time.Now().Add(-choiceCacheTTL).Unix()
	for host, ips := range stored {
		kept := map[string]*choiceEntry{}
		for ip, entry := range ips {
			if entry != nil && entry.TS >= cutoff {
				kept[ip] = entry
			}
		}
		if len(kept) > 0 {
			c.hosts[host] = kept
		}
	}
	return c
}

// seed returns the stored counts for the addresses this answer contains, so a
// fresh choice list starts from what earlier sessions learned about them.
func (c *choiceCache) seed(host string, ips []string) map[string]*ipCount {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := c.hosts[host]
	if len(stored) == 0 {
		return nil
	}
	out := make(map[string]*ipCount, len(ips))
	for _, ip := range ips {
		if entry, ok := stored[ip]; ok && entry != nil && entry.Total > 0 {
			out[ip] = &ipCount{
				value:       ip,
				total:       entry.Total,
				errorCount:  entry.Errors,
				successRate: 1 - float64(entry.Errors)/float64(entry.Total),
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// record updates one address and schedules a write.
func (c *choiceCache) record(host, ip string, isError bool) {
	if c == nil || c.path == "" {
		return
	}
	c.mu.Lock()
	ips := c.hosts[host]
	if ips == nil {
		ips = map[string]*choiceEntry{}
		c.hosts[host] = ips
	}
	entry := ips[ip]
	if entry == nil {
		entry = &choiceEntry{}
		ips[ip] = entry
	}
	entry.Total++
	if isError {
		entry.Errors++
	}
	entry.TS = time.Now().Unix()
	c.dirty = true
	flushNow := time.Since(c.lastFlush) >= choiceCacheFlushGap
	c.mu.Unlock()

	if flushNow {
		c.flush()
	}
}

// flush writes the cache atomically, dropping stale hosts and keeping the map
// bounded so a long-lived install does not grow without limit.
func (c *choiceCache) flush() {
	if c == nil || c.path == "" {
		return
	}
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	cutoff := time.Now().Add(-choiceCacheTTL).Unix()
	out := make(map[string]map[string]*choiceEntry, len(c.hosts))
	for host, ips := range c.hosts {
		kept := map[string]*choiceEntry{}
		for ip, entry := range ips {
			if entry != nil && entry.TS >= cutoff {
				kept[ip] = entry
			}
		}
		if len(kept) > 0 {
			out[host] = kept
		}
	}
	if len(out) > choiceCacheMaxHosts {
		out = trimOldest(out, choiceCacheMaxHosts)
	}
	c.hosts = out
	c.dirty = false
	c.lastFlush = time.Now()
	path := c.path
	c.mu.Unlock()

	raw, err := json.Marshal(out)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// reset drops everything learned so far, file included. A network change makes
// past verdicts worthless: an address that worked on Wi-Fi may be poisoned on
// mobile data.
func (c *choiceCache) reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.hosts = map[string]map[string]*choiceEntry{}
	c.dirty = false
	path := c.path
	c.mu.Unlock()
	if path != "" {
		_ = os.Remove(path)
	}
}

func trimOldest(hosts map[string]map[string]*choiceEntry, limit int) map[string]map[string]*choiceEntry {
	type pair struct {
		host string
		ts   int64
	}
	all := make([]pair, 0, len(hosts))
	for host, ips := range hosts {
		var newest int64
		for _, entry := range ips {
			if entry != nil && entry.TS > newest {
				newest = entry.TS
			}
		}
		all = append(all, pair{host, newest})
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].ts > all[i].ts {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	for i := limit; i < len(all); i++ {
		delete(hosts, all[i].host)
	}
	return hosts
}

package dnsres

import (
	"container/list"
	"sort"
	"sync"
)

// IP preference machinery, reworked from the desktop kernel's
// `mitmproxy/src/lib/choice/index.js` (DynamicChoice). The desktop kernel
// consumes its backup list while rotating (a failing candidate is dropped
// from the queue), which suits its one-dial-per-request flow. This kernel's
// proxy dials its whole candidate list per request, so rotation here
// *reorders* instead of consuming: a failing address sinks to the tail while
// every candidate stays eligible for a retry. Per-address statistics are
// kept for future ranking.

// ipCount tracks success statistics for one candidate address.
type ipCount struct {
	value        string
	total        int
	errorCount   int
	keepErrCount int
	successRate  float64
}

// ipChoice is the per-hostname candidate state. The hostname itself may be
// the trailing "fallback item" (desktop kernels push it too); it never yields
// a dialable address, so consumers filter it naturally.
type ipChoice struct {
	stats map[string]*ipCount
	order []string // preference order; failures sink to the tail
}

// newIPChoice builds candidate state for a fresh backup list.
func newIPChoice(backupList []string) *ipChoice {
	return &ipChoice{stats: map[string]*ipCount{}, order: append([]string(nil), backupList...)}
}

// sort returns the candidates in preference order.
func (c *ipChoice) orderedList() []string {
	return append([]string(nil), c.order...)
}

// doCount records one use (isError=false) or failure (isError=true) of ip.
// A failing candidate is demoted so the next lookup leads with a different
// address, mirroring the desktop's changeNext (it switches on the first
// consecutive failure); a success re-ranks by success rate, mirroring doRank,
// which the desktop calls after every proxied request.
func (c *ipChoice) doCount(ip string, isError bool) {
	cnt, ok := c.stats[ip]
	if !ok {
		cnt = &ipCount{value: ip, total: 5, successRate: 1}
		c.stats[ip] = cnt
	}
	if isError {
		cnt.errorCount++
		cnt.keepErrCount++
	} else {
		cnt.keepErrCount = 0
	}
	cnt.total++
	cnt.successRate = 1.0 - float64(cnt.errorCount)/float64(cnt.total)

	if isError {
		c.sink(ip)
	} else {
		c.doRank()
	}
}

// sink moves a failing candidate to the tail: an address that just refused a
// connection should not lead the next attempt.
func (c *ipChoice) sink(ip string) {
	if len(c.order) < 2 {
		return
	}
	for i, v := range c.order {
		if v == ip {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, ip)
			return
		}
	}
}

// doRank sorts the candidates by success rate, stable so equal rates keep the
// rotation order. Unseen addresses start at 0.5, like the desktop's
// setBackupList default.
func (c *ipChoice) doRank() {
	if len(c.order) < 2 {
		return
	}
	sort.SliceStable(c.order, func(i, j int) bool {
		return c.rate(c.order[i]) > c.rate(c.order[j])
	})
}

func (c *ipChoice) rate(ip string) float64 {
	if cnt, ok := c.stats[ip]; ok {
		return cnt.successRate
	}
	return 0.5
}

// count applies outside feedback; identical to doCount here.
func (c *ipChoice) count(ip string, isError bool) {
	if ip == "" {
		return
	}
	c.doCount(ip, isError)
}

// lru is a tiny bounded map with insertion-order eviction.
type lru struct {
	max int
	mu  sync.Mutex
	m   map[string]*list.Element
	ll  *list.List
}

type lruEntry struct {
	key   string
	value *ipChoice
}

func newLRU(maxSize int) *lru {
	if maxSize <= 0 {
		maxSize = 1024
	}
	return &lru{max: maxSize, m: map[string]*list.Element{}, ll: list.New()}
}

// get returns the cached choice (bumping recency) or nil.
func (c *lru) get(key string) *ipChoice {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil
	}
	c.ll.MoveToFront(el)
	return el.Value.(*lruEntry).value
}

func (c *lru) set(key string, v *ipChoice) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		el.Value.(*lruEntry).value = v
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntry{key: key, value: v})
	c.m[key] = el
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*lruEntry).key)
	}
}


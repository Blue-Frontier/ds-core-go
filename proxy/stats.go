package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// statsPath is answered by the kernel itself so counters can be read without
// attaching a debugger. It never touches the network.
const statsPath = "/__ds_stats__"

// statsPayload is the JSON the stats endpoint returns, shared by both protocols.
// It adds the live keep-alive pool counters so reuse is observable without a
// debugger.
func (s *Server) statsPayload() string {
	var doc map[string]any
	if err := json.Unmarshal([]byte(s.Stats.Snapshot()), &doc); err != nil {
		doc = map[string]any{}
	}
	keys, idle := s.pool.stats()
	doc["pool"] = map[string]int{"keys": keys, "idle": idle}
	out, err := json.Marshal(doc)
	if err != nil {
		return "{}"
	}
	return string(out)
}

// serveStats answers statsPath locally.
func (s *Server) serveStats(conn net.Conn, path string) bool {
	if path != statsPath {
		return false
	}
	body := s.statsPayload()
	fmt.Fprintf(conn,
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/json; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Cache-Control: no-store\r\n"+
			"Connection: keep-alive\r\n\r\n%s", len(body), body)
	return true
}

// countingWriter adds every byte written through it to n.
type countingWriter struct {
	w io.Writer
	n *atomic.Uint64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.n.Add(uint64(n))
	}
	return n, err
}

// Stats is the kernel's traffic accounting. The desktop kernel feeds a GUI
// from the same numbers; here they are exposed through the mobile API.
type Stats struct {
	Requests  atomic.Uint64
	Responses atomic.Uint64
	Bypassed  atomic.Uint64
	Injected  atomic.Uint64
	Stalls    atomic.Uint64
	Errors    atomic.Uint64
	Upgrades  atomic.Uint64
	BytesOut  atomic.Uint64

	mu    sync.Mutex
	hosts map[string]uint64
	// perHost carries the detail the traffic page shows: bytes, failures and
	// total latency per destination.
	perHost map[string]*hostStat
}

// hostStat is one row of the traffic page.
type hostStat struct {
	Requests uint64 `json:"requests"`
	Bytes    uint64 `json:"bytes"`
	Errors   uint64 `json:"errors"`
	Millis   uint64 `json:"ms"`
}

func newStats() *Stats {
	return &Stats{hosts: make(map[string]uint64), perHost: make(map[string]*hostStat)}
}

// NoteHost counts one request for host.
func (s *Stats) NoteHost(host string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.hosts[host]++
	if s.perHost[host] == nil {
		s.perHost[host] = &hostStat{}
	}
	s.perHost[host].Requests++
	s.mu.Unlock()
}

// NoteResult records the outcome of a finished exchange, so the traffic page
// can rank destinations by size and latency.
func (s *Stats) NoteResult(host string, bytes int, elapsed time.Duration, failed bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.perHost[host] == nil {
		s.perHost[host] = &hostStat{}
	}
	row := s.perHost[host]
	row.Bytes += uint64(bytes)
	row.Millis += uint64(elapsed.Milliseconds())
	if failed {
		row.Errors++
	}
	s.mu.Unlock()
}

type statsJSON struct {
	Requests  uint64               `json:"requests"`
	Responses uint64               `json:"responses"`
	Bypassed  uint64               `json:"bypassed"`
	Injected  uint64               `json:"injected"`
	Stalls    uint64               `json:"stalls"`
	Errors    uint64               `json:"errors"`
	Upgrades  uint64               `json:"upgrades"`
	BytesOut  uint64               `json:"bytesOut"`
	Hosts     map[string]uint64    `json:"hosts"`
	PerHost   map[string]*hostStat `json:"perHost"`
}

// Snapshot renders the counters as JSON.
func (s *Stats) Snapshot() string {
	if s == nil {
		return "{}"
	}
	s.mu.Lock()
	hosts := make(map[string]uint64, len(s.hosts))
	for k, v := range s.hosts {
		hosts[k] = v
	}
	perHost := make(map[string]*hostStat, len(s.perHost))
	for k, v := range s.perHost {
		row := *v
		perHost[k] = &row
	}
	s.mu.Unlock()

	b, err := json.Marshal(statsJSON{
		Requests:  s.Requests.Load(),
		Responses: s.Responses.Load(),
		Bypassed:  s.Bypassed.Load(),
		Injected:  s.Injected.Load(),
		Stalls:    s.Stalls.Load(),
		Errors:    s.Errors.Load(),
		Upgrades:  s.Upgrades.Load(),
		BytesOut:  s.BytesOut.Load(),
		Hosts:     hosts,
		PerHost:   perHost,
	})
	if err != nil {
		return "{}"
	}
	return string(b)
}

package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Blue-Frontier/ds-core-go/hostmatch"
	"github.com/Blue-Frontier/ds-core-go/rules"
)

// connPool keeps upstream connections alive between requests. The desktop does
// the same through its keep-alive agents; without it every asset pays a fresh
// TCP + TLS handshake.
type connPool struct {
	mu   sync.Mutex
	idle map[string][]pooledConn
	// ttl bounds how long a socket may sit idle: the desktop's freeSocketTimeout
	// is 5s, its keepAliveTimeout 30s, so 30s is the generous middle.
	ttl time.Duration
	max int
}

type pooledConn struct {
	conn  net.Conn
	since time.Time
}

func newConnPool() *connPool {
	return &connPool{idle: make(map[string][]pooledConn), ttl: 30 * time.Second, max: 64}
}

// get returns a live idle connection for key, or nil.
func (p *connPool) get(key string) net.Conn {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	entry := p.idle[key]
	now := time.Now()
	for len(entry) > 0 {
		last := entry[len(entry)-1]
		entry = entry[:len(entry)-1]
		if now.Sub(last.since) <= p.ttl {
			p.idle[key] = entry
			return last.conn
		}
		// Expired: drop it rather than hand out a socket the network has
		// probably already reaped.
		last.conn.Close()
	}
	delete(p.idle, key)
	return nil
}

// put returns a connection to the pool, closing the oldest when full.
func (p *connPool) put(key string, conn net.Conn) {
	if p == nil || conn == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idle) >= p.max {
		for k, list := range p.idle {
			if len(list) > 0 {
				list[0].conn.Close()
				p.idle[k] = list[1:]
				break
			}
		}
	}
	p.idle[key] = append(p.idle[key], pooledConn{conn: conn, since: time.Now()})
}

// closeAll drops every idle connection.
func (p *connPool) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, list := range p.idle {
		for _, c := range list {
			c.conn.Close()
		}
		delete(p.idle, k)
	}
}

// stats reports how many sockets are parked, for the diagnostics page.
func (p *connPool) stats() (keys, conns int) {
	if p == nil {
		return 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, list := range p.idle {
		conns += len(list)
	}
	return len(p.idle), conns
}

// upstreamKey identifies a connection by everything that shapes its TLS
// handshake, so a socket made for one rule is never reused for another.
func upstreamKey(dstHost, port, scheme string, action rules.Action, matched bool, insecure bool) string {
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(hostmatch.Normalize(dstHost))
	b.WriteString(":")
	b.WriteString(port)
	if matched {
		b.WriteString("|sni=")
		b.WriteString(action.Rule.SNI)
		b.WriteString("|vh=")
		b.WriteString(action.Rule.VerifyHost)
		if action.Rule.Proxy != "" {
			b.WriteString("|px=")
			b.WriteString(action.Rule.Proxy)
		}
	}
	if insecure {
		b.WriteString("|insecure")
	}
	return b.String()
}

// keepAlive reports whether the origin's response leaves the connection usable.
func keepAlive(resp *http.Response) bool {
	if resp == nil || resp.Close {
		return false
	}
	if resp.ProtoMajor == 1 && resp.ProtoMinor == 0 {
		return false
	}
	for _, v := range resp.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "close") {
			return false
		}
	}
	return true
}

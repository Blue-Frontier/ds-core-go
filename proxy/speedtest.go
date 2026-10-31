package proxy

import (
	"context"
	"net"
	"strings"
	"time"
)

// prewarm implements the practical part of "IP测速": for each configured host,
// resolve the address list and probe the port once, feeding the result into the
// same ranking every real dial uses. The desktop re-tests on a timer; here the
// ranking also updates continuously through normal traffic, so one pass at
// startup is enough to avoid a cold first request.
func (s *Server) prewarm(hosts []string) {
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		go func(host string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			st := s.st()
			if st == nil {
				return
			}
			ips, err := st.dns.Lookup(ctx, host)
			if err != nil {
				s.Log.Debug("speedtest resolve failed", "host", host, "err", err)
				return
			}
			good := 0
			for _, ip := range ips {
				conn, derr := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(
					ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
				if derr != nil {
					st.dns.Note(host, ip.String(), true)
					continue
				}
				_ = conn.Close()
				st.dns.Note(host, ip.String(), false)
				good++
			}
			s.Log.Info("speedtest prewarm", "host", host, "addresses", len(ips), "reachable", good)
		}(host)
	}
}

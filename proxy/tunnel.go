package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Blue-Frontier/ds-core-go/hostmatch"
	"github.com/Blue-Frontier/ds-core-go/rules"
)

// isBypassed reports whether host must not be MITM'd. The desktop kernel keeps
// these out of the proxy entirely; a MITM kernel cannot undo a CONNECT it has
// already accepted, so the equivalent is a byte tunnel.
func (s *Server) isBypassed(host string) bool {
	h := hostmatch.Normalize(host)
	st := s.st()
	for p := range st.whiteList {
		if hostmatch.Match(p, h) {
			return true
		}
	}
	for p := range st.excludeIPList {
		if hostmatch.Match(p, h) {
			return true
		}
	}
	return false
}

// blindTunnel relays bytes to the origin without terminating TLS.
func (s *Server) blindTunnel(conn net.Conn, host, port string) {
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		s.Stats.Errors.Add(1)
		return
	}
	defer up.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	s.Stats.Bypassed.Add(1)
	pipeBoth(conn, up)
}

// serveUpgrade handles Connection: Upgrade (WebSocket). It keeps the upgrade
// headers, relays a 101 verbatim and then pipes both directions. clientR is the
// buffered reader the request was parsed from, so no frame bytes are lost.
func (s *Server) serveUpgrade(conn net.Conn, clientR *bufio.Reader, req *http.Request, dstHost, port, scheme string, action rules.Action, matched bool) error {
	up, _, err := s.dialUpstream(req.Context(), dstHost, port, scheme, action, matched)
	if err != nil {
		s.Stats.Errors.Add(1)
		return s.writeError(conn, http.StatusBadGateway, err)
	}
	defer up.Close()

	out := req.Clone(req.Context())
	out.URL.Scheme = scheme
	out.URL.Host = net.JoinHostPort(dstHost, port)
	out.RequestURI = ""
	out.Close = false
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")

	up.SetDeadline(time.Time{})
	if err := out.Write(up); err != nil {
		return s.writeError(conn, http.StatusBadGateway, err)
	}

	up.SetReadDeadline(time.Now().Add(respHeaderTimeout))
	upR := bufio.NewReader(up)
	resp, err := http.ReadResponse(upR, out)
	if err != nil {
		s.Stats.Errors.Add(1)
		return s.writeError(conn, http.StatusBadGateway, err)
	}
	up.SetReadDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		s.Stats.Responses.Add(1)
		return resp.Write(conn)
	}

	s.Stats.Upgrades.Add(1)
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	if err := resp.Header.Write(conn); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		return err
	}

	// From here on the connection belongs to the upgraded protocol.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, clientR)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upR)
		closeWrite(conn)
		done <- struct{}{}
	}()
	<-done
	return errClose
}

func pipeBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

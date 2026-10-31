package proxy_test

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// countingListener records how many TCP connections the origin accepted, which
// is the direct measure of whether the kernel reuses sockets.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

func TestUpstreamConnectionReused(t *testing.T) {
	var hits atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, "hit-%d", hits.Load())
	})
	upstream := httptest.NewUnstartedServer(handler)
	listener := &countingListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.StartTLS()
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": {}}}, roots)

	client := clientFor(addr, ca)
	target := "https://" + upstream.Listener.Addr().String() + "/asset"

	for i := 0; i < 4; i++ {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		if len(body) == 0 {
			t.Fatalf("request %d: empty body", i)
		}
	}

	if got := listener.accepted.Load(); got != 1 {
		t.Fatalf("origin accepted %d connections for 4 requests, want 1", got)
	}
}

// A response that forbids keep-alive must not be reused.
func TestUpstreamCloseNotReused(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "bye")
	}))
	listener := &countingListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.StartTLS()
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": {}}}, roots)
	client := clientFor(addr, ca)
	target := "https://" + upstream.Listener.Addr().String() + "/x"

	for i := 0; i < 3; i++ {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := listener.accepted.Load(); got != 3 {
		t.Fatalf("origin accepted %d connections, want one per request (3)", got)
	}
}

// The browser negotiates h2, so the h2 path must reuse sockets as well.
func TestH2UpstreamConnectionReused(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, "hit-%d", hits.Load())
	}))
	listener := &countingListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.StartTLS()
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": {}}}, roots)

	transport := h2Client(t, addr, ca.RootPool())
	target := "https://" + upstream.Listener.Addr().String() + "/asset"

	for i := 0; i < 4; i++ {
		resp, err := transport.RoundTrip(mustRequest(t, target))
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("stream %d: proto %s", i, resp.Proto)
		}
	}

	if got := listener.accepted.Load(); got != 1 {
		t.Fatalf("origin accepted %d connections for 4 streams, want 1", got)
	}
}

// Concurrent requests must never receive each other's body: each takes its own
// socket from the pool and parks it again afterwards.
func TestPoolConcurrentRequestsStayIsolated(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		time.Sleep(20 * time.Millisecond) // widen the window for a mix-up
		fmt.Fprintf(w, "body-for-%s", id)
	}))
	listener := &countingListener{Listener: upstream.Listener}
	upstream.Listener = listener
	upstream.StartTLS()
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": {}}}, roots)
	client := clientFor(addr, ca)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			url := fmt.Sprintf("https://%s/asset?id=%d", upstream.Listener.Addr().String(), id)
			resp, err := client.Get(url)
			if err != nil {
				errs <- fmt.Sprintf("%d: %v", id, err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if want := fmt.Sprintf("body-for-%d", id); string(body) != want {
				errs <- fmt.Sprintf("%d: got %q, want %q", id, body, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
	}
	if got := listener.accepted.Load(); got > n/2 {
		t.Logf("origin accepted %d connections for %d concurrent requests", got, n)
	}
}

// The stats endpoint must expose the pool counters: they are the only way to
// observe reuse on a device without a debugger.
func TestStatsExposePool(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	addr, ca := startProxy(t, map[string]map[string]config.Rule{host: {".*": {}}}, roots)

	client := clientFor(addr, ca)
	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://" + upstream.Listener.Addr().String() + "/x")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	statsResp, err := client.Get("http://" + host + ":1/__ds_stats__")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	body, _ := io.ReadAll(statsResp.Body)
	statsResp.Body.Close()
	if !strings.Contains(string(body), `"pool"`) || !strings.Contains(string(body), `"idle"`) {
		t.Fatalf("stats payload lacks pool counters: %s", body)
	}
}

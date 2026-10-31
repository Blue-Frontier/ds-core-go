package proxy_test

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// When the primary proxy target cannot be dialed, the configured backups are
// tried in order (the desktop keeps a ranked mirror list).
func TestProxyBackupIsUsedWhenPrimaryFails(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "backup-ok")
	}))
	defer upstream.Close()

	host, _, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	addr, ca := startProxy(t, map[string]map[string]config.Rule{
		host: {".*": {
			Proxy:  "unreachable.invalid",
			Backup: config.StringList{host},
		}},
	}, roots)

	resp, err := clientFor(addr, ca).Get("https://" + upstream.Listener.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "backup-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

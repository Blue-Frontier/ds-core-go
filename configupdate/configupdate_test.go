package configupdate

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cfgVersioned = `
{
  app: { metaInfo: { id: "test", version: %d, updateLog: "v%d" } },
  server: { intercepts: { "a.example": { ".*": { sni: "x" } } } },
}
`

func configBytes(version int) []byte {
	return []byte(fmt.Sprintf(cfgVersioned, version, version))
}

// fetchFrom serves handler over TLS and rewires the download transport to it.
// The returned URL keeps the https scheme so Install's own scheme guard runs;
// only the certificate plumbing of the test server is bypassed.
func fetchFrom(t *testing.T, handler func(*http.Request) []byte) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(handler(r))
	}))
	t.Cleanup(srv.Close)

	original := httpFetch
	t.Cleanup(func() { httpFetch = original })
	httpFetch = func(u string) ([]byte, error) {
		resp, err := srv.Client().Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return strings.Replace(srv.URL, "http://", "https://", 1)
}

func TestInstallUpdatesOlderFileAndThenReportsCurrent(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
	if err := os.WriteFile(dest, configBytes(1), 0o644); err != nil {
		t.Fatal(err)
	}

	url := fetchFrom(t, func(*http.Request) []byte { return configBytes(2) })
	got := Install(url, dest)
	if got.Status != "updated" {
		t.Fatalf("first install = %+v, want updated", got)
	}
	if got.Version != 2 {
		t.Fatalf("version = %d", got.Version)
	}

	again := Install(url, dest)
	if again.Status != "current" {
		t.Fatalf("second install = %+v, want current", again)
	}
}

func TestInstallRefusesUnversionedRemote(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
	if err := os.WriteFile(dest, configBytes(5), 0o644); err != nil {
		t.Fatal(err)
	}

	url := fetchFrom(t, func(*http.Request) []byte {
		return []byte(`{"server":{"intercepts":{}}}`)
	})
	got := Install(url, dest)
	if got.Status != "error" {
		t.Fatalf("got %+v, want error", got)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("dest was removed: %v", err)
	}
}

func TestInstallReportsDownloadFailure(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
	// Plain http is refused before any attempt is made.
	got := Install("http://127.0.0.1:1/nope", dest)
	if got.Status != "error" {
		t.Fatalf("got %+v, want error", got)
	}
}

// A truncated body that still arrives without a transport error must not be
// mistaken for the published configuration: the retry has to fetch again and
// install the complete file.
func TestInstallRetriesWhenTheBodyIsTruncated(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
	if err := os.WriteFile(dest, configBytes(1), 0o644); err != nil {
		t.Fatal(err)
	}

	want := configBytes(2)
	calls := 0
	url := fetchFrom(t, func(*http.Request) []byte {
		calls++
		if calls == 1 {
			return want[:len(want)/2]
		}
		return want
	})

	got := Install(url, dest)
	if got.Status != "updated" {
		t.Fatalf("install = %+v, want updated after retry", got)
	}
	if calls < 2 {
		t.Fatalf("calls = %d, want a retry", calls)
	}
	if got.Version != 2 {
		t.Fatalf("version = %d, want 2", got.Version)
	}
}

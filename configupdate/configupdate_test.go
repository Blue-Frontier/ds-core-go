package configupdate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func serve(t *testing.T, version int) *httptest.Server {
	t.Helper()
	body := configBytes(version)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInstallUpdatesOlderFileAndThenReportsCurrent(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
	if err := os.WriteFile(dest, configBytes(1), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := serve(t, 2)
	got := Install(srv.URL, dest)
	if got.Status != "updated" {
		t.Fatalf("first install = %+v, want updated", got)
	}
	if got.Version != 2 {
		t.Fatalf("version = %d", got.Version)
	}

	again := Install(srv.URL, dest)
	if again.Status != "current" {
		t.Fatalf("second install = %+v, want current", again)
	}
}

func TestInstallRefusesUnversionedRemote(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
	if err := os.WriteFile(dest, configBytes(5), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server":{"intercepts":{}}}`))
	}))
	defer srv.Close()

	got := Install(srv.URL, dest)
	if got.Status != "error" {
		t.Fatalf("got %+v, want error", got)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("dest was removed: %v", err)
	}
}

func TestInstallReportsDownloadFailure(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "remote_config.json5")
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("full") == "" && r.Header.Get("X-Retry") == "" {
			_, _ = w.Write(want[:len(want)/2])
			return
		}
		_, _ = w.Write(want)
	}))
	t.Cleanup(srv.Close)

	calls := 0
	original := httpFetch
	t.Cleanup(func() { httpFetch = original })
	httpFetch = func(url string) ([]byte, error) {
		calls++
		if calls == 1 {
			return want[:len(want)/2], nil
		}
		return want, nil
	}

	got := Install(srv.URL, dest)
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

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

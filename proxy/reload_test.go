package proxy_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func configWithSNI(sni string) *config.Config {
	return &config.Config{Server: config.Server{
		Intercepts: map[string]map[string]config.Rule{
			"example.com": {`^/x$`: {SNI: sni}},
		},
	}}
}

// Reload must swap the compiled rules without recreating the server, so the
// listening socket and in-flight requests are untouched.
func TestReloadSwapsRules(t *testing.T) {
	ca, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache: %v", err)
	}
	srv, err := proxy.New(configWithSNI("one"), ca, testLogger())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	if a, ok := srv.Table().Match("example.com", "/x"); !ok || a.Rule.SNI != "one" {
		t.Fatalf("initial rule = %+v ok=%v", a.Rule, ok)
	}

	if err := srv.Reload(configWithSNI("two")); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if a, ok := srv.Table().Match("example.com", "/x"); !ok || a.Rule.SNI != "two" {
		t.Fatalf("reloaded rule = %+v ok=%v", a.Rule, ok)
	}
}

// The watcher turns a file edit into a live rule change.
func TestWatchPicksUpFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote_config.json5")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(`{ server: { intercepts: { "example.com": { "^/x$": { sni: "one" } } } } }`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ca, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache: %v", err)
	}
	srv, err := proxy.New(cfg, ca, testLogger())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	stop := srv.Watch(20*time.Millisecond, []string{path}, func() (*config.Config, error) {
		return config.Load(path)
	})
	defer stop()

	write(`{ server: { intercepts: { "example.com": { "^/x$": { sni: "two" } }, "extra.example": { ".*": { sni: "e" } } } } }`)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a, ok := srv.Table().Match("example.com", "/x"); ok && a.Rule.SNI == "two" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("watcher did not reload the configuration")
}

// A broken edit must leave the previous rules in force.
func TestWatchKeepsRulesOnBrokenConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote_config.json5")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(`{ server: { intercepts: { "example.com": { "^/x$": { sni: "one" } } } } }`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ca, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache: %v", err)
	}
	srv, err := proxy.New(cfg, ca, testLogger())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	stop := srv.Watch(20*time.Millisecond, []string{path}, func() (*config.Config, error) {
		return config.Load(path)
	})
	defer stop()

	write(`{ "server": `) // truncated write
	time.Sleep(300 * time.Millisecond)

	if a, ok := srv.Table().Match("example.com", "/x"); !ok || a.Rule.SNI != "one" {
		t.Fatalf("rules after broken edit = %+v ok=%v", a.Rule, ok)
	}
}

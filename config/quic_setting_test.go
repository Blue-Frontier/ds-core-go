package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The HTTP/3 upstream is configured as an object with a host list. A parser that
// silently dropped it would leave the feature off with no error anywhere, so the
// shape is pinned here.
func TestQuicUpstreamSettingParses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote_config.json5")
	src := `{
  server: {
    setting: {
      quicUpstream: { enabled: true, hosts: ["x.com", "*.x.com"] },
    },
  },
}`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := LoadLayers(path)
	if err != nil {
		t.Fatalf("LoadLayers: %v", err)
	}
	q := res.Config.Server.Setting.QuicUpstream
	if !bool(q.Enabled) {
		t.Fatalf("enabled = false, want true")
	}
	if len(q.Hosts) != 2 || q.Hosts[0] != "x.com" {
		t.Fatalf("hosts = %v", q.Hosts)
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The desktop's three modes only differ in these switches
// (gui/src/view/pages/index.vue applyMode).
func TestModeSwitchesMatchDesktop(t *testing.T) {
	dir := t.TempDir()
	official := filepath.Join(dir, "remote_config.json5")
	if err := os.WriteFile(official, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		mode string
		want map[string]any
	}{
		{
			mode: "safe",
			want: map[string]any{"intercept": false},
		},
		{
			mode: "default",
			want: map[string]any{"intercept": true},
		},
		{
			mode: "ow",
			want: map[string]any{"intercept": true, "overwall": true},
		},
	}

	for _, c := range cases {
		os.Remove(UserLayerPath(official))
		if err := SetMode(official, c.mode); err != nil {
			t.Fatalf("%s: SetMode: %v", c.mode, err)
		}

		raw := ReadUserLayer(official)
		got := map[string]any{
			"intercept": lookup(raw, "server", "intercept", "enabled"),
			"speedTest": lookup(raw, "server", "dns", "speedTest", "enabled"),
			"overwall":  lookup(raw, "plugin", "overwall", "enabled"),
		}
		// Untouched keys must stay absent: the mode switch only owns what it means.
		if c.mode != "ow" && got["overwall"] != nil {
			t.Errorf("%s: overwall should not be written, got %v", c.mode, got["overwall"])
		}
		if got["speedTest"] != nil {
			t.Errorf("%s: speedTest should not be written, got %v", c.mode, got["speedTest"])
		}
		for key, want := range c.want {
			if got[key] != want {
				t.Errorf("%s: %s = %v, want %v", c.mode, key, got[key], want)
			}
		}
		if mode := CurrentMode(official); mode != c.mode {
			t.Errorf("%s: CurrentMode = %q", c.mode, mode)
		}
	}
}

func TestSetModeRejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	official := filepath.Join(dir, "remote_config.json5")
	if err := os.WriteFile(official, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetMode(official, "turbo"); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}

// A mode recorded in the local layer survives a reload and is reported back.
func TestCurrentModeDefaultsToDefault(t *testing.T) {
	dir := t.TempDir()
	official := filepath.Join(dir, "remote_config.json5")
	if got := CurrentMode(official); got != "default" {
		t.Fatalf("CurrentMode on a fresh install = %q", got)
	}
}

func lookup(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[k]
	}
	return cur
}

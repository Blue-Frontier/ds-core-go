package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergeSemantics(t *testing.T) {
	dst := map[string]any{
		"a": map[string]any{"x": 1, "y": 2},
		"b": []any{"one", "two"},
		"c": "keep",
		"d": "remove-me",
	}
	src := map[string]any{
		"a": map[string]any{"y": 20, "z": 30},
		"b": []any{"three"},
		"d": nil,
	}
	Merge(dst, src)

	a := dst["a"].(map[string]any)
	if a["x"] != 1 || a["y"] != 20 || a["z"] != 30 {
		t.Fatalf("object not deep-merged: %+v", a)
	}
	b := dst["b"].([]any)
	if len(b) != 1 || b[0] != "three" {
		t.Fatalf("array should be replaced, got %+v", b)
	}
	if dst["c"] != "keep" {
		t.Fatalf("unrelated key lost: %+v", dst["c"])
	}
	if _, ok := dst["d"]; ok {
		t.Fatal("null should delete the key")
	}
}

const officialLayer = `
{
  app: { metaInfo: { id: "official", version: 202610281230 } },
  server: {
    intercepts: {
      "github.com": { "^/a": { sni: "baidu.com", desc: "official" } },
      "keep.example": { ".*": { proxy: "p.example" } },
    },
    whiteList: { "*.icloud.com": true },
  },
}
`

const personalLayer = `
{
  app: { metaInfo: { id: "personal", version: 12345 } },
  server: {
    intercepts: {
      "github.com": { "^/a": { desc: "personal wins" } },
      "mine.example": { ".*": { sni: "x" } },
    },
  },
}
`

func TestLoadWithPersonalMerges(t *testing.T) {
	dir := t.TempDir()
	off := filepath.Join(dir, "remote_config.json5")
	per := filepath.Join(dir, "remote_config_personal.json5")
	if err := os.WriteFile(off, []byte(officialLayer), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(per, []byte(personalLayer), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadWithPersonal(off, per)
	if err != nil {
		t.Fatalf("LoadWithPersonal: %v", err)
	}
	if res.Official.Version != 202610281230 {
		t.Fatalf("official layer meta lost: %+v", res.Official)
	}
	if res.Personal.ID != "personal" || res.Personal.Version != 12345 {
		t.Fatalf("personal meta = %+v", res.Personal)
	}
	// The merged view follows the desktop: the personal layer may override
	// app.metaInfo, which is exactly why each layer keeps its own copy.
	if got := res.Config.App.MetaInfo.Version; got != 12345 {
		t.Fatalf("merged meta version = %d, want the personal one", got)
	}

	// Personal overrides only the field it names; the rest of the rule survives.
	r := res.Config.Server.Intercepts["github.com"]["^/a"]
	if r.Desc != "personal wins" {
		t.Fatalf("personal did not win: %+v", r)
	}
	if r.SNI != "baidu.com" {
		t.Fatalf("official field lost: %+v", r)
	}
	// New hosts and untouched official branches both survive.
	if _, ok := res.Config.Server.Intercepts["mine.example"]; !ok {
		t.Fatal("personal-only host missing")
	}
	if _, ok := res.Config.Server.Intercepts["keep.example"]; !ok {
		t.Fatal("official-only host missing")
	}
	if !res.Config.Server.WhiteList["*.icloud.com"] {
		t.Fatal("official whiteList lost")
	}
}

func TestLoadWithPersonalBrokenLayerIsIgnored(t *testing.T) {
	dir := t.TempDir()
	off := filepath.Join(dir, "remote_config.json5")
	per := filepath.Join(dir, "remote_config_personal.json5")
	if err := os.WriteFile(off, []byte(officialLayer), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(per, []byte(`{ "server": `), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadWithPersonal(off, per)
	if err != nil {
		t.Fatalf("broken personal layer must not abort: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected a warning")
	}
	if _, ok := res.Config.Server.Intercepts["keep.example"]; !ok {
		t.Fatal("official layer should still load")
	}
}

func TestLoadWithPersonalMissingLayer(t *testing.T) {
	dir := t.TempDir()
	off := filepath.Join(dir, "remote_config.json5")
	if err := os.WriteFile(off, []byte(officialLayer), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := LoadWithPersonal(off, filepath.Join(dir, "nope.json5"))
	if err != nil {
		t.Fatalf("LoadWithPersonal: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("missing layer is not a warning: %v", res.Warnings)
	}
	if res.Personal.Version != 0 {
		t.Fatalf("personal meta should be zero: %+v", res.Personal)
	}
}

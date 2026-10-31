package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ruleTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	official := filepath.Join(dir, "remote_config.json5")
	body := `{ server: { intercepts: { "example.com": { ".*": { sni: "x.example" } } } } }`
	if err := os.WriteFile(official, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return official
}

// The editor reads the merged block, writes a local override, and can drop it
// again so the lower layer shows through.
func TestRuleEditingRoundTrip(t *testing.T) {
	official := ruleTestConfig(t)

	txt, err := RuleText(official, "example.com")
	if err != nil {
		t.Fatalf("RuleText: %v", err)
	}
	var block map[string]any
	if err := json.Unmarshal([]byte(txt), &block); err != nil {
		t.Fatalf("RuleText is not JSON: %v (%s)", err, txt)
	}
	if _, ok := block[".*"]; !ok {
		t.Fatalf("expected the .* pattern, got %s", txt)
	}

	if err := SetRuleText(official, "added.example", `{".*":{"abort":true}}`); err != nil {
		t.Fatalf("SetRuleText: %v", err)
	}
	res, err := LoadLayers(official, defaultLayerPaths(official)...)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Config.Server.Intercepts["added.example"]; !ok {
		t.Fatal("the override should appear in the merged configuration")
	}

	if err := ResetRuleText(official, "added.example"); err != nil {
		t.Fatalf("ResetRuleText: %v", err)
	}
	res, err = LoadLayers(official, defaultLayerPaths(official)...)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Config.Server.Intercepts["added.example"]; ok {
		t.Fatal("the override should be gone after a reset")
	}
	if _, ok := res.Config.Server.Intercepts["example.com"]; !ok {
		t.Fatal("the lower layer must survive a reset")
	}
}

func TestSetRuleTextRejectsBrokenJSON(t *testing.T) {
	official := ruleTestConfig(t)
	if err := SetRuleText(official, "bad.example", `{not json`); err == nil {
		t.Fatal("broken JSON must be rejected")
	}
}

// An override replaces the whole host block, so the merged table reflects the
// edit rather than a mixture of layers.
func TestRuleOverrideWins(t *testing.T) {
	official := ruleTestConfig(t)
	if err := SetRuleText(official, "example.com", `{".*":{"abort":true}}`); err != nil {
		t.Fatal(err)
	}
	res, err := LoadLayers(official, defaultLayerPaths(official)...)
	if err != nil {
		t.Fatal(err)
	}
	rule := res.Config.Server.Intercepts["example.com"][".*"]
	if rule.Abort == nil {
		t.Fatalf("expected the abort override, got %+v", rule)
	}
	if rule.SNI != "" {
		t.Fatalf("the lower layer's sni should be replaced, got %q", rule.SNI)
	}
}

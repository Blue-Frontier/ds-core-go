package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// UserLayerFile is the highest-priority layer: the overrides the app writes.
const UserLayerFile = "user_config.json5"

// UserLayerPath returns the local layer that sits next to the official config.
func UserLayerPath(officialPath string) string {
	return filepath.Join(filepath.Dir(officialPath), UserLayerFile)
}

// ReadUserLayer parses the local layer, treating a missing or broken file as
// empty so a hand edit can never lock the app out of its own settings.
func ReadUserLayer(officialPath string) map[string]any {
	data, err := os.ReadFile(UserLayerPath(officialPath))
	if err != nil {
		return map[string]any{}
	}
	raw, err := ParseRaw(data)
	if err != nil {
		return map[string]any{}
	}
	return raw
}

// WriteUserLayer stores the local layer as plain JSON, which the JSON5 parser
// accepts.
func WriteUserLayer(officialPath string, raw map[string]any) error {
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(UserLayerPath(officialPath), data, 0o644)
}

// SetMode applies the mode switch to the local layer.
//
// The desktop's applyMode also writes speedTest and overwall on every change.
// We only touch what the switch actually means: writing overwall=false on
// every visit would silently cancel a relay the user configured by hand, and
// speedTest is unaffected by the mode anyway.
func SetMode(officialPath, mode string) error {
	raw := ReadUserLayer(officialPath)
	switch mode {
	case "safe":
		setPath(raw, false, "server", "intercept", "enabled")
	case "default":
		setPath(raw, true, "server", "intercept", "enabled")
	case "ow":
		setPath(raw, true, "server", "intercept", "enabled")
		setPath(raw, true, "plugin", "overwall", "enabled")
	default:
		return ErrUnknownMode
	}
	setPath(raw, mode, "app", "mode")
	return WriteUserLayer(officialPath, raw)
}

// CurrentMode reads the mode recorded in the local layer.
func CurrentMode(officialPath string) string {
	raw := ReadUserLayer(officialPath)
	app, _ := raw["app"].(map[string]any)
	if mode, _ := app["mode"].(string); mode != "" {
		return mode
	}
	return "default"
}

// RuleText renders the merged rule block for host as JSON, for the editor.
func RuleText(officialPath, host string) (string, error) {
	res, err := LoadLayers(officialPath, defaultLayerPaths(officialPath)...)
	if err != nil {
		return "", err
	}
	block, ok := res.Config.Server.Intercepts[host]
	if !ok {
		return "{}", nil
	}
	b, err := json.MarshalIndent(block, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SetRuleText writes one host block into the local layer.
//
// The editor shows the merged block, so the write replaces it: patterns the
// user removed are recorded as null, otherwise the deep merge would resurrect
// them from a lower layer.
func SetRuleText(officialPath, host, text string) error {
	var block map[string]any
	if err := json.Unmarshal([]byte(text), &block); err != nil {
		return err
	}
	if res, err := LoadLayers(officialPath, defaultLayerPaths(officialPath)...); err == nil {
		nullDiff(rawRuleBlock(res.Config.Server.Intercepts[host]), block)
	}
	raw := ReadUserLayer(officialPath)
	setPath(raw, block, "server", "intercepts", host)
	return WriteUserLayer(officialPath, raw)
}

// ResetRuleText drops the local override for host, falling back to the layers
// below it.
func ResetRuleText(officialPath, host string) error {
	raw := ReadUserLayer(officialPath)
	server, _ := raw["server"].(map[string]any)
	hosts, _ := server["intercepts"].(map[string]any)
	if hosts == nil {
		return nil
	}
	delete(hosts, host)
	return WriteUserLayer(officialPath, raw)
}

// defaultLayerPaths lists the personal and local layers for a config path.
func defaultLayerPaths(officialPath string) []Layer {
	dir := filepath.Dir(officialPath)
	return []Layer{
		{Name: LayerPersonal, Path: filepath.Join(dir, "remote_config_personal.json5")},
		{Name: LayerUser, Path: UserLayerPath(officialPath)},
	}
}

// setPath writes value at the given key path, creating intermediate objects.
func setPath(root map[string]any, value any, keys ...string) {
	cur := root
	for _, k := range keys[:len(keys)-1] {
		next, ok := cur[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[k] = next
		}
		cur = next
	}
	cur[keys[len(keys)-1]] = value
}

// ErrUnknownMode rejects a mode the desktop does not define.
var ErrUnknownMode = &modeError{}

type modeError struct{}

func (*modeError) Error() string { return "config: unknown mode" }

// rawRuleBlock re-decodes a host block into generic maps so it can be compared
// with edited JSON.
func rawRuleBlock(block map[string]Rule) map[string]any {
	if len(block) == 0 {
		return nil
	}
	data, err := json.Marshal(block)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

// nullDiff writes an explicit null for every key that exists below but not
// above, recursively, so the merge deletes it instead of keeping the old value.
func nullDiff(lower, upper map[string]any) {
	for k, lv := range lower {
		uv, ok := upper[k]
		if !ok {
			upper[k] = nil
			continue
		}
		lm, lok := lv.(map[string]any)
		um, uok := uv.(map[string]any)
		if lok && uok {
			nullDiff(lm, um)
		}
	}
}

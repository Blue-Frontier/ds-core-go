package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Layer names as shown in the settings screen.
const (
	LayerOfficial = "official"
	LayerPersonal = "personal"
	LayerUser     = "user"
)

// Layer is one configuration file to merge over the official one.
type Layer struct {
	Name string
	Path string
}

// DisabledRule is a rule switched off from the UI. It is not part of any
// configuration file: the kernel filters it out after merging.
type DisabledRule struct {
	Host    string `json:"host"`
	Pattern string `json:"pattern"`
}

// DisabledRulesFile is where the per-rule switches live, next to the configs.
const DisabledRulesFile = "disabled_rules.json"

// LoadLayers loads the official configuration and merges each additional layer
// over it in order (personal, then the local user layer). Missing layers are
// skipped; a broken optional layer is reported as a warning, never fatal.
func LoadLayers(officialPath string, layers ...Layer) (*LoadResult, error) {
	officialBytes, err := os.ReadFile(officialPath)
	if err != nil {
		return nil, err
	}
	merged, err := ParseRaw(officialBytes)
	if err != nil {
		return nil, err
	}

	res := &LoadResult{
		Official:  metaFromRaw(merged),
		Sources:   map[string]string{},
		Disabled:  ReadDisabled(officialPath),
		LayerMeta: map[string]MetaInfo{LayerOfficial: metaFromRaw(merged)},
	}
	recordSources(res.Sources, merged, LayerOfficial)

	for _, layer := range layers {
		if layer.Path == "" {
			continue
		}
		data, readErr := os.ReadFile(layer.Path)
		if readErr != nil {
			if !os.IsNotExist(readErr) {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s config unreadable: %v", layer.Name, readErr))
			}
			continue
		}
		parsed, perr := ParseRaw(data)
		if perr != nil {
			// A broken optional layer must not take the kernel down.
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("%s config ignored: %v", layer.Name, perr))
			continue
		}
		meta := metaFromRaw(parsed)
		switch layer.Name {
		case LayerPersonal:
			res.Personal = meta
		case LayerUser:
			res.User = meta
		}
		res.LayerMeta[layer.Name] = meta
		Merge(merged, parsed)
		recordSources(res.Sources, parsed, layer.Name)
	}

	b, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(b)
	if err != nil {
		return nil, err
	}
	cfg.Disabled = res.Disabled
	res.Config = cfg
	return res, nil
}

// LoadWithPersonal keeps the two-layer entry point used by the tests and the
// tools that do not need a local layer.
func LoadWithPersonal(officialPath, personalPath string) (*LoadResult, error) {
	return LoadLayers(officialPath, Layer{Name: LayerPersonal, Path: personalPath})
}

// recordSources notes which layer supplied (or last overrode) each host block.
func recordSources(dst map[string]string, layer map[string]any, name string) {
	server, _ := layer["server"].(map[string]any)
	intercepts, _ := server["intercepts"].(map[string]any)
	for host := range intercepts {
		dst[host] = name
	}
}

// ReadDisabled loads the per-rule switch file next to the configuration.
func ReadDisabled(officialPath string) []DisabledRule {
	path := filepath.Join(filepath.Dir(officialPath), DisabledRulesFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []DisabledRule
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

// WriteDisabled stores the per-rule switches next to the configuration.
func WriteDisabled(officialPath string, rules []DisabledRule) error {
	path := filepath.Join(filepath.Dir(officialPath), DisabledRulesFile)
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

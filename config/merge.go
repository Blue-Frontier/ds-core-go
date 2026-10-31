package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ParseRaw parses JSON5 into a generic map so layers can be merged before the
// typed struct is built. Numbers are kept as json.Number to avoid re-encoding
// large integers (metaInfo.version is a 12-digit timestamp).
func ParseRaw(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(StripJSON5(data)))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return out, nil
}

// Merge deep-merges src into dst with the desktop kernel's semantics
// (lodash.mergeWith then deleteNullItems): objects merge recursively, arrays
// and scalars replace, and a null or "[delete]" value removes the key. Nulls
// already present in dst are dropped as well, exactly like the desktop's
// post-merge cleanup.
func Merge(dst, src map[string]any) {
	mergeInto(dst, src)
	dropNulls(dst)
}

// mergeInto is the raw lodash.mergeWith behaviour; nulls are only handled once
// the whole layer has been merged.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if v == nil || v == "[delete]" {
			delete(dst, k)
			continue
		}
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				mergeInto(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}

// dropNulls mirrors the desktop's deleteNullItems: after merging, every key
// whose value is null or "[delete]" disappears, recursively.
func dropNulls(m map[string]any) {
	for k, v := range m {
		if v == nil || v == "[delete]" {
			delete(m, k)
			continue
		}
		switch vv := v.(type) {
		case map[string]any:
			dropNulls(vv)
		case []any:
			for _, item := range vv {
				if im, ok := item.(map[string]any); ok {
					dropNulls(im)
				}
			}
		}
	}
}

// LoadResult is the outcome of loading the configuration layers.
type LoadResult struct {
	Config *Config
	// Official is the official layer's own metadata, captured before the
	// personal layer may overwrite app.metaInfo in the merged view.
	Official MetaInfo
	// Personal is the personal layer's own metadata (zero when absent).
	Personal MetaInfo
	// User is the local layer's own metadata (zero when absent).
	User MetaInfo
	// LayerMeta holds each layer's metadata by name.
	LayerMeta map[string]MetaInfo
	// Sources maps a host block to the layer that last supplied it.
	Sources map[string]string
	// Disabled lists rules switched off from the UI.
	Disabled []DisabledRule
	// Warnings describe layers that were ignored, e.g. an unparsable personal
	// configuration. They never abort the load.
	Warnings []string
}

// metaFromRaw pulls app.metaInfo out of a generic layer.
func metaFromRaw(m map[string]any) MetaInfo {
	app, _ := m["app"].(map[string]any)
	meta, _ := app["metaInfo"].(map[string]any)
	var out MetaInfo
	if s, ok := meta["id"].(string); ok {
		out.ID = s
	}
	switch v := meta["version"].(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			out.Version = n
		}
	case float64:
		out.Version = int64(v)
	}
	if s, ok := meta["updateLog"].(string); ok {
		out.UpdateLog = s
	}
	return out
}

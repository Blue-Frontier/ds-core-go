package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The base, overlay and expected result below are taken from the desktop
// kernel's own merge test (core/test/mergeTest.js). It pins the semantics that
// matter for layered configuration: objects deep-merge, arrays replace, null
// deletes a key, and nulls left in the base are dropped.
func TestDesktopMergeVectors(t *testing.T) {
	var base, overlay, want map[string]any
	mustJSON := func(s string, into *map[string]any) {
		if err := json.Unmarshal([]byte(s), into); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}

	mustJSON(`{
		"a": {"aa": {"value": 1}, "bb": {"value": 2}},
		"b": {"c": 2},
		"c": 1,
		"d": [1, 2, 3],
		"e": {"aa": 2, "ee": 5},
		"f": {"x": 1},
		"g": [1, 2],
		"h": null,
		"i": null
	}`, &base)

	// This is the diff the desktop's merge test feeds into doMerge.
	mustJSON(`{
		"a": {"aa": null, "cc": {"value": 3}},
		"c": null,
		"d": [1, 2, 3, 4],
		"e": {"ff": 6},
		"f": {"x": null}
	}`, &overlay)

	mustJSON(`{
		"a": {"bb": {"value": 2}, "cc": {"value": 3}},
		"b": {"c": 2},
		"d": [1, 2, 3, 4],
		"e": {"aa": 2, "ee": 5, "ff": 6},
		"f": {},
		"g": [1, 2]
	}`, &want)

	Merge(base, overlay)
	if !reflect.DeepEqual(base, want) {
		got, _ := json.MarshalIndent(base, "", "  ")
		exp, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("merge result differs\n got: %s\nwant: %s", got, exp)
	}
}

// A null in the base must not survive the merge, matching deleteNullItems.
func TestMergeDropsBaseNulls(t *testing.T) {
	base := map[string]any{"keep": 1, "drop": nil, "nested": map[string]any{"x": nil}}
	Merge(base, map[string]any{})
	if _, ok := base["drop"]; ok {
		t.Fatal("null in the base should be dropped")
	}
	if nested, ok := base["nested"].(map[string]any); ok {
		if _, ok := nested["x"]; ok {
			t.Fatal("nested null should be dropped")
		}
	}
	if base["keep"] != float64(1) && base["keep"] != 1 {
		t.Fatalf("keep = %v", base["keep"])
	}
}

package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Ported from the desktop kernel's core/test/configTest.js: a null in a higher
// layer removes an entry supplied by a lower one, which is how the desktop lets
// a user clear a default exclusion.
func TestExcludeIPListNullDeletion(t *testing.T) {
	cases := []struct {
		name string
		base string
		user string
		want string
	}{
		{
			name: "removes one default domain",
			base: `{"proxy":{"excludeIpList":{"default.example":true}}}`,
			user: `{"proxy":{"excludeIpList":{"default.example":null}}}`,
			want: `{"proxy":{"excludeIpList":{}}}`,
		},
		{
			name: "removes every default domain",
			base: `{"proxy":{"excludeIpList":{"first.example":true,"second.example":true}}}`,
			user: `{"proxy":{"excludeIpList":{"first.example":null,"second.example":null}}}`,
			want: `{"proxy":{"excludeIpList":{}}}`,
		},
		{
			name: "keeps an explicit override",
			base: `{"proxy":{"excludeIpList":{"default.example":true}}}`,
			user: `{"proxy":{"excludeIpList":{"default.example":false}}}`,
			want: `{"proxy":{"excludeIpList":{"default.example":false}}}`,
		},
		{
			name: "removes a user added domain",
			base: `{"proxy":{"excludeIpList":{"default.example":true,"custom.example":true}}}`,
			user: `{"proxy":{"excludeIpList":{"custom.example":null}}}`,
			want: `{"proxy":{"excludeIpList":{"default.example":true}}}`,
		},
		{
			name: "remote layer can drop a default",
			base: `{"proxy":{"excludeIpList":{"remote.example":true}}}`,
			user: `{"proxy":{"excludeIpList":{"remote.example":null}}}`,
			want: `{"proxy":{"excludeIpList":{}}}`,
		},
	}

	for _, c := range cases {
		var base, user, want map[string]any
		for _, pair := range []struct {
			in string
			to *map[string]any
		}{{c.base, &base}, {c.user, &user}, {c.want, &want}} {
			if err := json.Unmarshal([]byte(pair.in), pair.to); err != nil {
				t.Fatalf("%s: fixture: %v", c.name, err)
			}
		}
		Merge(base, user)
		if !reflect.DeepEqual(base, want) {
			t.Errorf("%s: got %v, want %v", c.name, base, want)
		}
	}
}

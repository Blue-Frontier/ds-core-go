package hostmatch

import "testing"

// The cases below are copied verbatim from the desktop kernel's own test,
// ds-core/mitmproxy/test/matchUtilTest.js, so the Go port is checked against
// the reference implementation's expectations instead of my reading of them.
func TestDesktopMatchUtilVectors(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
		note    string
	}{
		// test1: exact key
		{"aaa.com", "aaa.com", true, "exact hit"},
		{"aaa.com", "aaaa.com", false, "exact must not prefix-match"},
		{"aaa.com", "aaaa.comx", false, "exact must not suffix-match"},

		// test2: single-star prefix
		{"*bbb.com", "bbb.com", true, "test2.1"},
		{"*bbb.com", "xbbb.com", true, "test2.2"},
		{"*bbb.com", "bbb.comx", false, "test2.3"},
		{"*bbb.com", "x.bbb.com", true, "test2.4"},

		// test3: *.domain
		{"*.ccc.com", "ccc.com", true, "test3.1"},
		{"*.ccc.com", "x.ccc.com", true, "test3.2"},
		{"*.ccc.com", "xccc.com", false, "test3.3"},

		// test4: regex key
		{"^.{1,3}ddd.com$", "ddd.com", false, "test4.1"},
		{"^.{1,3}ddd.com$", "x.ddd.com", true, "test4.2"},
		{"^.{1,3}ddd.com$", "xddd.com", true, "test4.3"},

		// test5: bare TLD wildcard
		{"*.cn", "zzz.cn", true, "test5.1"},
		{"*.cn", "x.zzz.cn", true, "test5.2"},
		{"*.cn", "zzz.cnet.com", false, "test5.3"},

		// test6: dot prefix is rewritten to *.domain
		{".github.com", "github.com", true, "test6.1"},
		{".github.com", "api.github.com", true, "test6.2"},
		{".github.com", "aa.bb.github.com", true, "test6.3"},
	}

	for _, c := range cases {
		if got := Match(c.pattern, c.host); got != c.want {
			t.Errorf("%-22s vs %-16s = %v, want %v (%s)", c.pattern, c.host, got, c.want, c.note)
		}
	}
}

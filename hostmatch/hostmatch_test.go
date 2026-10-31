package hostmatch

import "testing"

func TestMatchForms(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"github.com", "github.com", true},
		{"GitHub.com", "github.com", true},
		{"github.com", "github.com.evil", false},
		// "*.example.com" also covers the bare domain (desktop fast path).
		{"*.gstatic.com", "fonts.gstatic.com", true},
		{"*.gstatic.com", "gstatic.com", true},
		{"*gstatic.com", "gstatic.com", true},
		// A leading dot is read as a wildcard.
		{".example.com", "a.example.com", true},
		// "^" prefixes mean "this is already a regular expression".
		{`^.*\.googleapis\.com$`, "maps.googleapis.com", true},
		{`^.*\.googleapis\.com$`, "googleapis.com", false},
		{`^foo`, "foobar.example", true},
		// An unusable regex falls back to literal matching instead of panicking.
		{`^((`, "^((", true},
		{"", "example.com", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.host); got != c.want {
			t.Fatalf("Match(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestNormalizeStripsPortAndCase(t *testing.T) {
	if got := Normalize("GitHub.COM:443"); got != "github.com" {
		t.Fatalf("Normalize = %q", got)
	}
	if got := Normalize("example.com."); got != "example.com" {
		t.Fatalf("trailing dot: %q", got)
	}
}

// The configuration uses a negative lookahead to exclude a family of hosts.
// RE2 has no lookaround, so it has to be rewritten rather than silently never
// matching — that behaviour cost us the working google preset address.
func TestLookaheadHostPattern(t *testing.T) {
	pat := `^(?!fonts).*(with)?google(apis|usercontent)?.com.*$`
	cases := map[string]bool{
		"www.google.com":       true,
		"accounts.google.com":  true,
		"fonts.googleapis.com": false,
		"fonts.gstatic.com":    false,
		"not-google.example":   false,
	}
	for host, want := range cases {
		if got := Match(pat, host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
}

// A prefix assertion excludes the whole family that starts with it.
func TestLookaheadPrefixExclusion(t *testing.T) {
	pat := `^(?!api\.).*\.example\.com$`
	if !Match(pat, "www.example.com") {
		t.Fatal("www.example.com should match")
	}
	if Match(pat, "api.internal.example.com") {
		t.Fatal("api.* hosts must be excluded")
	}
}

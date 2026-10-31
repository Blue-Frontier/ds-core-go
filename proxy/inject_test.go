package proxy

import (
	"strings"
	"testing"
)

func TestCSPWithSelf(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "adds self to existing script-src",
			in:   "default-src 'none'; script-src cdn.example.com 'sha256-abc'",
			want: "default-src 'none'; script-src 'self' cdn.example.com 'sha256-abc'",
		},
		{
			name: "leaves an already widened policy alone",
			in:   "script-src 'self' cdn.example.com",
			want: "script-src 'self' cdn.example.com",
		},
		{
			name: "prepends the directive when only default-src exists",
			in:   "default-src 'none'",
			want: "script-src 'self'; default-src 'none'",
		},
		{
			name: "handles script-src-elem",
			in:   "script-src-elem cdn.example.com; img-src 'self'",
			want: "script-src-elem 'self' cdn.example.com; img-src 'self'",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cspWithSelf(c.in)
			if got != c.want {
				t.Fatalf("cspWithSelf(%q) = %q, want %q", c.in, got, c.want)
			}
			// A directive name glued to its value is silently ignored by
			// browsers, which would disable the injected scripts outright.
			if strings.Contains(got, "script-src'self'") {
				t.Fatalf("CSP lost the separator: %q", got)
			}
		})
	}
}

package proxy

import (
	"testing"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// Only the listed hosts are covered, and only when the plugin is switched on.
func TestECHCoverage(t *testing.T) {
	cfg := config.ECH{
		Enabled: true,
		Use:     true,
		Domains: []string{"*openai.com", "^(.+\\.)?x\\.com$"},
	}
	e := newECH(cfg)
	if e == nil {
		t.Fatal("newECH returned nil for an enabled config")
	}
	if !e.covers("api.openai.com") {
		t.Fatal("openai host should be covered")
	}
	if !e.covers("x.com") || !e.covers("www.x.com") {
		t.Fatal("regex host should be covered")
	}
	if e.covers("example.org") {
		t.Fatal("unrelated host must not be covered")
	}

	off := cfg
	off.Enabled = false
	if newECH(off) != nil {
		t.Fatal("disabled ECH must not be active")
	}
}

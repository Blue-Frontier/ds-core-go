package dnsres

import (
	"path/filepath"
	"testing"
)

// A fresh process must not start from the DNS order: what earlier sessions
// learned about an address has to survive the restart.
func TestChoiceCacheSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-choice.json")

	first := loadChoiceCache(path)
	first.record("example.com", "10.0.0.1", true)
	first.record("example.com", "10.0.0.2", false)
	first.flush()

	// Simulate the app being killed and reopened.
	second := loadChoiceCache(path)
	seeded := second.seed("example.com", []string{"10.0.0.1", "10.0.0.2"})
	if len(seeded) != 2 {
		t.Fatalf("expected both addresses to be restored, got %d", len(seeded))
	}

	c := newIPChoice([]string{"10.0.0.1", "10.0.0.2"})
	c.stats = seeded
	c.doRank()
	if c.orderedList()[0] != "10.0.0.2" {
		t.Fatalf("expected the address that worked to lead, got %v", c.orderedList())
	}
}

func TestChoiceCacheDropsStaleHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-choice.json")
	c := loadChoiceCache(path)
	c.record("old.example", "10.0.0.9", false)
	c.mu.Lock()
	c.hosts["old.example"]["10.0.0.9"].TS = 0 // long expired
	c.dirty = true                            // record() already flushed once
	c.mu.Unlock()
	c.flush()

	if seeded := loadChoiceCache(path).seed("old.example", []string{"10.0.0.9"}); len(seeded) != 0 {
		t.Fatalf("stale entry should have been dropped")
	}
}

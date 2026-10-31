package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

func TestPresetDeadMemory(t *testing.T) {
	s := newSettingServer(t, config.Server{})
	if s.presetConsideredDead("example.com") {
		t.Fatal("nothing should be marked dead initially")
	}
	s.markPresetDead("example.com")
	if !s.presetConsideredDead("example.com") {
		t.Fatal("a failed preset list should be remembered")
	}
	if s.presetConsideredDead("other.example") {
		t.Fatal("the memory must be per host")
	}

	// The entry expires on its own.
	s.presetMu.Lock()
	s.presetDead["example.com"] = time.Now().Add(-time.Second)
	s.presetMu.Unlock()
	if s.presetConsideredDead("example.com") {
		t.Fatal("an expired entry should be dropped")
	}
}

// A mark that outlives the request which set it turns one bad round into
// minutes of "use DNS instead". The desktop kernel keeps no such state, so the
// window is a short cooldown and an unsuccessful DNS attempt clears it.
func TestPresetDeadClearedWhenSkippingWasWrong(t *testing.T) {
	s := newSettingServer(t, config.Server{})
	s.markPresetDead("example.com")
	s.clearPresetDead("example.com")
	if s.presetConsideredDead("example.com") {
		t.Fatal("clearing must make the preset eligible again")
	}

	if presetDeadTTL > time.Minute {
		t.Fatalf("cooldown %v is too long to survive a flaky address batch", presetDeadTTL)
	}
}

func TestSameIPSet(t *testing.T) {
	a := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	b := []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")}
	if !sameIPSet(a, b) {
		t.Fatal("order must not matter")
	}
	c := []net.IP{net.ParseIP("192.0.2.1")}
	if sameIPSet(a, c) {
		t.Fatal("different sizes are different sets")
	}
	if sameIPSet(a, []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.3")}) {
		t.Fatal("different members are different sets")
	}
}

// The resolver reports preset coverage, which gates the "stale hint" memory.
func TestUsesPreset(t *testing.T) {
	s := newSettingServer(t, config.Server{
		PreSetIPList: map[string]config.IPList{"preset.example": {"203.0.113.9"}},
	})
	if !s.st().dns.UsesPreset("preset.example") {
		t.Fatal("configured host should report preset coverage")
	}
	if s.st().dns.UsesPreset("other.example") {
		t.Fatal("unconfigured host must not report preset coverage")
	}
}

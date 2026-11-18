package proxy

import (
	"errors"
	"testing"
	"time"
)

// A host that just failed over HTTP/3 must not pay the handshake timeout again
// on the next request; the cool-off is what makes the opt-in usable on a network
// that filters UDP.
func TestQuicFailureCoolsOff(t *testing.T) {
	s := &Server{}
	s.noteQuicResult("example.com", errors.New("timeout"))
	if !s.quicRecentlyFailed("example.com") {
		t.Fatalf("host should be in the cool-off window after a failure")
	}
	if s.quicRecentlyFailed("other.example") {
		t.Fatalf("an unrelated host must not be affected")
	}

	// A later success clears the record.
	s.noteQuicResult("example.com", nil)
	if s.quicRecentlyFailed("example.com") {
		t.Fatalf("success should clear the cool-off")
	}

	// An old failure expires.
	s.noteQuicResult("old.example", errors.New("timeout"))
	s.quicMu.Lock()
	s.quicFail["old.example"] = time.Now().Add(-quicFailFor - time.Second)
	s.quicMu.Unlock()
	if s.quicRecentlyFailed("old.example") {
		t.Fatalf("a failure older than the window must not block")
	}
}

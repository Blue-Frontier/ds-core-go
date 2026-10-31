package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestReadPrefetchComplete(t *testing.T) {
	body := []byte("hello kernel")
	head, complete, err := readPrefetch(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("readPrefetch: %v", err)
	}
	if !complete {
		t.Fatalf("complete = false, want true for a body under the cap")
	}
	if !bytes.Equal(head, body) {
		t.Fatalf("head = %q, want %q", head, body)
	}
}

func TestReadPrefetchEmpty(t *testing.T) {
	head, complete, err := readPrefetch(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("readPrefetch: %v", err)
	}
	if !complete {
		t.Fatalf("complete = false, want true for an empty body")
	}
	if len(head) != 0 {
		t.Fatalf("head = %q, want empty", head)
	}
}

func TestReadPrefetchCapsAtPrefetchMax(t *testing.T) {
	big := bytes.Repeat([]byte("x"), prefetchMax+4096)
	head, complete, err := readPrefetch(bytes.NewReader(big))
	if err != nil {
		t.Fatalf("readPrefetch: %v", err)
	}
	if complete {
		t.Fatalf("complete = true, want false when the body exceeds the cap")
	}
	if len(head) != prefetchMax {
		t.Fatalf("prefetched %d bytes, want exactly %d", len(head), prefetchMax)
	}
}

// A stalled body must trip the idle deadline instead of blocking forever; that
// is what turns a blackholed upstream into a fast 502 rather than a white page.
func TestIdleReaderTripsOnStall(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ir := &idleReader{r: client, conn: client, idle: 60 * time.Millisecond}
	buf := make([]byte, 16)

	start := time.Now()
	_, err := ir.Read(buf)
	if err == nil {
		t.Fatal("Read returned nil error, want a timeout")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected a net.Error timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %v, want ~60ms", elapsed)
	}
}

// Progress keeps the transfer alive: each Read re-arms the deadline, so a body
// that trickles data never trips the idle budget.
func TestIdleReaderKeepsAliveWithProgress(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ir := &idleReader{r: client, conn: client, idle: 100 * time.Millisecond}
	go func() {
		for i := 0; i < 3; i++ {
			_, _ = server.Write([]byte("ab"))
			time.Sleep(40 * time.Millisecond)
		}
	}()

	buf := make([]byte, 8)
	total := 0
	for total < 6 {
		n, err := ir.Read(buf)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", total, err)
		}
		total += n
	}
	if total != 6 {
		t.Fatalf("read %d bytes, want 6", total)
	}
}

// streamBody must replay the prefetched head before continuing with the live
// body, without losing or duplicating bytes.
func TestStreamBodyReplaysHeadThenRest(t *testing.T) {
	sb := &streamBody{head: []byte("head"), rest: bytes.NewReader([]byte("-rest"))}
	got, err := io.ReadAll(sb)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "head-rest" {
		t.Fatalf("streamBody = %q, want %q", got, "head-rest")
	}
}

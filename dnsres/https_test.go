package dnsres

import (
	"bytes"
	"testing"
)

func TestParseHTTPSRecord(t *testing.T) {
	// priority 1, target ".", alpn=["h2","http/1.1"], ech=<6 bytes>
	var b bytes.Buffer
	b.Write([]byte{0, 1}) // priority
	b.WriteByte(0)        // root target

	b.Write([]byte{0, 1})  // key 1 = alpn
	b.Write([]byte{0, 12}) // length: 3 + 9 bytes
	b.Write([]byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})

	b.Write([]byte{0, 5, 0, 6})       // key 5 = ech, length 6
	b.Write([]byte{0, 4, 1, 2, 3, 4}) // ECHConfigList (2-byte length + payload)

	rec, err := ParseHTTPS(b.Bytes())
	if err != nil {
		t.Fatalf("ParseHTTPS: %v", err)
	}
	if rec.Priority != 1 {
		t.Fatalf("priority = %d", rec.Priority)
	}
	if rec.Target != "" {
		t.Fatalf("target = %q", rec.Target)
	}
	if len(rec.ALPN) != 2 || rec.ALPN[0] != "h2" || rec.ALPN[1] != "http/1.1" {
		t.Fatalf("alpn = %v", rec.ALPN)
	}
	if !bytes.Equal(rec.ECH, []byte{0, 4, 1, 2, 3, 4}) {
		t.Fatalf("ech = %v", rec.ECH)
	}
}

// A record without ECH still parses; the kernel then simply skips ECH.
func TestParseHTTPSWithoutECH(t *testing.T) {
	var b bytes.Buffer
	b.Write([]byte{0, 0})
	b.Write([]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0})
	b.Write([]byte{0, 3, 0, 2, 0, 1}) // unknown key 3, 2 bytes

	rec, err := ParseHTTPS(b.Bytes())
	if err != nil {
		t.Fatalf("ParseHTTPS: %v", err)
	}
	if rec.Target != "www.example" {
		t.Fatalf("target = %q", rec.Target)
	}
	if len(rec.ECH) != 0 {
		t.Fatalf("ech should be empty, got %v", rec.ECH)
	}
}

func TestParseHTTPSRejectsTruncatedParam(t *testing.T) {
	data := []byte{0, 1, 0, 0, 5, 0, 9, 1} // param claims 9 bytes, only 1 present
	if _, err := ParseHTTPS(data); err == nil {
		t.Fatal("want an error for a truncated parameter")
	}
}

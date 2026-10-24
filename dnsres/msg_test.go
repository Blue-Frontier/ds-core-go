package dnsres

import (
	"testing"
)

// mustBuildQuery encodes a query and returns header id + question name.
func mustBuildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	return encodeQuery(name, qtype)
}

// TestEncodeQueryLayout checks the wire layout of a simple A query.
func TestEncodeQueryLayout(t *testing.T) {
	q := encodeQuery("a.example.com", typeA)
	// header(12) + "a"(2) + "example"(8) + "com"(4) + root(1) + type/class(4)
	if len(q) != 31 {
		t.Fatalf("query length = %d, want 31", len(q))
	}
	// flags: RD set
	if q[2] != 0x01 || q[3] != 0x00 {
		t.Errorf("flags = % x", q[2:4])
	}
	// question type A, class IN
	tail := string(q[len(q)-4:])
	if tail != "\x00\x01\x00\x01" {
		t.Errorf("question tail = % x", q[len(q)-4:])
	}
}

// TestParseRoundTripA builds an A response and parses it back.
func TestParseRoundTripA(t *testing.T) {
	q := mustBuildQuery(t, "www.example.com", typeA)

	// Craft the response by hand: same header (flipped to response), same
	// question, one A answer with a compression pointer to the name.
	r := append([]byte(nil), q[:msgHeaderLen]...) // reuse id + questions
	r[2] = 0x81                                   // response + recursion desired
	r[3] = 0x80                                   // recursion available
	r[6], r[7] = 0, 1
	r[8], r[9] = 0, 1
	r = append(r, q[msgHeaderLen:]...)

	rr := []byte{0xc0, 0x0c} // name pointer to offset 12 (the question name)
	rr = append(rr, 0x00, byte(typeA))
	rr = append(rr, 0x00, 0x01)             // class
	rr = append(rr, 0x00, 0x00, 0x02, 0x03) // ttl 515
	rr = append(rr, 0x00, 0x04)             // rdlength
	rr = append(rr, 198, 18, 0, 1)
	r = append(r, rr...)

	resp, err := parseResponse(r)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if resp.rcode != 0 || resp.truncated {
		t.Fatalf("header bad: %+v", resp)
	}
	if len(resp.answers) != 1 {
		t.Fatalf("answers = %d", len(resp.answers))
	}
	a := resp.answers[0]
	if a.typ != typeA || a.ttl != 515 {
		t.Errorf("answer meta = %+v", a)
	}
	if a.name != "www.example.com" {
		t.Errorf("uncompressed name: %q (want www.example.com)", a.name)
	}
	ips := resp.answerIPs(typeA)
	if len(ips) != 1 || ips[0] != "198.18.0.1" {
		t.Errorf("answerIPs = %v", ips)
	}
	if got := resp.answerIPs(typeAAAA); len(got) != 0 {
		t.Errorf("AAAA filter = %v", got)
	}
}

// TestParseAAAA covers a literal (uncompressed) AAAA answer.
func TestParseAAAA(t *testing.T) {
	r := make([]byte, msgHeaderLen)
	r[2], r[3] = 0x80, 0x00
	r[5], r[7] = 1, 1
	r = appendDomainName(r, "v6.example.com")
	r = append(r, 0x00, byte(typeAAAA), 0x00, 0x01) // question type/class
	r = appendDomainName(r, "v6.example.com")
	r = append(r, 0x00, byte(typeAAAA), 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x10)
	r = append(r, 0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)

	resp, err := parseResponse(r)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	ips := resp.answerIPs(typeAAAA)
	if len(ips) != 1 || ips[0] != "fd00::1" {
		t.Errorf("AAAA = %v", ips)
	}
}

// TestParseBadInput guards the parser.
func TestParseBadInput(t *testing.T) {
	if _, err := parseResponse([]byte{0, 1}); err == nil {
		t.Error("short message accepted")
	}
}

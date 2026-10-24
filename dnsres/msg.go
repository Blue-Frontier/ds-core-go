package dnsres

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
)

// Minimal DNS wire format codec (RFC 1035), enough for A (1) / AAAA (28)
// queries with recursion desired and untruncated responses. Written by hand to
// keep the kernel dependency-free; the desktop kernel uses `dns-packet`.

// Question / record types used by the resolver.
const (
	typeA    = 1
	typeAAAA = 28
)

// msgHeaderLen is the fixed header length (ID, flags, counts).
const msgHeaderLen = 12

// answer is one decoded resource record.
type answer struct {
	name string
	typ  uint16
	ttl  uint32
	data []byte // raw RDATA
}

// response is a decoded DNS response.
type response struct {
	rcode     int
	truncated bool
	answers   []answer
}

// encodeQuery builds a single-question A/AAAA query packet.
func encodeQuery(name string, qtype uint16) []byte {
	buf := make([]byte, 0, 64)
	var hdr [msgHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(rand.Intn(0xffff)))
	// flags: recursion desired (0x0100)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // 1 question
	buf = append(buf, hdr[:]...)

	buf = appendDomainName(buf, name)
	var q [4]byte
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], 1) // class IN
	return append(buf, q[:]...)
}

// appendDomainName appends name in wire format (length prefixed labels).
func appendDomainName(buf []byte, name string) []byte {
	name = trimTrailingDot(name)
	if name == "" {
		return append(buf, 0)
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			if label != "" && len(label) <= 63 {
				buf = append(buf, byte(len(label)))
				buf = append(buf, label...)
			}
			start = i + 1
		}
	}
	return append(buf, 0)
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// parseResponse decodes a DNS response (raw UDP payload or framed TCP body).
func parseResponse(b []byte) (*response, error) {
	if len(b) < msgHeaderLen {
		return nil, errors.New("dnsres: short message")
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	qdCount := binary.BigEndian.Uint16(b[4:6])
	anCount := binary.BigEndian.Uint16(b[6:8])

	r := &response{
		rcode:     int(flags & 0xf),
		truncated: flags&0x0200 != 0,
	}
	off := msgHeaderLen
	for i := 0; i < int(qdCount); i++ {
		var err error
		if _, off, err = parseDomainName(b, off); err != nil {
			return nil, err
		}
		if off+4 > len(b) {
			return nil, errors.New("dnsres: truncated question")
		}
		off += 4
	}
	for i := 0; i < int(anCount); i++ {
		name, next, err := parseDomainName(b, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(b) {
			return nil, errors.New("dnsres: truncated rr header")
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		ttl := binary.BigEndian.Uint32(b[off+4 : off+8])
		rdLen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdLen > len(b) {
			return nil, errors.New("dnsres: truncated rdata")
		}
		r.answers = append(r.answers, answer{
			name: name,
			typ:  typ,
			ttl:  ttl,
			data: b[off : off+rdLen],
		})
		off += rdLen
	}
	return r, nil
}

// answerIPs returns the addresses of `qtype` records, in wire order.
func (r *response) answerIPs(qtype uint16) []string {
	var ips []string
	for _, a := range r.answers {
		if a.typ != qtype {
			continue
		}
		switch qtype {
		case typeA:
			if len(a.data) != net.IPv4len {
				continue
			}
			ips = append(ips, net.IP(a.data).String())
		case typeAAAA:
			if len(a.data) != net.IPv6len {
				continue
			}
			ips = append(ips, net.IP(a.data).String())
		}
	}
	return ips
}

// parseDomainName decodes a (possibly compressed) domain name and returns the
// name plus the offset just past it in the original buffer.
func parseDomainName(b []byte, off int) (string, int, error) {
	var sb []byte
	idx := off
	next := -1 // offset just past the name (already known before the first pointer)
	for depth := 0; depth < 64; depth++ {
		if idx < 0 || idx >= len(b) {
			return "", next, errors.New("dnsres: bad name offset")
		}
		length := int(b[idx])
		switch {
		case length == 0:
			if next < 0 {
				next = idx + 1
			}
			return string(sb), next, nil
		case length&0xc0 == 0xc0: // compression pointer to an earlier name
			if idx+1 >= len(b) {
				return "", next, errors.New("dnsres: truncated pointer")
			}
			if next < 0 {
				next = idx + 2
			}
			idx = int(binary.BigEndian.Uint16(b[idx:idx+2]) & 0x3fff)
		case length&0xc0 != 0:
			return "", next, errors.New("dnsres: unsupported label type")
		default:
			if idx+1+length > len(b) {
				return "", next, errors.New("dnsres: truncated label")
			}
			if len(sb) > 0 {
				sb = append(sb, '.')
			}
			sb = append(sb, b[idx+1:idx+1+length]...)
			idx += 1 + length
		}
	}
	return "", next, errors.New("dnsres: name too deep")
}

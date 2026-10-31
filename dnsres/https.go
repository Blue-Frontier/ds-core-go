package dnsres

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// typeHTTPS is the DNS HTTPS resource record (RFC 9460), which carries the
// ECHConfigList a client needs for Encrypted Client Hello.
const typeHTTPS = 65

// SVCB parameter keys we care about.
const (
	svcbALPN = 1
	svcbECH  = 5
)

// HTTPSRecord is the part of an HTTPS (type 65) record the kernel uses.
type HTTPSRecord struct {
	Priority uint16
	Target   string
	ALPN     []string
	// ECH is a serialized ECHConfigList, ready for crypto/tls.
	ECH []byte
}

// LookupHTTPS asks the named provider (falling back to the host's usual one)
// for its HTTPS record. A missing record is not an error.
func (r *Resolver) LookupHTTPS(ctx context.Context, host, providerName string) (*HTTPSRecord, error) {
	p := r.providers[providerName]
	if p == nil {
		p = r.primary(host)
	}
	if p == nil {
		return nil, errors.New("dnsres: no provider for HTTPS lookup")
	}
	raws, err := p.queryRawList(ctx, host, typeHTTPS)
	if err != nil {
		return nil, err
	}
	// Providers return several records (aliases plus the one carrying params);
	// the useful one is whichever actually carries an ECH config.
	var fallback *HTTPSRecord
	for _, raw := range raws {
		rec, perr := ParseHTTPS(raw)
		if perr != nil {
			continue
		}
		if len(rec.ECH) > 0 {
			return rec, nil
		}
		if fallback == nil && (len(rec.ALPN) > 0 || rec.Target != "") {
			fallback = rec
		}
	}
	return fallback, nil
}

// ParseHTTPS decodes the RDATA of an HTTPS record.
func ParseHTTPS(data []byte) (*HTTPSRecord, error) {
	if len(data) < 3 {
		return nil, errors.New("dnsres: short HTTPS record")
	}
	rec := &HTTPSRecord{Priority: binary.BigEndian.Uint16(data[:2])}
	target, next, err := parseDomainName(data, 2)
	if err != nil {
		return nil, err
	}
	rec.Target = target

	off := next
	for off+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[off : off+2])
		length := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if off+length > len(data) {
			return nil, errors.New("dnsres: truncated SVCB parameter")
		}
		value := data[off : off+length]
		off += length

		switch key {
		case svcbALPN:
			rec.ALPN = parseALPN(value)
		case svcbECH:
			// The parameter value is the ECHConfigList itself, which already
			// carries its own two-byte length prefix.
			rec.ECH = append([]byte(nil), value...)
		}
	}
	return rec, nil
}

// parseALPN decodes the length-prefixed protocol identifiers of the alpn key.
func parseALPN(value []byte) []string {
	var out []string
	for i := 0; i < len(value); {
		n := int(value[i])
		i++
		if n == 0 || i+n > len(value) {
			break
		}
		out = append(out, string(value[i:i+n]))
		i += n
	}
	return out
}

// String renders the record for logs.
func (h *HTTPSRecord) String() string {
	return fmt.Sprintf("priority=%d target=%q alpn=[%s] ech=%d bytes",
		h.Priority, h.Target, strings.Join(h.ALPN, ","), len(h.ECH))
}

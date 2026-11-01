package dns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// RData is the type-specific payload of a resource record.
type RData interface {
	// Type is the record type this payload belongs to.
	Type() Type
	// String renders the payload in zone-file presentation format.
	String() string
	pack(b []byte, comp compressor) ([]byte, error)
}

// A is an IPv4 address record.
type A struct{ Addr netip.Addr }

// AAAA is an IPv6 address record.
type AAAA struct{ Addr netip.Addr }

// NS names an authoritative name server.
type NS struct{ Host string }

// CNAME makes the owner an alias for Target.
type CNAME struct{ Target string }

// PTR points to another name, typically for reverse lookups.
type PTR struct{ Ptr string }

// MX names a mail exchanger with a preference (lower is preferred).
type MX struct {
	Pref     uint16
	Exchange string
}

// TXT holds one or more character-strings of up to 255 octets each.
type TXT struct{ Texts []string }

// SRV locates a service (RFC 2782).
type SRV struct {
	Priority, Weight, Port uint16
	Target                 string
}

// SOA marks the start of a zone of authority.
type SOA struct {
	MName, RName                           string
	Serial, Refresh, Retry, Expire, MinTTL uint32
}

// Unknown carries RDATA for types without a dedicated struct (RFC 3597).
type Unknown struct {
	T    Type
	Data []byte
}

func (A) Type() Type         { return TypeA }
func (AAAA) Type() Type      { return TypeAAAA }
func (NS) Type() Type        { return TypeNS }
func (CNAME) Type() Type     { return TypeCNAME }
func (PTR) Type() Type       { return TypePTR }
func (MX) Type() Type        { return TypeMX }
func (TXT) Type() Type       { return TypeTXT }
func (SRV) Type() Type       { return TypeSRV }
func (SOA) Type() Type       { return TypeSOA }
func (u Unknown) Type() Type { return u.T }

func (r A) String() string     { return r.Addr.String() }
func (r AAAA) String() string  { return r.Addr.String() }
func (r NS) String() string    { return r.Host }
func (r CNAME) String() string { return r.Target }
func (r PTR) String() string   { return r.Ptr }
func (r MX) String() string    { return fmt.Sprintf("%d %s", r.Pref, r.Exchange) }
func (r SRV) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
}
func (r SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
}
func (r TXT) String() string {
	parts := make([]string, len(r.Texts))
	for i, t := range r.Texts {
		parts[i] = quoteText(t)
	}
	return strings.Join(parts, " ")
}
func (r Unknown) String() string {
	if len(r.Data) == 0 {
		return "\\# 0"
	}
	return fmt.Sprintf("\\# %d %s", len(r.Data), strings.ToUpper(hex.EncodeToString(r.Data)))
}

// quoteText renders a character-string with zone-file escaping.
func quoteText(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x20 || c > 0x7E:
			fmt.Fprintf(&sb, "\\%03d", c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func (r A) pack(b []byte, _ compressor) ([]byte, error) {
	if !r.Addr.Is4() {
		return nil, fmt.Errorf("dns: A record needs an IPv4 address, got %v", r.Addr)
	}
	a := r.Addr.As4()
	return append(b, a[:]...), nil
}

func (r AAAA) pack(b []byte, _ compressor) ([]byte, error) {
	if !r.Addr.Is6() || r.Addr.Is4In6() {
		return nil, fmt.Errorf("dns: AAAA record needs an IPv6 address, got %v", r.Addr)
	}
	a := r.Addr.As16()
	return append(b, a[:]...), nil
}

func (r NS) pack(b []byte, c compressor) ([]byte, error)    { return packName(b, r.Host, c) }
func (r CNAME) pack(b []byte, c compressor) ([]byte, error) { return packName(b, r.Target, c) }
func (r PTR) pack(b []byte, c compressor) ([]byte, error)   { return packName(b, r.Ptr, c) }

func (r MX) pack(b []byte, c compressor) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, r.Pref)
	return packName(b, r.Exchange, c)
}

func (r SRV) pack(b []byte, _ compressor) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, r.Priority)
	b = binary.BigEndian.AppendUint16(b, r.Weight)
	b = binary.BigEndian.AppendUint16(b, r.Port)
	return packName(b, r.Target, nil) // RFC 2782: target is never compressed
}

func (r SOA) pack(b []byte, c compressor) ([]byte, error) {
	b, err := packName(b, r.MName, c)
	if err != nil {
		return nil, err
	}
	if b, err = packName(b, r.RName, c); err != nil {
		return nil, err
	}
	for _, v := range []uint32{r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b, nil
}

func (r TXT) pack(b []byte, _ compressor) ([]byte, error) {
	if len(r.Texts) == 0 {
		return nil, errors.New("dns: TXT record needs at least one string")
	}
	for _, t := range r.Texts {
		if len(t) > 255 {
			return nil, errors.New("dns: TXT character-string longer than 255 octets")
		}
		b = append(b, byte(len(t)))
		b = append(b, t...)
	}
	return b, nil
}

func (r Unknown) pack(b []byte, _ compressor) ([]byte, error) { return append(b, r.Data...), nil }

// unpackRData decodes rdlen octets at off. msg is the whole message so
// compressed names inside RDATA can be followed.
func unpackRData(t Type, msg []byte, off, rdlen int) (RData, error) {
	end := off + rdlen
	if end > len(msg) {
		return nil, ErrShortBuffer
	}
	rd := msg[off:end]
	name := func(at int) (string, int, error) {
		n, next, err := unpackName(msg, at)
		if err == nil && next > end {
			err = ErrShortBuffer
		}
		return n, next, err
	}
	switch t {
	case TypeA:
		if rdlen != 4 {
			return nil, fmt.Errorf("dns: A rdata length %d", rdlen)
		}
		return A{netip.AddrFrom4([4]byte(rd))}, nil
	case TypeAAAA:
		if rdlen != 16 {
			return nil, fmt.Errorf("dns: AAAA rdata length %d", rdlen)
		}
		return AAAA{netip.AddrFrom16([16]byte(rd))}, nil
	case TypeNS, TypeCNAME, TypePTR:
		n, next, err := name(off)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, errors.New("dns: trailing bytes after name in rdata")
		}
		switch t {
		case TypeNS:
			return NS{n}, nil
		case TypeCNAME:
			return CNAME{n}, nil
		}
		return PTR{n}, nil
	case TypeMX:
		if rdlen < 3 {
			return nil, ErrShortBuffer
		}
		n, next, err := name(off + 2)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, errors.New("dns: trailing bytes in MX rdata")
		}
		return MX{binary.BigEndian.Uint16(rd), n}, nil
	case TypeSRV:
		if rdlen < 7 {
			return nil, ErrShortBuffer
		}
		n, next, err := name(off + 6)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, errors.New("dns: trailing bytes in SRV rdata")
		}
		return SRV{binary.BigEndian.Uint16(rd), binary.BigEndian.Uint16(rd[2:]), binary.BigEndian.Uint16(rd[4:]), n}, nil
	case TypeSOA:
		m, next, err := name(off)
		if err != nil {
			return nil, err
		}
		r, next, err := name(next)
		if err != nil {
			return nil, err
		}
		if end-next != 20 {
			return nil, errors.New("dns: bad SOA rdata length")
		}
		v := msg[next:end]
		u := func(i int) uint32 { return binary.BigEndian.Uint32(v[i*4:]) }
		return SOA{m, r, u(0), u(1), u(2), u(3), u(4)}, nil
	case TypeTXT:
		var texts []string
		for i := 0; i < len(rd); {
			l := int(rd[i])
			if i+1+l > len(rd) {
				return nil, ErrShortBuffer
			}
			texts = append(texts, string(rd[i+1:i+1+l]))
			i += 1 + l
		}
		if len(texts) == 0 {
			return nil, errors.New("dns: empty TXT rdata")
		}
		return TXT{texts}, nil
	}
	return Unknown{t, bytes.Clone(rd)}, nil
}

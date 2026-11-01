// Package dns implements the DNS wire format described in RFC 1035:
// domain names with message compression, headers, questions and resource
// records for the common record types, plus RFC 3597 opaque records for
// everything else.
package dns

import (
	"errors"
	"fmt"
	"strings"
)

// Limits from RFC 1035 section 2.3.4.
const (
	MaxLabelLen = 63
	MaxNameLen  = 255 // wire length, including length octets and the root label
)

var (
	ErrLabelTooLong = errors.New("dns: label longer than 63 octets")
	ErrNameTooLong  = errors.New("dns: name longer than 255 octets")
	ErrEmptyLabel   = errors.New("dns: empty label")
	ErrPointerLoop  = errors.New("dns: compression pointer loop or forward pointer")
	ErrShortBuffer  = errors.New("dns: message truncated")
	ErrBadLabelType = errors.New("dns: reserved label type")
)

// CanonicalName validates a presentation-format name and returns it fully
// qualified (with a trailing dot). Case is preserved; use EqualNames to
// compare. The empty string and "." both mean the root.
func CanonicalName(s string) (string, error) {
	if s == "" || s == "." {
		return ".", nil
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	wire := 1 // root label
	for _, l := range strings.Split(s[:len(s)-1], ".") {
		if l == "" {
			return "", fmt.Errorf("%w in %q", ErrEmptyLabel, s)
		}
		if len(l) > MaxLabelLen {
			return "", fmt.Errorf("%w: %q", ErrLabelTooLong, l)
		}
		wire += 1 + len(l)
	}
	if wire > MaxNameLen {
		return "", ErrNameTooLong
	}
	return s, nil
}

// MustName is CanonicalName for names known to be valid; it panics otherwise.
func MustName(s string) string {
	n, err := CanonicalName(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Labels splits a fully qualified name into its labels, leftmost first.
// The root name has no labels.
func Labels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// EqualNames compares two names case-insensitively (RFC 4343).
func EqualNames(a, b string) bool {
	return strings.EqualFold(fqdn(a), fqdn(b))
}

// IsSubdomain reports whether child is equal to or below parent.
func IsSubdomain(child, parent string) bool {
	c, p := strings.ToLower(fqdn(child)), strings.ToLower(fqdn(parent))
	if p == "." {
		return true
	}
	return c == p || strings.HasSuffix(c, "."+p)
}

// Parent returns the name with its leftmost label removed ("." for the root).
func Parent(name string) string {
	name = fqdn(name)
	if name == "." {
		return "."
	}
	i := strings.IndexByte(name, '.')
	if i == len(name)-1 {
		return "."
	}
	return name[i+1:]
}

func fqdn(s string) string {
	if s == "" || s == "." {
		return "."
	}
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// compressor remembers where name suffixes were written so later names can
// point at them. Keys are matched exactly, so the case of every name is
// preserved on the wire (RFC 4343).
type compressor map[string]int

// packName appends the wire form of name. When comp is non-nil, suffixes
// already present in the message are replaced with 14-bit pointers.
func packName(b []byte, name string, comp compressor) ([]byte, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return nil, err
	}
	labels := Labels(name)
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if comp != nil {
			if off, ok := comp[suffix]; ok {
				return append(b, 0xC0|byte(off>>8), byte(off)), nil
			}
			if len(b) < 0x3FFF {
				comp[suffix] = len(b)
			}
		}
		b = append(b, byte(len(labels[i])))
		b = append(b, labels[i]...)
	}
	return append(b, 0), nil
}

// unpackName reads a possibly compressed name starting at off and returns
// it with the offset just past the name in the original stream. Pointers
// must point strictly backwards, which rules out loops.
func unpackName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1    // where parsing resumes after the first pointer
	limit := off // pointers must land before this
	wire := 0
	for {
		if off >= len(msg) {
			return "", 0, ErrShortBuffer
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				off++
				if end < 0 {
					end = off
				}
				if sb.Len() == 0 {
					return ".", end, nil
				}
				return sb.String(), end, nil
			}
			if off+1+c > len(msg) {
				return "", 0, ErrShortBuffer
			}
			wire += 1 + c
			if wire+1 > MaxNameLen {
				return "", 0, ErrNameTooLong
			}
			label := msg[off+1 : off+1+c]
			if strings.IndexByte(string(label), '.') >= 0 {
				return "", 0, fmt.Errorf("dns: label contains a dot: %q", label)
			}
			sb.Write(label)
			sb.WriteByte('.')
			off += 1 + c
		case 0xC0:
			if off+1 >= len(msg) {
				return "", 0, ErrShortBuffer
			}
			ptr := (c&0x3F)<<8 | int(msg[off+1])
			if ptr >= limit {
				return "", 0, ErrPointerLoop
			}
			if end < 0 {
				end = off + 2
			}
			limit = ptr
			off = ptr
		default:
			return "", 0, ErrBadLabelType
		}
	}
}

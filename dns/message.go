package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Header is the fixed 12-octet message header minus the section counts.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	RCode              RCode
}

// Question is an entry in the question section.
type Question struct {
	Name  string
	Type  Type
	Class Class
}

func (q Question) String() string {
	return fmt.Sprintf("%s %s %s", q.Name, q.Class, q.Type)
}

// RR is a resource record. For OPT pseudo-records (RFC 6891) Class holds
// the advertised UDP payload size and TTL the extended flags.
type RR struct {
	Name  string
	Class Class
	TTL   uint32
	Data  RData
}

// Type returns the record type of the payload.
func (r RR) Type() Type { return r.Data.Type() }

// String renders the record as a zone-file line.
func (r RR) String() string {
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", r.Name, r.TTL, r.Class, r.Type(), r.Data)
}

// Message is a complete DNS message.
type Message struct {
	Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

const headerLen = 12

func (h Header) flags() uint16 {
	var f uint16
	if h.Response {
		f |= 1 << 15
	}
	f |= uint16(h.Opcode&0xF) << 11
	if h.Authoritative {
		f |= 1 << 10
	}
	if h.Truncated {
		f |= 1 << 9
	}
	if h.RecursionDesired {
		f |= 1 << 8
	}
	if h.RecursionAvailable {
		f |= 1 << 7
	}
	return f | uint16(h.RCode&0xF)
}

func headerFromFlags(id, f uint16) Header {
	return Header{
		ID:                 id,
		Response:           f&(1<<15) != 0,
		Opcode:             uint8(f>>11) & 0xF,
		Authoritative:      f&(1<<10) != 0,
		Truncated:          f&(1<<9) != 0,
		RecursionDesired:   f&(1<<8) != 0,
		RecursionAvailable: f&(1<<7) != 0,
		RCode:              RCode(f & 0xF),
	}
}

// Pack serialises the message with name compression.
func (m *Message) Pack() ([]byte, error) {
	return m.AppendPack(make([]byte, 0, 512))
}

// AppendPack appends the wire form of m to b. Compression offsets are
// relative to len(b), so b should normally be empty.
func (m *Message) AppendPack(b []byte) ([]byte, error) {
	for _, n := range []int{len(m.Questions), len(m.Answers), len(m.Authority), len(m.Additional)} {
		if n > 0xFFFF {
			return nil, errors.New("dns: too many records in a section")
		}
	}
	base := len(b)
	b = binary.BigEndian.AppendUint16(b, m.ID)
	b = binary.BigEndian.AppendUint16(b, m.flags())
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Questions)))
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Answers)))
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Authority)))
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Additional)))
	comp := compressor{}
	var err error
	// Compression offsets are absolute within the message, so packing works
	// on a sub-slice that starts at the header.
	msg := b[base:]
	for _, q := range m.Questions {
		if msg, err = packName(msg, q.Name, comp); err != nil {
			return nil, err
		}
		msg = binary.BigEndian.AppendUint16(msg, uint16(q.Type))
		msg = binary.BigEndian.AppendUint16(msg, uint16(q.Class))
	}
	for _, sec := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for _, rr := range sec {
			if msg, err = packRR(msg, rr, comp); err != nil {
				return nil, err
			}
		}
	}
	return append(b[:base], msg...), nil
}

func packRR(b []byte, rr RR, comp compressor) ([]byte, error) {
	if rr.Data == nil {
		return nil, errors.New("dns: record without data")
	}
	b, err := packName(b, rr.Name, comp)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Type()))
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Class))
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	lenAt := len(b)
	b = append(b, 0, 0)
	if b, err = rr.Data.pack(b, comp); err != nil {
		return nil, fmt.Errorf("%s %s: %w", rr.Name, rr.Type(), err)
	}
	rdlen := len(b) - lenAt - 2
	if rdlen > 0xFFFF {
		return nil, errors.New("dns: rdata longer than 65535 octets")
	}
	binary.BigEndian.PutUint16(b[lenAt:], uint16(rdlen))
	return b, nil
}

// Unpack parses a wire-format message. It rejects trailing garbage and
// sections whose counts do not match the data.
func Unpack(msg []byte) (*Message, error) {
	if len(msg) < headerLen {
		return nil, ErrShortBuffer
	}
	m := &Message{Header: headerFromFlags(binary.BigEndian.Uint16(msg), binary.BigEndian.Uint16(msg[2:]))}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	ar := int(binary.BigEndian.Uint16(msg[10:]))
	off := headerLen
	for i := 0; i < qd; i++ {
		name, next, err := unpackName(msg, off)
		if err != nil {
			return nil, fmt.Errorf("question %d: %w", i, err)
		}
		if next+4 > len(msg) {
			return nil, ErrShortBuffer
		}
		m.Questions = append(m.Questions, Question{name, Type(binary.BigEndian.Uint16(msg[next:])), Class(binary.BigEndian.Uint16(msg[next+2:]))})
		off = next + 4
	}
	sections := []*[]RR{&m.Answers, &m.Authority, &m.Additional}
	for si, count := range []int{an, ns, ar} {
		for i := 0; i < count; i++ {
			rr, next, err := unpackRR(msg, off)
			if err != nil {
				return nil, fmt.Errorf("section %d record %d: %w", si+1, i, err)
			}
			*sections[si] = append(*sections[si], rr)
			off = next
		}
	}
	if off != len(msg) {
		return nil, fmt.Errorf("dns: %d trailing bytes after message", len(msg)-off)
	}
	return m, nil
}

func unpackRR(msg []byte, off int) (RR, int, error) {
	name, off, err := unpackName(msg, off)
	if err != nil {
		return RR{}, 0, err
	}
	if off+10 > len(msg) {
		return RR{}, 0, ErrShortBuffer
	}
	t := Type(binary.BigEndian.Uint16(msg[off:]))
	rr := RR{Name: name, Class: Class(binary.BigEndian.Uint16(msg[off+2:])), TTL: binary.BigEndian.Uint32(msg[off+4:])}
	rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if rr.Data, err = unpackRData(t, msg, off, rdlen); err != nil {
		return RR{}, 0, err
	}
	return rr, off + rdlen, nil
}

// String renders the message roughly the way dig does.
func (m *Message) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, ";; opcode: %d, status: %s, id: %d\n", m.Opcode, m.RCode, m.ID)
	var fl []string
	for _, f := range []struct {
		on   bool
		name string
	}{{m.Response, "qr"}, {m.Authoritative, "aa"}, {m.Truncated, "tc"}, {m.RecursionDesired, "rd"}, {m.RecursionAvailable, "ra"}} {
		if f.on {
			fl = append(fl, f.name)
		}
	}
	fmt.Fprintf(&sb, ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		strings.Join(fl, " "), len(m.Questions), len(m.Answers), len(m.Authority), len(m.Additional))
	if len(m.Questions) > 0 {
		sb.WriteString("\n;; QUESTION SECTION:\n")
		for _, q := range m.Questions {
			fmt.Fprintf(&sb, ";%s\n", q)
		}
	}
	for _, s := range []struct {
		title string
		rrs   []RR
	}{{"ANSWER", m.Answers}, {"AUTHORITY", m.Authority}, {"ADDITIONAL", m.Additional}} {
		if len(s.rrs) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "\n;; %s SECTION:\n", s.title)
		for _, rr := range s.rrs {
			sb.WriteString(rr.String())
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// NewQuery builds a recursion-desired query for name/type in class IN.
func NewQuery(id uint16, name string, t Type) (*Message, error) {
	n, err := CanonicalName(name)
	if err != nil {
		return nil, err
	}
	return &Message{
		Header:    Header{ID: id, RecursionDesired: true},
		Questions: []Question{{n, t, ClassINET}},
	}, nil
}

// Reply starts a response to q: same ID, opcode, question and RD bit.
func (m *Message) Reply() *Message {
	r := &Message{Header: Header{ID: m.ID, Response: true, Opcode: m.Opcode, RecursionDesired: m.RecursionDesired}}
	r.Questions = append(r.Questions, m.Questions...)
	return r
}

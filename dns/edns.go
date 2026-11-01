package dns

// MinUDPSize is the classic 512-octet limit for UDP messages without EDNS.
const MinUDPSize = 512

// EDNS returns the UDP payload size advertised by an OPT pseudo-record
// (RFC 6891). ok is false when the message carries no OPT record.
func (m *Message) EDNS() (size uint16, ok bool) {
	for _, rr := range m.Additional {
		if rr.Type() == TypeOPT {
			size = uint16(rr.Class)
			if size < MinUDPSize {
				size = MinUDPSize
			}
			return size, true
		}
	}
	return 0, false
}

// SetEDNS adds or replaces the OPT record advertising size.
func (m *Message) SetEDNS(size uint16) {
	opt := RR{Name: ".", Class: Class(size), Data: Unknown{T: TypeOPT, Data: []byte{}}}
	for i, rr := range m.Additional {
		if rr.Type() == TypeOPT {
			m.Additional[i] = opt
			return
		}
	}
	m.Additional = append(m.Additional, opt)
}

// PackLimit packs m so that it fits in max octets. Additional records are
// dropped first; if answer or authority records also have to go, the TC
// bit is set so the client retries over TCP. The OPT record is kept.
// m itself is not modified.
func (m *Message) PackLimit(max int) ([]byte, error) {
	wire, err := m.Pack()
	if err != nil || len(wire) <= max {
		return wire, err
	}
	t := *m
	var opt []RR
	for _, rr := range m.Additional {
		if rr.Type() == TypeOPT {
			opt = append(opt, rr)
		}
	}
	t.Additional = opt
	// Drop from the end of authority, then answers, until it fits.
	t.Answers = append([]RR(nil), m.Answers...)
	t.Authority = append([]RR(nil), m.Authority...)
	for {
		wire, err = t.Pack()
		if err != nil || len(wire) <= max {
			return wire, err
		}
		switch {
		case len(t.Authority) > 0:
			t.Authority = t.Authority[:len(t.Authority)-1]
		case len(t.Answers) > 0:
			t.Answers = t.Answers[:len(t.Answers)-1]
		default:
			t.Questions = nil
			t.Additional = nil
			t.Truncated = true
			return t.Pack()
		}
		t.Truncated = true
	}
}

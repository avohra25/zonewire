package dns

import (
	"bytes"
	"errors"
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func sampleMessage() *Message {
	return &Message{
		Header:    Header{ID: 0xBEEF, Response: true, Authoritative: true, RecursionDesired: true, RCode: RCodeSuccess},
		Questions: []Question{{"www.example.com.", TypeA, ClassINET}},
		Answers: []RR{
			{"www.example.com.", ClassINET, 300, CNAME{"web.example.com."}},
			{"web.example.com.", ClassINET, 300, A{netip.MustParseAddr("192.0.2.10")}},
			{"web.example.com.", ClassINET, 300, AAAA{netip.MustParseAddr("2001:db8::10")}},
		},
		Authority: []RR{
			{"example.com.", ClassINET, 3600, NS{"ns1.example.com."}},
			{"example.com.", ClassINET, 3600, SOA{"ns1.example.com.", "hostmaster.example.com.", 2026110101, 7200, 900, 1209600, 300}},
		},
		Additional: []RR{
			{"example.com.", ClassINET, 3600, MX{10, "mail.example.com."}},
			{"example.com.", ClassINET, 60, TXT{[]string{"v=spf1 -all", "quote \" and \\ slash"}}},
			{"_sip._tcp.example.com.", ClassINET, 60, SRV{10, 60, 5060, "sip.example.com."}},
			{"10.2.0.192.in-addr.arpa.", ClassINET, 60, PTR{"web.example.com."}},
			{"example.com.", ClassINET, 60, Unknown{Type(65280), []byte{1, 2, 3}}},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	m := sampleMessage()
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Names come back with the case they were written with; the first
	// occurrence of a suffix wins when compressed, so compare
	// case-insensitively via a repack.
	again, err := got.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, again) {
		t.Fatalf("repack differs:\n%x\n%x", wire, again)
	}
	if got.Header != m.Header {
		t.Fatalf("header %+v != %+v", got.Header, m.Header)
	}
	if len(got.Answers) != 3 || len(got.Authority) != 2 || len(got.Additional) != 5 {
		t.Fatalf("section sizes wrong: %v", got)
	}
	if !reflect.DeepEqual(got.Additional[1].Data, m.Additional[1].Data) {
		t.Fatalf("TXT mismatch: %v", got.Additional[1].Data)
	}
	if got.Authority[1].Data != m.Authority[1].Data {
		t.Fatalf("SOA mismatch: %v", got.Authority[1].Data)
	}
}

func TestCompressionShrinksMessage(t *testing.T) {
	m := sampleMessage()
	wire, _ := m.Pack()
	// "example.com" is written out once for the question and once inside
	// the SRV target, which must never be compressed; everything else
	// points back at the first copy.
	if n := bytes.Count(wire, []byte("\x07example\x03com\x00")); n != 2 {
		t.Fatalf("example.com written %d times", n)
	}
	// SRV targets must not be compressed (RFC 2782).
	if !bytes.Contains(wire, []byte("\x03sip\x07example\x03com\x00")) {
		t.Fatal("SRV target was compressed")
	}
}

func TestCasePreserved(t *testing.T) {
	m := &Message{Questions: []Question{{"WWW.Example.COM.", TypeA, ClassINET}},
		Answers: []RR{{"www.example.com.", ClassINET, 5, A{netip.MustParseAddr("192.0.2.1")}}}}
	wire, _ := m.Pack()
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Questions[0].Name != "WWW.Example.COM." || got.Answers[0].Name != "www.example.com." {
		t.Fatalf("case not preserved: %q %q", got.Questions[0].Name, got.Answers[0].Name)
	}
}

func TestKnownWireBytes(t *testing.T) {
	q, _ := NewQuery(0x1234, "example.com", TypeAAAA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 28, 0, 1,
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("got %x want %x", wire, want)
	}
}

func TestUnpackRejectsMalformed(t *testing.T) {
	q, _ := NewQuery(1, "a.b", TypeA)
	good, _ := q.Pack()
	cases := map[string][]byte{
		"short header":  good[:5],
		"short name":    good[:15],
		"trailing":      append(append([]byte{}, good...), 0),
		"forward ptr":   append(append([]byte{}, good[:12]...), 0xC0, 0x20, 0, 1, 0, 1),
		"self ptr":      append(append([]byte{}, good[:12]...), 0xC0, 0x0C, 0, 1, 0, 1),
		"reserved bits": append(append([]byte{}, good[:12]...), 0x80, 0, 0, 1, 0, 1),
		"missing count": func() []byte { b := append([]byte{}, good...); b[7] = 1; return b }(),
	}
	for name, b := range cases {
		if _, err := Unpack(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	_, err := Unpack(cases["self ptr"])
	if !errors.Is(err, ErrPointerLoop) {
		t.Errorf("self pointer: got %v", err)
	}
}

func TestPointerChainBackwards(t *testing.T) {
	// Each name below compresses against the one before it, producing a
	// chain of pointers that the decoder has to follow.
	m := &Message{Questions: []Question{{"a.example.com.", TypeA, ClassINET}},
		Answers: []RR{{"b.a.example.com.", ClassINET, 1, CNAME{"c.b.a.example.com."}}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 12+(15+4)+(4+10+4) {
		t.Fatalf("unexpected compressed length %d", len(wire))
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Answers[0].Data.(CNAME).Target != "c.b.a.example.com." {
		t.Fatalf("got %v", got.Answers[0])
	}
}

func TestNameValidation(t *testing.T) {
	if _, err := CanonicalName(strings.Repeat("a", 64) + ".com"); !errors.Is(err, ErrLabelTooLong) {
		t.Errorf("long label: %v", err)
	}
	if _, err := CanonicalName("a..com"); !errors.Is(err, ErrEmptyLabel) {
		t.Errorf("empty label: %v", err)
	}
	long := strings.Repeat(strings.Repeat("x", 63)+".", 4)
	if _, err := CanonicalName(long); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("long name: %v", err)
	}
	if n, _ := CanonicalName("Example.COM"); n != "Example.COM." {
		t.Errorf("got %q", n)
	}
	if !EqualNames("WWW.example.com", "www.EXAMPLE.com.") {
		t.Error("EqualNames should ignore case")
	}
	if !IsSubdomain("a.b.example.com.", "Example.com") || IsSubdomain("badexample.com.", "example.com.") {
		t.Error("IsSubdomain wrong")
	}
	if Parent("a.b.") != "b." || Parent("b.") != "." || Parent(".") != "." {
		t.Error("Parent wrong")
	}
}

func TestTypeParsing(t *testing.T) {
	for _, s := range []string{"A", "mx", "TYPE65280", "SOA"} {
		ty, err := ParseType(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if back, _ := ParseType(ty.String()); back != ty {
			t.Fatalf("%s did not round-trip", s)
		}
	}
	if _, err := ParseType("BOGUS"); err == nil {
		t.Fatal("expected error")
	}
	if c, _ := ParseClass("class3"); c != ClassCH {
		t.Fatal("CLASS3 should be CH")
	}
}

func TestAddressFamilyChecks(t *testing.T) {
	bad := []RR{
		{"x.", ClassINET, 1, A{netip.MustParseAddr("::1")}},
		{"x.", ClassINET, 1, AAAA{netip.MustParseAddr("1.2.3.4")}},
		{"x.", ClassINET, 1, TXT{nil}},
		{"x.", ClassINET, 1, TXT{[]string{strings.Repeat("z", 256)}}},
	}
	for _, rr := range bad {
		m := &Message{Answers: []RR{rr}}
		if _, err := m.Pack(); err == nil {
			t.Errorf("%v: expected pack error", rr)
		}
	}
}

func randName(r *rand.Rand, pool []string) string {
	n := 1 + r.Intn(4)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = pool[r.Intn(len(pool))]
	}
	return strings.Join(parts, ".") + "."
}

func randRR(r *rand.Rand, pool []string) RR {
	name := randName(r, pool)
	var d RData
	switch r.Intn(9) {
	case 0:
		d = A{netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})}
	case 1:
		var b [16]byte
		r.Read(b[:])
		b[0] = 0x20
		d = AAAA{netip.AddrFrom16(b)}
	case 2:
		d = NS{randName(r, pool)}
	case 3:
		d = CNAME{randName(r, pool)}
	case 4:
		d = MX{uint16(r.Intn(100)), randName(r, pool)}
	case 5:
		texts := make([]string, 1+r.Intn(3))
		for i := range texts {
			b := make([]byte, r.Intn(40))
			r.Read(b)
			texts[i] = string(b)
		}
		d = TXT{texts}
	case 6:
		d = SRV{uint16(r.Intn(10)), uint16(r.Intn(10)), uint16(r.Intn(65536)), randName(r, pool)}
	case 7:
		d = SOA{randName(r, pool), randName(r, pool), r.Uint32(), r.Uint32(), r.Uint32(), r.Uint32(), r.Uint32()}
	default:
		b := make([]byte, r.Intn(20))
		r.Read(b)
		d = Unknown{Type(1000 + r.Intn(100)), b}
	}
	return RR{name, ClassINET, r.Uint32(), d}
}

// TestRandomRoundTrip packs random messages, unpacks them and checks the
// decoded records are deeply equal to the originals.
func TestRandomRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	pool := []string{"a", "b", "example", "com", "net", "www", "mail", "x-1", "_tcp"}
	for iter := 0; iter < 2000; iter++ {
		m := &Message{Header: headerFromFlags(uint16(r.Intn(65536)), uint16(r.Intn(65536))&^0x0070)}
		m.Questions = []Question{{randName(r, pool), Type(1 + r.Intn(40)), ClassINET}}
		for _, sec := range []*[]RR{&m.Answers, &m.Authority, &m.Additional} {
			for i := r.Intn(5); i > 0; i-- {
				*sec = append(*sec, randRR(r, pool))
			}
		}
		wire, err := m.Pack()
		if err != nil {
			t.Fatalf("iter %d: pack: %v", iter, err)
		}
		got, err := Unpack(wire)
		if err != nil {
			t.Fatalf("iter %d: unpack: %v", iter, err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("iter %d: mismatch\nwant %v\ngot  %v", iter, m, got)
		}
	}
}

// TestUnpackNeverPanics feeds mutated messages to the decoder.
func TestUnpackNeverPanics(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	wire, _ := sampleMessage().Pack()
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), wire...)
		for j := 1 + r.Intn(4); j > 0; j-- {
			b[r.Intn(len(b))] = byte(r.Intn(256))
		}
		if r.Intn(4) == 0 {
			b = b[:r.Intn(len(b))]
		}
		Unpack(b) // must not panic
	}
}

func FuzzUnpack(f *testing.F) {
	wire, _ := sampleMessage().Pack()
	f.Add(wire)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Unpack(b)
		if err != nil {
			return
		}
		if _, err := m.Pack(); err != nil {
			// Anything the decoder accepts must be encodable again.
			t.Fatalf("decoded message failed to repack: %v", err)
		}
	})
}

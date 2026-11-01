package dns

import (
	"net/netip"
	"testing"
)

func bigAnswer(n int) *Message {
	q, _ := NewQuery(9, "big.example.com.", TypeA)
	m := q.Reply()
	for i := 0; i < n; i++ {
		m.Answers = append(m.Answers, RR{"big.example.com.", ClassINET, 60, A{netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})}})
	}
	m.Additional = []RR{{"glue.example.com.", ClassINET, 60, A{netip.MustParseAddr("192.0.2.1")}}}
	return m
}

func TestPackLimitTruncates(t *testing.T) {
	m := bigAnswer(100)
	m.SetEDNS(1232)
	wire, err := m.PackLimit(MinUDPSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > MinUDPSize {
		t.Fatalf("packed %d octets", len(wire))
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(got.Answers) == 0 || len(got.Answers) >= 100 {
		t.Fatalf("tc=%v answers=%d", got.Truncated, len(got.Answers))
	}
	if size, ok := got.EDNS(); !ok || size != 1232 {
		t.Fatalf("OPT record lost: %d %v", size, ok)
	}
	if len(m.Answers) != 100 {
		t.Fatal("PackLimit modified its receiver")
	}
}

func TestPackLimitDropsAdditionalWithoutTC(t *testing.T) {
	m := bigAnswer(29) // 12+21+29*16 = 497 octets of answers, glue does not fit
	wire, _ := m.PackLimit(MinUDPSize)
	got, _ := Unpack(wire)
	if got.Truncated || len(got.Answers) != 29 || len(got.Additional) != 0 {
		t.Fatalf("tc=%v answers=%d additional=%d", got.Truncated, len(got.Answers), len(got.Additional))
	}
}

func TestEDNSFloor(t *testing.T) {
	m := &Message{}
	if _, ok := m.EDNS(); ok {
		t.Fatal("no OPT expected")
	}
	m.SetEDNS(100)
	m.SetEDNS(200)
	if size, _ := m.EDNS(); size != MinUDPSize || len(m.Additional) != 1 {
		t.Fatalf("size %d, %d records", size, len(m.Additional))
	}
}

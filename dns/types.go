package dns

import (
	"fmt"
	"strconv"
	"strings"
)

// Type is a resource record type (RFC 1035 3.2.2 and later RFCs).
type Type uint16

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41
	TypeAXFR  Type = 252
	TypeANY   Type = 255
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", TypeOPT: "OPT",
	TypeAXFR: "AXFR", TypeANY: "ANY",
}

func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType accepts mnemonics ("MX") and the RFC 3597 generic form ("TYPE99").
func ParseType(s string) (Type, error) {
	u := strings.ToUpper(s)
	for t, n := range typeNames {
		if n == u {
			return t, nil
		}
	}
	if strings.HasPrefix(u, "TYPE") {
		if n, err := strconv.ParseUint(u[4:], 10, 16); err == nil {
			return Type(n), nil
		}
	}
	return 0, fmt.Errorf("dns: unknown type %q", s)
}

// Class is a resource record class.
type Class uint16

const (
	ClassINET Class = 1
	ClassCH   Class = 3
	ClassANY  Class = 255
)

func (c Class) String() string {
	switch c {
	case ClassINET:
		return "IN"
	case ClassCH:
		return "CH"
	case ClassANY:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// ParseClass accepts IN, CH, ANY and the generic CLASSnn form.
func ParseClass(s string) (Class, error) {
	switch u := strings.ToUpper(s); {
	case u == "IN":
		return ClassINET, nil
	case u == "CH":
		return ClassCH, nil
	case u == "ANY":
		return ClassANY, nil
	case strings.HasPrefix(u, "CLASS"):
		if n, err := strconv.ParseUint(u[5:], 10, 16); err == nil {
			return Class(n), nil
		}
	}
	return 0, fmt.Errorf("dns: unknown class %q", s)
}

// RCode is a response code.
type RCode uint8

const (
	RCodeSuccess        RCode = 0
	RCodeFormatError    RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNameError      RCode = 3 // NXDOMAIN
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
	RCodeNotAuth        RCode = 9
)

func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "NOERROR"
	case RCodeFormatError:
		return "FORMERR"
	case RCodeServerFailure:
		return "SERVFAIL"
	case RCodeNameError:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	case RCodeNotAuth:
		return "NOTAUTH"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// Opcode values used here.
const (
	OpcodeQuery  uint8 = 0
	OpcodeStatus uint8 = 2
)

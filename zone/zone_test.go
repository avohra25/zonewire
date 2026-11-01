package zone

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/avohra25/zonewire/dns"
)

const exampleZone = `
$ORIGIN example.com.
$TTL 1h
@   IN  SOA ns1 hostmaster (
            2026110101 ; serial
            2h         ; refresh
            15m        ; retry
            2w         ; expire
            5m )       ; negative TTL
    IN  NS  ns1
    IN  NS  ns2.example.net.
    IN  MX  10 mail
    IN  TXT "v=spf1 mx -all" "second string"
ns1         A     192.0.2.1
mail  300   A     192.0.2.25
            AAAA  2001:db8::25
www         CNAME web
web         A     192.0.2.80
web         A     192.0.2.81
alias       CNAME www
loop1       CNAME loop2
loop2       CNAME loop1
outside     CNAME www.example.org.
_sip._tcp   SRV   10 60 5060 sip
sip         A     192.0.2.50
*.apps      A     192.0.2.99
*.apps      TXT   "wild"
fixed.apps  A     192.0.2.98
a.b.c       A     192.0.2.7
sub         NS    ns.sub
ns.sub      A     192.0.2.53
unknown     TYPE65280 \# 3 010203
genericA    A     \# 4 C0000207
esc         TXT   "tab\009here" semi\;colon
`

func mustZone(t *testing.T) *Zone {
	t.Helper()
	z, err := Load(strings.NewReader(exampleZone), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func names(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.Name+" "+rr.Type().String()+" "+rr.Data.String())
	}
	return out
}

func TestParseDetails(t *testing.T) {
	rrs, err := ParseString(exampleZone, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	soa := rrs[0]
	want := dns.SOA{MName: "ns1.example.com.", RName: "hostmaster.example.com.", Serial: 2026110101, Refresh: 7200, Retry: 900, Expire: 1209600, MinTTL: 300}
	if soa.Data != want || soa.TTL != 3600 || soa.Name != "example.com." {
		t.Fatalf("SOA parsed as %v", soa)
	}
	byName := map[string]dns.RR{} // first record of each owner/type
	for _, rr := range rrs {
		if _, ok := byName[rr.Name+"/"+rr.Type().String()]; !ok {
			byName[rr.Name+"/"+rr.Type().String()] = rr
		}
	}
	if rr := byName["mail.example.com./AAAA"]; rr.TTL != 3600 || rr.Data.(dns.AAAA).Addr != netip.MustParseAddr("2001:db8::25") {
		t.Errorf("indented AAAA should inherit owner and $TTL: %v", rr)
	}
	if rr := byName["mail.example.com./A"]; rr.TTL != 300 {
		t.Errorf("explicit TTL ignored: %v", rr)
	}
	if rr := byName["example.com./NS"]; rr.Data.(dns.NS).Host != "ns1.example.com." {
		t.Errorf("relative NS host: %v", rr)
	}
	if rr := byName["genericA.example.com./A"]; rr.Data != (dns.A{Addr: netip.MustParseAddr("192.0.2.7")}) {
		t.Errorf("generic A syntax should decode to A: %#v", rr.Data)
	}
	if rr := byName["unknown.example.com./TYPE65280"]; !reflect.DeepEqual(rr.Data, dns.Unknown{T: 65280, Data: []byte{1, 2, 3}}) {
		t.Errorf("unknown type: %#v", rr.Data)
	}
	if rr := byName["esc.example.com./TXT"]; !reflect.DeepEqual(rr.Data.(dns.TXT).Texts, []string{"tab\there", "semi;colon"}) {
		t.Errorf("escapes: %q", rr.Data.(dns.TXT).Texts)
	}
}

func TestParseTTLUnits(t *testing.T) {
	for in, want := range map[string]uint32{"0": 0, "86400": 86400, "1h30m": 5400, "1W2D": 777600, "45s": 45} {
		got, err := ParseTTL(in)
		if err != nil || got != want {
			t.Errorf("%s: got %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "h", "1x", "1h5", "99999999999"} {
		if _, err := ParseTTL(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestParseErrorsHaveLineNumbers(t *testing.T) {
	cases := map[string]int{
		"$TTL 60\n@ SOA a b 1 2 3 4 5\nx A 300.1.1.1\n":      3,
		"$TTL 60\n\n\nx MX ten mail\n":                       4,
		"$TTL 60\nx TXT \"unterminated\n":                    2,
		"$TTL 60\n@ SOA a b ( 1 2 3\n 4 5\n":                 2,
		"x A 192.0.2.1\n":                                    1,
		"$TTL 60\n$INCLUDE other.zone\n":                     2,
		"$TTL 60\nx BOGUS data\n":                            2,
		"$TTL 60\nx A \\# 4 C000\n":                          2,
		"$TTL 60\n" + strings.Repeat("a", 64) + " A 1.2.3.4": 2,
	}
	for src, line := range cases {
		_, err := ParseString(src, "example.com.")
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Line != line {
			t.Errorf("%q: got %v, want error on line %d", src, err, line)
		}
	}
}

func TestZoneValidation(t *testing.T) {
	bad := map[string]string{
		"no SOA":       "$TTL 60\n@ NS ns\n",
		"no NS":        "$TTL 60\n@ SOA a b 1 2 3 4 5\n",
		"CNAME+other":  "$TTL 60\n@ SOA a b 1 2 3 4 5\n@ NS ns\nx CNAME y\nx A 192.0.2.1\n",
		"out of zone":  "$TTL 60\n@ SOA a b 1 2 3 4 5\n@ NS ns\nother.org. A 192.0.2.1\n",
		"two SOAs":     "$TTL 60\n@ SOA a b 1 2 3 4 5\n@ SOA c d 1 2 3 4 5\n@ NS ns\n",
		"SOA not apex": "$TTL 60\n@ SOA a b 1 2 3 4 5\n@ NS ns\nx SOA a b 1 2 3 4 5\n",
	}
	for name, src := range bad {
		if _, err := Load(strings.NewReader(src), "example.com."); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLookup(t *testing.T) {
	z := mustZone(t)
	tests := []struct {
		name, qname string
		qtype       dns.Type
		rcode       dns.RCode
		aa          bool
		answer      []string
		authority   []string
		additional  []string
	}{
		{"exact", "web.example.com.", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"web.example.com. A 192.0.2.80", "web.example.com. A 192.0.2.81"}, nil, nil},
		{"case-insensitive", "WEB.Example.COM", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"web.example.com. A 192.0.2.80", "web.example.com. A 192.0.2.81"}, nil, nil},
		{"cname chain", "alias.example.com.", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"alias.example.com. CNAME www.example.com.", "www.example.com. CNAME web.example.com.",
				"web.example.com. A 192.0.2.80", "web.example.com. A 192.0.2.81"}, nil, nil},
		{"cname itself", "www.example.com.", dns.TypeCNAME, dns.RCodeSuccess, true,
			[]string{"www.example.com. CNAME web.example.com."}, nil, nil},
		{"cname loop stops", "loop1.example.com.", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"loop1.example.com. CNAME loop2.example.com.", "loop2.example.com. CNAME loop1.example.com."}, nil, nil},
		{"cname out of zone", "outside.example.com.", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"outside.example.com. CNAME www.example.org."}, nil, nil},
		{"nodata", "web.example.com.", dns.TypeMX, dns.RCodeSuccess, true, nil,
			[]string{"example.com. SOA ns1.example.com. hostmaster.example.com. 2026110101 7200 900 1209600 300"}, nil},
		{"nxdomain", "nope.example.com.", dns.TypeA, dns.RCodeNameError, true, nil,
			[]string{"example.com. SOA ns1.example.com. hostmaster.example.com. 2026110101 7200 900 1209600 300"}, nil},
		{"empty non-terminal", "b.c.example.com.", dns.TypeA, dns.RCodeSuccess, true, nil,
			[]string{"example.com. SOA ns1.example.com. hostmaster.example.com. 2026110101 7200 900 1209600 300"}, nil},
		{"wildcard", "foo.apps.example.com.", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"foo.apps.example.com. A 192.0.2.99"}, nil, nil},
		{"wildcard deeper", "x.y.apps.example.com.", dns.TypeTXT, dns.RCodeSuccess, true,
			[]string{`x.y.apps.example.com. TXT "wild"`}, nil, nil},
		{"wildcard does not cover existing", "fixed.apps.example.com.", dns.TypeA, dns.RCodeSuccess, true,
			[]string{"fixed.apps.example.com. A 192.0.2.98"}, nil, nil},
		{"wildcard nodata", "foo.apps.example.com.", dns.TypeMX, dns.RCodeSuccess, true, nil,
			[]string{"example.com. SOA ns1.example.com. hostmaster.example.com. 2026110101 7200 900 1209600 300"}, nil},
		{"wildcard blocked by closer encloser", "z.fixed.apps.example.com.", dns.TypeA, dns.RCodeNameError, true, nil,
			[]string{"example.com. SOA ns1.example.com. hostmaster.example.com. 2026110101 7200 900 1209600 300"}, nil},
		{"referral", "host.sub.example.com.", dns.TypeA, dns.RCodeSuccess, false, nil,
			[]string{"sub.example.com. NS ns.sub.example.com."}, []string{"ns.sub.example.com. A 192.0.2.53"}},
		{"referral at cut", "sub.example.com.", dns.TypeNS, dns.RCodeSuccess, false, nil,
			[]string{"sub.example.com. NS ns.sub.example.com."}, []string{"ns.sub.example.com. A 192.0.2.53"}},
		{"mx additional", "example.com.", dns.TypeMX, dns.RCodeSuccess, true,
			[]string{"example.com. MX 10 mail.example.com."}, nil,
			[]string{"mail.example.com. A 192.0.2.25", "mail.example.com. AAAA 2001:db8::25"}},
		{"srv additional", "_sip._tcp.example.com.", dns.TypeSRV, dns.RCodeSuccess, true,
			[]string{"_sip._tcp.example.com. SRV 10 60 5060 sip.example.com."}, nil,
			[]string{"sip.example.com. A 192.0.2.50"}},
		{"apex ns additional skips out-of-zone", "example.com.", dns.TypeNS, dns.RCodeSuccess, true,
			[]string{"example.com. NS ns1.example.com.", "example.com. NS ns2.example.net."}, nil,
			[]string{"ns1.example.com. A 192.0.2.1"}},
		{"refused outside zone", "example.org.", dns.TypeA, dns.RCodeRefused, false, nil, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := z.Lookup(tc.qname, tc.qtype)
			if r.RCode != tc.rcode || r.Authoritative != tc.aa {
				t.Fatalf("rcode %v aa %v, want %v %v", r.RCode, r.Authoritative, tc.rcode, tc.aa)
			}
			for _, sec := range []struct {
				label     string
				got, want []string
			}{{"answer", names(r.Answer), tc.answer}, {"authority", names(r.Authority), tc.authority}, {"additional", names(r.Additional), tc.additional}} {
				if !reflect.DeepEqual(sec.got, sec.want) {
					t.Errorf("%s:\n got  %q\n want %q", sec.label, sec.got, sec.want)
				}
			}
		})
	}
}

func TestNegativeTTLCapped(t *testing.T) {
	r := mustZone(t).Lookup("missing.example.com.", dns.TypeA)
	if r.Authority[0].TTL != 300 {
		t.Fatalf("negative SOA TTL %d, want SOA minimum 300", r.Authority[0].TTL)
	}
}

func TestANYQuery(t *testing.T) {
	r := mustZone(t).Lookup("mail.example.com.", dns.TypeANY)
	if len(r.Answer) != 2 {
		t.Fatalf("ANY returned %v", names(r.Answer))
	}
}

func TestRecordsRoundTripThroughText(t *testing.T) {
	z := mustZone(t)
	var sb strings.Builder
	for _, rr := range z.Records() {
		sb.WriteString(rr.String())
		sb.WriteByte('\n')
	}
	z2, err := Load(strings.NewReader(sb.String()), z.Origin)
	if err != nil {
		t.Fatalf("re-parsing printed zone: %v\n%s", err, sb.String())
	}
	if !reflect.DeepEqual(names(z.Records()), names(z2.Records())) {
		t.Fatal("printed zone did not round-trip")
	}
}

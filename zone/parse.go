// Package zone reads RFC 1035 master files and answers queries from the
// resulting zone the way an authoritative server does.
package zone

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/avohra25/zonewire/dns"
)

// ParseError reports a problem with a line number.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

type token struct {
	text   string
	quoted bool
}

// entry is one logical record: tokens joined across parentheses.
type entry struct {
	line     int
	indented bool // started with whitespace: owner is the previous owner
	toks     []token
}

// lexer splits master-file text into logical entries.
type lexer struct {
	sc   *bufio.Scanner
	line int
}

func (lx *lexer) next() (*entry, error) {
	var e *entry
	depth := 0
	for lx.sc.Scan() {
		lx.line++
		raw := lx.sc.Text()
		if e == nil {
			e = &entry{line: lx.line, indented: len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')}
		}
		toks, d, err := splitLine(raw, depth)
		if err != nil {
			return nil, &ParseError{lx.line, err.Error()}
		}
		depth = d
		e.toks = append(e.toks, toks...)
		if depth == 0 {
			if len(e.toks) == 0 {
				e = nil // blank or comment-only line
				continue
			}
			return e, nil
		}
	}
	if err := lx.sc.Err(); err != nil {
		return nil, err
	}
	if depth > 0 {
		return nil, &ParseError{e.line, "unclosed parenthesis"}
	}
	return nil, io.EOF
}

// splitLine tokenises one physical line, tracking parenthesis depth.
func splitLine(s string, depth int) ([]token, int, error) {
	var toks []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == ';':
			return toks, depth, nil
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth == 0 {
				return nil, 0, errors.New("unbalanced ')'")
			}
			depth--
			i++
		case c == '"':
			var sb strings.Builder
			i++
			for {
				if i >= len(s) {
					return nil, 0, errors.New("unterminated quoted string")
				}
				if s[i] == '"' {
					i++
					break
				}
				if s[i] == '\\' {
					b, n, err := unescape(s[i:])
					if err != nil {
						return nil, 0, err
					}
					sb.WriteByte(b)
					i += n
					continue
				}
				sb.WriteByte(s[i])
				i++
			}
			toks = append(toks, token{sb.String(), true})
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\r;()\"", rune(s[j])) {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				j++
			}
			toks = append(toks, token{text: s[i:j]})
			i = j
		}
	}
	return toks, depth, nil
}

// unescape decodes \X or \DDD at the start of s.
func unescape(s string) (byte, int, error) {
	if len(s) < 2 {
		return 0, 0, errors.New("dangling backslash")
	}
	if s[1] >= '0' && s[1] <= '9' {
		if len(s) < 4 {
			return 0, 0, errors.New("short \\DDD escape")
		}
		n, err := strconv.Atoi(s[1:4])
		if err != nil || n > 255 {
			return 0, 0, fmt.Errorf("bad escape %q", s[:4])
		}
		return byte(n), 4, nil
	}
	return s[1], 2, nil
}

// ParseTTL accepts plain seconds or BIND-style units such as 1h30m or 2w.
func ParseTTL(s string) (uint32, error) {
	if s == "" {
		return 0, errors.New("empty TTL")
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	var total, cur uint64
	digits := false
	for _, c := range strings.ToLower(s) {
		if c >= '0' && c <= '9' {
			cur = cur*10 + uint64(c-'0')
			digits = true
			continue
		}
		mult := map[rune]uint64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[c]
		if mult == 0 || !digits {
			return 0, fmt.Errorf("bad TTL %q", s)
		}
		total += cur * mult
		cur, digits = 0, false
	}
	if digits {
		return 0, fmt.Errorf("bad TTL %q: trailing number without unit", s)
	}
	if total > 1<<31-1 {
		return 0, fmt.Errorf("TTL %q too large", s)
	}
	return uint32(total), nil
}

func isTTL(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	_, err := ParseTTL(s)
	return err == nil
}

// Parse reads a master file. origin is the initial $ORIGIN; records without
// a TTL get the most recent $TTL (or the previous record's TTL).
func Parse(r io.Reader, origin string) ([]dns.RR, error) {
	origin, err := dns.CanonicalName(origin)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	lx := &lexer{sc: sc}
	p := &parser{origin: origin, class: dns.ClassINET}
	var out []dns.RR
	for {
		e, err := lx.next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		rr, err := p.entry(e)
		if err != nil {
			var pe *ParseError
			if errors.As(err, &pe) {
				return nil, err
			}
			return nil, &ParseError{e.line, err.Error()}
		}
		if rr != nil {
			out = append(out, *rr)
		}
	}
}

// ParseString is Parse for an in-memory zone.
func ParseString(s, origin string) ([]dns.RR, error) {
	return Parse(strings.NewReader(s), origin)
}

type parser struct {
	origin     string
	owner      string
	defaultTTL uint32
	haveTTL    bool
	lastTTL    uint32
	haveLast   bool
	class      dns.Class
}

func (p *parser) name(s string) (string, error) {
	if s == "@" {
		return p.origin, nil
	}
	n, err := decodeName(s)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(s, ".") || strings.HasSuffix(s, "\\.") {
		if p.origin == "." {
			n = n + "."
		} else {
			n = n + "." + p.origin
		}
	}
	return dns.CanonicalName(n)
}

// decodeName resolves escapes in a presentation-format name. Escaped dots
// are not supported because labels are stored as dot-separated text.
func decodeName(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return strings.TrimSuffix(s, "."), nil
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' {
			b, n, err := unescape(s[i:])
			if err != nil {
				return "", err
			}
			if b == '.' {
				return "", errors.New("escaped dots in names are not supported")
			}
			sb.WriteByte(b)
			i += n
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return strings.TrimSuffix(sb.String(), "."), nil
}

func (p *parser) entry(e *entry) (*dns.RR, error) {
	toks := e.toks
	if !toks[0].quoted && strings.HasPrefix(toks[0].text, "$") && !e.indented {
		return nil, p.directive(toks)
	}
	if !e.indented {
		owner, err := p.name(toks[0].text)
		if err != nil {
			return nil, err
		}
		p.owner = owner
		toks = toks[1:]
	} else if p.owner == "" {
		return nil, errors.New("record has no owner and there is no previous owner")
	}
	ttl, haveTTL := uint32(0), false
	class := p.class
	// TTL and class may appear in either order before the type.
	for i := 0; i < 2 && len(toks) > 0 && !toks[0].quoted; i++ {
		if !haveTTL && isTTL(toks[0].text) {
			ttl, _ = ParseTTL(toks[0].text)
			haveTTL = true
			toks = toks[1:]
			continue
		}
		if c, err := dns.ParseClass(toks[0].text); err == nil && !strings.HasPrefix(strings.ToUpper(toks[0].text), "TYPE") {
			class = c
			toks = toks[1:]
			continue
		}
		break
	}
	if len(toks) == 0 {
		return nil, errors.New("missing record type")
	}
	t, err := dns.ParseType(toks[0].text)
	if err != nil {
		return nil, err
	}
	if !haveTTL {
		switch {
		case p.haveTTL:
			ttl = p.defaultTTL
		case p.haveLast:
			ttl = p.lastTTL
		case t != dns.TypeSOA:
			return nil, errors.New("no TTL given and no $TTL in effect")
		}
	}
	data, err := p.rdata(t, toks[1:])
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", p.owner, t, err)
	}
	if soa, ok := data.(dns.SOA); ok && !haveTTL && !p.haveTTL && !p.haveLast {
		ttl = soa.MinTTL // RFC 1035 behaviour before $TTL existed
	}
	p.class = class
	p.lastTTL, p.haveLast = ttl, true
	return &dns.RR{Name: p.owner, Class: class, TTL: ttl, Data: data}, nil
}

func (p *parser) directive(toks []token) error {
	switch strings.ToUpper(toks[0].text) {
	case "$ORIGIN":
		if len(toks) != 2 {
			return errors.New("$ORIGIN takes one name")
		}
		if !strings.HasSuffix(toks[1].text, ".") {
			return errors.New("$ORIGIN must be fully qualified")
		}
		o, err := p.name(toks[1].text)
		if err != nil {
			return err
		}
		p.origin = o
	case "$TTL":
		if len(toks) != 2 {
			return errors.New("$TTL takes one value")
		}
		ttl, err := ParseTTL(toks[1].text)
		if err != nil {
			return err
		}
		p.defaultTTL, p.haveTTL = ttl, true
	case "$INCLUDE":
		return errors.New("$INCLUDE is not supported")
	default:
		return fmt.Errorf("unknown directive %s", toks[0].text)
	}
	return nil
}

func (p *parser) rdata(t dns.Type, toks []token) (dns.RData, error) {
	if len(toks) > 0 && toks[0].text == `\#` && !toks[0].quoted {
		return genericRData(t, toks[1:])
	}
	want := func(n int) error {
		if len(toks) != n {
			return fmt.Errorf("expected %d fields, got %d", n, len(toks))
		}
		return nil
	}
	u16 := func(s string) (uint16, error) {
		n, err := strconv.ParseUint(s, 10, 16)
		return uint16(n), err
	}
	switch t {
	case dns.TypeA, dns.TypeAAAA:
		if err := want(1); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(toks[0].text)
		if err != nil {
			return nil, err
		}
		if t == dns.TypeA {
			if !a.Is4() {
				return nil, fmt.Errorf("%s is not an IPv4 address", a)
			}
			return dns.A{Addr: a}, nil
		}
		if !a.Is6() || a.Is4In6() {
			return nil, fmt.Errorf("%s is not an IPv6 address", a)
		}
		return dns.AAAA{Addr: a}, nil
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR:
		if err := want(1); err != nil {
			return nil, err
		}
		n, err := p.name(toks[0].text)
		if err != nil {
			return nil, err
		}
		switch t {
		case dns.TypeNS:
			return dns.NS{Host: n}, nil
		case dns.TypeCNAME:
			return dns.CNAME{Target: n}, nil
		}
		return dns.PTR{Ptr: n}, nil
	case dns.TypeMX:
		if err := want(2); err != nil {
			return nil, err
		}
		pref, err := u16(toks[0].text)
		if err != nil {
			return nil, fmt.Errorf("bad preference %q", toks[0].text)
		}
		n, err := p.name(toks[1].text)
		if err != nil {
			return nil, err
		}
		return dns.MX{Pref: pref, Exchange: n}, nil
	case dns.TypeSRV:
		if err := want(4); err != nil {
			return nil, err
		}
		var v [3]uint16
		for i := range v {
			n, err := u16(toks[i].text)
			if err != nil {
				return nil, fmt.Errorf("bad SRV field %q", toks[i].text)
			}
			v[i] = n
		}
		n, err := p.name(toks[3].text)
		if err != nil {
			return nil, err
		}
		return dns.SRV{Priority: v[0], Weight: v[1], Port: v[2], Target: n}, nil
	case dns.TypeSOA:
		if err := want(7); err != nil {
			return nil, err
		}
		m, err := p.name(toks[0].text)
		if err != nil {
			return nil, err
		}
		r, err := p.name(toks[1].text)
		if err != nil {
			return nil, err
		}
		var v [5]uint32
		for i := range v {
			n, err := ParseTTL(toks[2+i].text)
			if err != nil {
				return nil, fmt.Errorf("bad SOA field %q", toks[2+i].text)
			}
			v[i] = n
		}
		return dns.SOA{MName: m, RName: r, Serial: v[0], Refresh: v[1], Retry: v[2], Expire: v[3], MinTTL: v[4]}, nil
	case dns.TypeTXT:
		if len(toks) == 0 {
			return nil, errors.New("TXT needs at least one string")
		}
		texts := make([]string, len(toks))
		for i, tk := range toks {
			s := tk.text
			if !tk.quoted {
				var err error
				if s, err = unescapeAll(s); err != nil {
					return nil, err
				}
			}
			if len(s) > 255 {
				return nil, errors.New("TXT string longer than 255 octets")
			}
			texts[i] = s
		}
		return dns.TXT{Texts: texts}, nil
	}
	return nil, fmt.Errorf("type %s needs RFC 3597 \\# syntax", t)
}

func unescapeAll(s string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' {
			b, n, err := unescape(s[i:])
			if err != nil {
				return "", err
			}
			sb.WriteByte(b)
			i += n
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String(), nil
}

// genericRData parses "\# <len> <hex...>" (RFC 3597 section 5).
func genericRData(t dns.Type, toks []token) (dns.RData, error) {
	if len(toks) == 0 {
		return nil, errors.New(`\# needs a length`)
	}
	n, err := strconv.Atoi(toks[0].text)
	if err != nil || n < 0 || n > 65535 {
		return nil, fmt.Errorf("bad \\# length %q", toks[0].text)
	}
	var hx strings.Builder
	for _, tk := range toks[1:] {
		hx.WriteString(tk.text)
	}
	data, err := hex.DecodeString(hx.String())
	if err != nil {
		return nil, fmt.Errorf("bad \\# hex data: %v", err)
	}
	if len(data) != n {
		return nil, fmt.Errorf("\\# length %d but %d octets of data", n, len(data))
	}
	return dns.DecodeRData(t, data)
}

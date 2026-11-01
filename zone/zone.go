package zone

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/avohra25/zonewire/dns"
)

// maxCNAMEChain bounds alias chasing inside one zone.
const maxCNAMEChain = 8

// node holds every RRset owned by one name.
type node map[dns.Type][]dns.RR

// Zone is an in-memory authoritative zone.
type Zone struct {
	Origin string
	SOA    dns.RR
	nodes  map[string]node // lower-cased owner -> rrsets
	exists map[string]bool // owners plus empty non-terminals
	cuts   map[string]bool // delegation points below the apex
}

func key(name string) string { return strings.ToLower(name) }

// New validates records and builds a zone rooted at origin.
func New(origin string, rrs []dns.RR) (*Zone, error) {
	origin, err := dns.CanonicalName(origin)
	if err != nil {
		return nil, err
	}
	z := &Zone{Origin: origin, nodes: map[string]node{}, exists: map[string]bool{}, cuts: map[string]bool{}}
	var errs []error
	for _, rr := range rrs {
		if rr.Class != dns.ClassINET {
			errs = append(errs, fmt.Errorf("%s: only class IN is supported", rr.Name))
			continue
		}
		if !dns.IsSubdomain(rr.Name, origin) {
			errs = append(errs, fmt.Errorf("%s is outside zone %s", rr.Name, origin))
			continue
		}
		k := key(rr.Name)
		n := z.nodes[k]
		if n == nil {
			n = node{}
			z.nodes[k] = n
		}
		dup := false
		for _, have := range n[rr.Type()] {
			if have.Data.String() == rr.Data.String() {
				dup = true
			}
		}
		if !dup {
			n[rr.Type()] = append(n[rr.Type()], rr)
		}
		for name := k; ; name = dns.Parent(name) {
			z.exists[name] = true
			if name == key(origin) {
				break
			}
		}
	}
	apex := z.nodes[key(origin)]
	switch {
	case apex == nil || len(apex[dns.TypeSOA]) == 0:
		errs = append(errs, fmt.Errorf("zone %s has no SOA record at its apex", origin))
	case len(apex[dns.TypeSOA]) > 1:
		errs = append(errs, fmt.Errorf("zone %s has more than one SOA record", origin))
	default:
		z.SOA = apex[dns.TypeSOA][0]
	}
	if apex != nil && len(apex[dns.TypeNS]) == 0 {
		errs = append(errs, fmt.Errorf("zone %s has no NS records at its apex", origin))
	}
	for k, n := range z.nodes {
		if _, ok := n[dns.TypeSOA]; ok && k != key(origin) {
			errs = append(errs, fmt.Errorf("SOA record at %s is not at the zone apex", k))
		}
		if c, ok := n[dns.TypeCNAME]; ok {
			if len(c) > 1 {
				errs = append(errs, fmt.Errorf("%s has more than one CNAME", k))
			}
			if len(n) > 1 {
				errs = append(errs, fmt.Errorf("%s has a CNAME and other data", k))
			}
		}
		if _, ok := n[dns.TypeNS]; ok && k != key(origin) {
			z.cuts[k] = true
		}
	}
	if len(errs) > 0 {
		sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
		return nil, errors.Join(errs...)
	}
	return z, nil
}

// Load parses a master file and builds the zone in one step.
func Load(r io.Reader, origin string) (*Zone, error) {
	rrs, err := Parse(r, origin)
	if err != nil {
		return nil, err
	}
	return New(origin, rrs)
}

// Records returns every record in the zone in a stable order, SOA first.
func (z *Zone) Records() []dns.RR {
	out := []dns.RR{z.SOA}
	keys := make([]string, 0, len(z.nodes))
	for k := range z.nodes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return canonicalLess(keys[i], keys[j]) })
	for _, k := range keys {
		types := make([]int, 0)
		for t := range z.nodes[k] {
			types = append(types, int(t))
		}
		sort.Ints(types)
		for _, t := range types {
			if dns.Type(t) == dns.TypeSOA {
				continue
			}
			out = append(out, z.nodes[k][dns.Type(t)]...)
		}
	}
	return out
}

// canonicalLess orders names by their reversed labels (RFC 4034 6.1).
func canonicalLess(a, b string) bool {
	la, lb := dns.Labels(a), dns.Labels(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if la[i] != lb[j] {
			return la[i] < lb[j]
		}
	}
	return len(la) < len(lb)
}

// Result is the outcome of an authoritative lookup.
type Result struct {
	RCode         dns.RCode
	Authoritative bool
	Answer        []dns.RR
	Authority     []dns.RR
	Additional    []dns.RR
}

// Lookup answers qname/qtype following RFC 1034 section 4.3.2: delegations
// produce referrals with glue, CNAMEs are chased within the zone, missing
// names fall back to wildcards, and negative answers carry the SOA.
func (z *Zone) Lookup(qname string, qtype dns.Type) Result {
	qname, err := dns.CanonicalName(qname)
	if err != nil || !dns.IsSubdomain(qname, z.Origin) {
		return Result{RCode: dns.RCodeRefused}
	}
	res := Result{Authoritative: true}
	seen := map[string]bool{}
	for hop := 0; ; hop++ {
		if cut := z.findCut(qname); cut != "" {
			// A referral is only valid if no answer was collected yet in
			// this zone; after a CNAME we stop at the cut and let the
			// resolver follow it.
			if len(res.Answer) == 0 {
				res.Authoritative = false
				res.Authority = z.nodes[cut][dns.TypeNS]
				res.Additional = z.glue(res.Authority)
			}
			return res
		}
		n, wild := z.find(qname)
		if n == nil {
			// RFC 6604: the rcode describes the last name in the chain.
			if !z.exists[key(qname)] {
				res.RCode = dns.RCodeNameError
			}
			res.Authority = []dns.RR{z.negativeSOA()}
			return res
		}
		rename := func(rrs []dns.RR) []dns.RR {
			if !wild {
				return rrs
			}
			out := make([]dns.RR, len(rrs))
			for i, rr := range rrs {
				rr.Name = qname
				out[i] = rr
			}
			return out
		}
		if c, ok := n[dns.TypeCNAME]; ok && qtype != dns.TypeCNAME && qtype != dns.TypeANY {
			res.Answer = append(res.Answer, rename(c)...)
			target := c[0].Data.(dns.CNAME).Target
			seen[key(qname)] = true
			if !dns.IsSubdomain(target, z.Origin) || seen[key(target)] || hop+1 >= maxCNAMEChain {
				return res
			}
			qname = target
			continue
		}
		var ans []dns.RR
		if qtype == dns.TypeANY {
			for _, t := range sortedTypes(n) {
				ans = append(ans, n[t]...)
			}
		} else {
			ans = n[qtype]
		}
		if len(ans) == 0 {
			res.Authority = []dns.RR{z.negativeSOA()}
			return res
		}
		res.Answer = append(res.Answer, rename(ans)...)
		res.Additional = z.additional(res.Answer)
		return res
	}
}

func sortedTypes(n node) []dns.Type {
	ts := make([]dns.Type, 0, len(n))
	for t := range n {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts
}

// findCut returns the delegation point at or above qname, if any.
func (z *Zone) findCut(qname string) string {
	apex := key(z.Origin)
	for name := key(qname); name != apex && name != "."; name = dns.Parent(name) {
		if z.cuts[name] {
			return name
		}
	}
	return ""
}

// find returns the node for qname, or a wildcard node that synthesises it
// (reported by the second result).
// The wildcard is only considered when qname does not exist, and only at
// the closest encloser (RFC 4592).
func (z *Zone) find(qname string) (node, bool) {
	k := key(qname)
	if n := z.nodes[k]; n != nil {
		return n, false
	}
	if z.exists[k] {
		return nil, false
	}
	for enc := dns.Parent(k); ; enc = dns.Parent(enc) {
		if z.exists[enc] {
			if w := z.nodes["*."+enc]; w != nil {
				return w, true
			}
			return nil, false
		}
		if enc == key(z.Origin) || enc == "." {
			return nil, false
		}
	}
}

// negativeSOA is the SOA placed in negative answers; its TTL is capped by
// the SOA minimum field (RFC 2308 section 3).
func (z *Zone) negativeSOA() dns.RR {
	soa := z.SOA
	if m := soa.Data.(dns.SOA).MinTTL; m < soa.TTL {
		soa.TTL = m
	}
	return soa
}

// addresses returns in-zone A and AAAA records for host.
func (z *Zone) addresses(host string) []dns.RR {
	n := z.nodes[key(host)]
	if n == nil {
		return nil
	}
	return append(append([]dns.RR{}, n[dns.TypeA]...), n[dns.TypeAAAA]...)
}

// glue returns addresses for name servers named in a referral.
func (z *Zone) glue(nsset []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range nsset {
		out = append(out, z.addresses(rr.Data.(dns.NS).Host)...)
	}
	return out
}

// additional collects address records for targets mentioned in answers.
func (z *Zone) additional(answers []dns.RR) []dns.RR {
	var out []dns.RR
	seen := map[string]bool{}
	for _, rr := range answers {
		var host string
		switch d := rr.Data.(type) {
		case dns.MX:
			host = d.Exchange
		case dns.NS:
			host = d.Host
		case dns.SRV:
			host = d.Target
		default:
			continue
		}
		if seen[key(host)] || z.findCut(host) != "" {
			continue
		}
		seen[key(host)] = true
		out = append(out, z.addresses(host)...)
	}
	return out
}

package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avohra25/zonewire/dns"
	"github.com/avohra25/zonewire/zone"
)

func testZone(t testing.TB) *zone.Zone {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`$ORIGIN example.com.
$TTL 300
@     SOA ns1 hostmaster 1 7200 900 1209600 60
@     NS  ns1
ns1   A   192.0.2.1
www   A   192.0.2.80
alias CNAME www
`)
	// 120 addresses on one name: far more than fits in 512 octets.
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&sb, "big A 10.0.%d.%d\n", i/256, i%256)
	}
	z, err := zone.Load(strings.NewReader(sb.String()), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func startServer(t testing.TB, zones ...*zone.Zone) (*Server, string) {
	t.Helper()
	return serve(t, New(zones...))
}

// serve runs s on a loopback port until the test ends.
func serve(t testing.TB, s *Server) (*Server, string) {
	t.Helper()
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.ListenAndServe(ctx, "127.0.0.1:0", func(u, _ net.Addr) { ready <- u.String() })
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return s, addr
}

func TestUDPQuery(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	c := &Client{}
	r, err := c.Query(context.Background(), addr, "alias.example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Authoritative || r.RCode != dns.RCodeSuccess || len(r.Answers) != 2 {
		t.Fatalf("unexpected reply:\n%v", r)
	}
	if r.Answers[1].Data != (dns.A{Addr: netip.MustParseAddr("192.0.2.80")}) {
		t.Fatalf("got %v", r.Answers[1])
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	// A raw UDP query without EDNS must come back truncated.
	q, _ := dns.NewQuery(77, "big.example.com.", dns.TypeA)
	udp := &Client{}
	r, err := udp.exchange(context.Background(), "udp", addr, q)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Answers) >= 120 {
		t.Fatalf("expected truncated UDP reply, got tc=%v with %d answers", r.Truncated, len(r.Answers))
	}
	// The client transparently retries over TCP and gets everything.
	full, err := udp.Query(context.Background(), addr, "big.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if full.Truncated || len(full.Answers) != 120 {
		t.Fatalf("TCP retry got tc=%v with %d answers", full.Truncated, len(full.Answers))
	}
	// With a large enough EDNS buffer UDP alone suffices.
	big := New(testZone(t))
	big.MaxUDPSize = 4096
	_, addr = serve(t, big)
	edns := &Client{UDPSize: 4096}
	q2, _ := dns.NewQuery(78, "big.example.com.", dns.TypeA)
	q2.SetEDNS(4096)
	r2, err := edns.exchange(context.Background(), "udp", addr, q2)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Truncated || len(r2.Answers) != 120 {
		t.Fatalf("EDNS UDP got tc=%v with %d answers", r2.Truncated, len(r2.Answers))
	}
	if size, ok := r2.EDNS(); !ok || size != 4096 {
		t.Fatalf("server should echo OPT, got %d %v", size, ok)
	}
}

func TestErrorResponses(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	c := &Client{}
	ctx := context.Background()
	r, err := c.Query(ctx, addr, "example.org.", dns.TypeA)
	if err != nil || r.RCode != dns.RCodeRefused {
		t.Fatalf("out-of-zone: %v %v", r, err)
	}
	r, err = c.Query(ctx, addr, "missing.example.com.", dns.TypeA)
	if err != nil || r.RCode != dns.RCodeNameError || len(r.Authority) != 1 || r.Authority[0].TTL != 60 {
		t.Fatalf("nxdomain: %v %v", r, err)
	}
	q, _ := dns.NewQuery(5, "www.example.com.", dns.TypeA)
	q.Opcode = dns.OpcodeStatus
	r, err = c.Exchange(ctx, addr, q)
	if err != nil || r.RCode != dns.RCodeNotImplemented {
		t.Fatalf("status opcode: %v %v", r, err)
	}
	q, _ = dns.NewQuery(6, "example.com.", dns.TypeAXFR)
	r, err = c.Exchange(ctx, addr, q)
	if err != nil || r.RCode != dns.RCodeFormatError {
		t.Fatalf("AXFR over UDP: %v %v", r, err)
	}
}

func TestGarbageGetsFormErr(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF})
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := dns.Unpack(buf[:n])
	if err != nil || r.ID != 0xABCD || r.RCode != dns.RCodeFormatError {
		t.Fatalf("got %v %v", r, err)
	}
}

func TestTCPPipelining(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	names := []string{"www.example.com.", "ns1.example.com.", "missing.example.com."}
	for i, n := range names {
		q, _ := dns.NewQuery(uint16(100+i), n, dns.TypeA)
		w, _ := q.Pack()
		if err := WriteTCPMessage(conn, w); err != nil {
			t.Fatal(err)
		}
	}
	for i := range names {
		b, err := ReadTCPMessage(conn)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := dns.Unpack(b)
		if r.ID != uint16(100+i) {
			t.Fatalf("reply %d has id %d", i, r.ID)
		}
	}
}

func TestAXFR(t *testing.T) {
	z := testZone(t)
	_, addr := startServer(t, z)
	c := &Client{}
	rrs, err := c.Transfer(context.Background(), addr, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != len(z.Records()) || rrs[0].Type() != dns.TypeSOA {
		t.Fatalf("transferred %d records, zone has %d", len(rrs), len(z.Records()))
	}
	// Transferred records rebuild an identical zone.
	z2, err := zone.New("example.com.", rrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(z2.Records()) != len(z.Records()) {
		t.Fatal("rebuilt zone differs")
	}
	if _, err := c.Transfer(context.Background(), addr, "www.example.com."); err == nil {
		t.Fatal("transfer of a non-apex name should fail")
	}
}

func TestConcurrentClients(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := &Client{ForceTCP: i%2 == 0}
			r, err := c.Query(context.Background(), addr, "www.example.com.", dns.TypeA)
			if err == nil && len(r.Answers) != 1 {
				err = fmt.Errorf("got %d answers", len(r.Answers))
			}
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestMostSpecificZoneWins(t *testing.T) {
	sub, err := zone.Load(strings.NewReader("$TTL 60\n@ SOA ns hm 1 2 3 4 5\n@ NS ns\nwww A 198.51.100.7\n"), "dev.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	_, addr := startServer(t, testZone(t), sub)
	r, err := (&Client{}).Query(context.Background(), addr, "www.dev.example.com.", dns.TypeA)
	if err != nil || len(r.Answers) != 1 || r.Answers[0].Data.String() != "198.51.100.7" {
		t.Fatalf("got %v %v", r, err)
	}
}

func TestCloseIsIdempotentAndStopsServing(t *testing.T) {
	s := New(testZone(t))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { done <- s.ServeUDP(pc) }()
	time.Sleep(20 * time.Millisecond)
	s.Close()
	s.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := s.ServeUDP(pc); err == nil {
		t.Fatal("serving after Close should fail")
	}
}

func TestAXFRSpansMessages(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("$TTL 60\n@ SOA ns hm 1 2 3 4 5\n@ NS ns\n")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&sb, "host%d TXT \"record number %d with some padding text\"\n", i, i)
	}
	z, err := zone.Load(strings.NewReader(sb.String()), "big.test.")
	if err != nil {
		t.Fatal(err)
	}
	s := New(z)
	q, _ := dns.NewQuery(1, "big.test.", dns.TypeAXFR)
	msgs := s.transfer(q)
	if len(msgs) < 5 {
		t.Fatalf("expected the transfer to span several messages, got %d", len(msgs))
	}
	_, addr := serve(t, s)
	rrs, err := (&Client{}).Transfer(context.Background(), addr, "big.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 3002 {
		t.Fatalf("got %d records", len(rrs))
	}
}

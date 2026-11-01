// Package server serves zones over UDP and TCP and provides a client with
// TCP fallback and a TTL-respecting cache.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/avohra25/zonewire/dns"
	"github.com/avohra25/zonewire/zone"
)

// Server answers queries authoritatively for a set of zones.
type Server struct {
	// MaxUDPSize caps the EDNS payload size the server will use (default 1232).
	MaxUDPSize uint16
	// TCPIdleTimeout closes idle TCP connections (default 10s).
	TCPIdleTimeout time.Duration
	// Logger receives one line per query when non-nil.
	Logger *log.Logger

	mu    sync.RWMutex
	zones map[string]*zone.Zone

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
	lmu       sync.Mutex
	closers   []io.Closer
}

// New returns a server for the given zones.
func New(zones ...*zone.Zone) *Server {
	s := &Server{zones: map[string]*zone.Zone{}, done: make(chan struct{})}
	for _, z := range zones {
		s.AddZone(z)
	}
	return s
}

// AddZone adds or replaces a zone; it is safe to call while serving.
func (s *Server) AddZone(z *zone.Zone) {
	s.mu.Lock()
	s.zones[strings.ToLower(z.Origin)] = z
	s.mu.Unlock()
}

// zoneFor picks the most specific zone that contains name.
func (s *Server) zoneFor(name string) *zone.Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for n := strings.ToLower(name); ; n = dns.Parent(n) {
		if z, ok := s.zones[n]; ok {
			return z
		}
		if n == "." {
			return nil
		}
	}
}

// Handle builds the response to one query. It returns nil for messages
// that must not be answered (responses, or input too broken to echo).
func (s *Server) Handle(req *dns.Message) *dns.Message {
	if req.Response {
		return nil
	}
	resp := req.Reply()
	resp.Additional = nil
	if size, ok := req.EDNS(); ok {
		resp.SetEDNS(min(size, s.maxUDP()))
	}
	switch {
	case req.Opcode != dns.OpcodeQuery:
		resp.RCode = dns.RCodeNotImplemented
		return resp
	case len(req.Questions) != 1:
		resp.RCode = dns.RCodeFormatError
		return resp
	}
	q := req.Questions[0]
	if q.Class != dns.ClassINET && q.Class != dns.ClassANY {
		resp.RCode = dns.RCodeRefused
		return resp
	}
	if q.Type == dns.TypeAXFR {
		resp.RCode = dns.RCodeFormatError // transfers are only offered over TCP
		return resp
	}
	z := s.zoneFor(q.Name)
	if z == nil {
		resp.RCode = dns.RCodeRefused
		return resp
	}
	r := z.Lookup(q.Name, q.Type)
	resp.RCode = r.RCode
	resp.Authoritative = r.Authoritative
	resp.Answers = r.Answer
	resp.Authority = r.Authority
	resp.Additional = append(r.Additional, resp.Additional...)
	return resp
}

func (s *Server) maxUDP() uint16 {
	if s.MaxUDPSize == 0 {
		return 1232
	}
	return s.MaxUDPSize
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

func (s *Server) track(c io.Closer) bool {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	select {
	case <-s.done:
		c.Close()
		return false
	default:
	}
	s.closers = append(s.closers, c)
	return true
}

// ServeUDP answers queries on pc until Close is called.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	if !s.track(pc) {
		return net.ErrClosed
	}
	s.wg.Add(1)
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.closed() {
				return nil
			}
			return err
		}
		wire := s.answerUDP(buf[:n], addr)
		if wire != nil {
			pc.WriteTo(wire, addr)
		}
	}
}

func (s *Server) answerUDP(b []byte, addr net.Addr) []byte {
	req, err := dns.Unpack(b)
	if err != nil {
		return formErr(b)
	}
	resp := s.Handle(req)
	if resp == nil {
		return nil
	}
	limit := dns.MinUDPSize
	if size, ok := req.EDNS(); ok {
		limit = int(min(size, s.maxUDP()))
	}
	wire, err := resp.PackLimit(limit)
	if err != nil {
		resp = req.Reply()
		resp.RCode = dns.RCodeServerFailure
		wire, _ = resp.Pack()
	}
	s.logQuery("udp", addr, req, resp)
	return wire
}

func (s *Server) logQuery(proto string, addr net.Addr, req, resp *dns.Message) {
	q := "?"
	if len(req.Questions) > 0 {
		q = req.Questions[0].String()
	}
	s.logf("%s %s %s -> %s an=%d ns=%d ar=%d tc=%v", proto, addr, q, resp.RCode, len(resp.Answers), len(resp.Authority), len(resp.Additional), resp.Truncated)
}

// formErr answers an undecodable query with FORMERR if at least the
// header is present and it looks like a query.
func formErr(b []byte) []byte {
	if len(b) < 12 || b[2]&0x80 != 0 {
		return nil
	}
	m := &dns.Message{Header: dns.Header{ID: binary.BigEndian.Uint16(b), Response: true, RCode: dns.RCodeFormatError}}
	wire, _ := m.Pack()
	return wire
}

// ServeTCP accepts connections on ln until Close is called. Each
// connection may carry several length-prefixed queries (RFC 7766).
func (s *Server) ServeTCP(ln net.Listener) error {
	if !s.track(ln) {
		return net.ErrClosed
	}
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(c)
		}()
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-s.done:
			c.Close()
		case <-stop:
		}
	}()
	idle := s.TCPIdleTimeout
	if idle == 0 {
		idle = 10 * time.Second
	}
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		b, err := ReadTCPMessage(c)
		if err != nil {
			return
		}
		req, err := dns.Unpack(b)
		if err != nil {
			if w := formErr(b); w != nil {
				WriteTCPMessage(c, w)
			}
			return
		}
		var out [][]byte
		if len(req.Questions) == 1 && req.Questions[0].Type == dns.TypeAXFR && !req.Response {
			out = s.transfer(req)
		} else if resp := s.Handle(req); resp != nil {
			wire, err := resp.PackLimit(65535)
			if err != nil {
				continue
			}
			s.logQuery("tcp", c.RemoteAddr(), req, resp)
			out = [][]byte{wire}
		}
		c.SetWriteDeadline(time.Now().Add(idle))
		for _, w := range out {
			if err := WriteTCPMessage(c, w); err != nil {
				return
			}
		}
	}
}

// axfrBatch is the target size of each message in a zone transfer.
const axfrBatch = 16000

// transfer implements AXFR (RFC 5936): SOA, every other record, SOA,
// split across as many messages as needed.
func (s *Server) transfer(req *dns.Message) [][]byte {
	q := req.Questions[0]
	reply := func() *dns.Message { r := req.Reply(); r.Authoritative = true; return r }
	z := s.zoneFor(q.Name)
	if z == nil || !dns.EqualNames(z.Origin, q.Name) {
		r := reply()
		r.Authoritative = false
		r.RCode = dns.RCodeNotAuth
		w, _ := r.Pack()
		return [][]byte{w}
	}
	recs := append(z.Records(), z.SOA)
	var out [][]byte
	cur := reply()
	size := 0
	for _, rr := range recs {
		// The uncompressed size of each record is an upper bound on what
		// it adds to the message, which keeps batching linear.
		one, err := (&dns.Message{Answers: []dns.RR{rr}}).Pack()
		if err != nil {
			continue
		}
		n := len(one) - 12
		if size+n > axfrBatch && len(cur.Answers) > 0 {
			w, _ := cur.Pack()
			out = append(out, w)
			cur = reply()
			cur.Questions = nil
			size = 0
		}
		cur.Answers = append(cur.Answers, rr)
		size += n
	}
	w, _ := cur.Pack()
	s.logf("tcp axfr %s -> %d records in %d messages", z.Origin, len(recs), len(out)+1)
	return append(out, w)
}

// ReadTCPMessage reads one length-prefixed DNS message.
func ReadTCPMessage(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

// WriteTCPMessage writes one length-prefixed DNS message.
func WriteTCPMessage(w io.Writer, b []byte) error {
	if len(b) > 0xFFFF {
		return errors.New("dns: message too large for TCP")
	}
	_, err := w.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
	return err
}

func (s *Server) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// ListenAndServe serves on addr over both UDP and TCP until ctx is done.
// ready, if non-nil, is called with the bound addresses once listening.
func (s *Server) ListenAndServe(ctx context.Context, addr string, ready func(udp, tcp net.Addr)) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	// Bind TCP to the same port UDP got, which matters when addr ends in :0.
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return err
	}
	if ready != nil {
		ready(pc.LocalAddr(), ln.Addr())
	}
	errc := make(chan error, 2)
	go func() { errc <- s.ServeUDP(pc) }()
	go func() { errc <- s.ServeTCP(ln) }()
	select {
	case <-ctx.Done():
		s.Close()
		return nil
	case err := <-errc:
		s.Close()
		return err
	}
}

// Close stops all listeners and connections and waits for them to finish.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.lmu.Lock()
		for _, c := range s.closers {
			c.Close()
		}
		s.lmu.Unlock()
	})
	s.wg.Wait()
	return nil
}

package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/avohra25/zonewire/dns"
)

// Client sends queries to a single server.
type Client struct {
	// Timeout bounds each attempt (default 2s).
	Timeout time.Duration
	// UDPSize is the EDNS payload size to advertise; 0 sends no OPT record.
	UDPSize uint16
	// ForceTCP skips UDP entirely.
	ForceTCP bool
}

// ErrMismatch means a reply did not match the query it answered.
var ErrMismatch = errors.New("dns: reply does not match query")

func randomID() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// Query asks server (host:port) for name/type and returns the reply.
func (c *Client) Query(ctx context.Context, server, name string, t dns.Type) (*dns.Message, error) {
	q, err := dns.NewQuery(randomID(), name, t)
	if err != nil {
		return nil, err
	}
	return c.Exchange(ctx, server, q)
}

// Exchange sends q over UDP and retries over TCP if the reply is truncated.
func (c *Client) Exchange(ctx context.Context, server string, q *dns.Message) (*dns.Message, error) {
	if c.UDPSize > 0 {
		if _, ok := q.EDNS(); !ok {
			q.SetEDNS(c.UDPSize)
		}
	}
	if !c.ForceTCP {
		r, err := c.exchange(ctx, "udp", server, q)
		if err != nil || !r.Truncated {
			return r, err
		}
	}
	return c.exchange(ctx, "tcp", server, q)
}

func (c *Client) exchange(ctx context.Context, network, server string, q *dns.Message) (*dns.Message, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		if err := WriteTCPMessage(conn, wire); err != nil {
			return nil, err
		}
		b, err := ReadTCPMessage(conn)
		if err != nil {
			return nil, err
		}
		return checkReply(q, b)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		r, err := checkReply(q, buf[:n])
		if errors.Is(err, ErrMismatch) {
			continue // stray or spoofed datagram: keep waiting
		}
		return r, err
	}
}

func checkReply(q *dns.Message, b []byte) (*dns.Message, error) {
	r, err := dns.Unpack(b)
	if err != nil {
		return nil, err
	}
	if r.ID != q.ID || !r.Response {
		return nil, ErrMismatch
	}
	if len(r.Questions) > 0 && (len(r.Questions) != 1 || !dns.EqualNames(r.Questions[0].Name, q.Questions[0].Name) || r.Questions[0].Type != q.Questions[0].Type) {
		return nil, ErrMismatch
	}
	if len(r.Questions) == 0 && !r.Truncated && r.RCode != dns.RCodeFormatError {
		return nil, fmt.Errorf("%w: no question section", ErrMismatch)
	}
	return r, nil
}

// Transfer performs an AXFR of zone over TCP and returns its records,
// with the closing SOA removed.
func (c *Client) Transfer(ctx context.Context, server, zoneName string) ([]dns.RR, error) {
	q, err := dns.NewQuery(randomID(), zoneName, dns.TypeAXFR)
	if err != nil {
		return nil, err
	}
	q.RecursionDesired = false
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	wire, _ := q.Pack()
	if err := WriteTCPMessage(conn, wire); err != nil {
		return nil, err
	}
	var out []dns.RR
	for {
		b, err := ReadTCPMessage(conn)
		if err != nil {
			return nil, err
		}
		r, err := dns.Unpack(b)
		if err != nil {
			return nil, err
		}
		if r.ID != q.ID {
			return nil, ErrMismatch
		}
		if r.RCode != dns.RCodeSuccess {
			return nil, fmt.Errorf("dns: transfer refused: %s", r.RCode)
		}
		for _, rr := range r.Answers {
			if len(out) == 0 && rr.Type() != dns.TypeSOA {
				return nil, errors.New("dns: transfer does not start with SOA")
			}
			if len(out) > 0 && rr.Type() == dns.TypeSOA {
				return out, nil
			}
			out = append(out, rr)
		}
	}
}

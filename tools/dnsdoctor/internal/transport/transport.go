// Package transport sends DNS queries over UDP with automatic TCP fallback
// on truncation, per-attempt timeouts and basic response validation.
package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

// Exchanger sends a query to a server and returns its response.
type Exchanger interface {
	Exchange(ctx context.Context, server netip.AddrPort, q *dnswire.Msg) (*dnswire.Msg, time.Duration, error)
}

// ErrMismatch is returned when a response does not match the query.
var ErrMismatch = errors.New("transport: response does not match query")

// Net is the real network Exchanger.
type Net struct {
	// Timeout bounds each attempt (UDP or TCP). Defaults to 3s.
	Timeout time.Duration
	// Retries is the number of extra UDP attempts after a timeout.
	Retries int
	// Dialer is used for all connections; nil means a zero net.Dialer.
	Dialer *net.Dialer
}

func (n *Net) timeout() time.Duration {
	if n.Timeout <= 0 {
		return 3 * time.Second
	}
	return n.Timeout
}

func (n *Net) dialer() *net.Dialer {
	if n.Dialer != nil {
		return n.Dialer
	}
	return &net.Dialer{}
}

// RandomID returns a cryptographically random query ID.
func RandomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

// Exchange implements Exchanger.
func (n *Net) Exchange(ctx context.Context, server netip.AddrPort, q *dnswire.Msg) (*dnswire.Msg, time.Duration, error) {
	wire, err := q.Pack()
	if err != nil {
		return nil, 0, err
	}
	var lastErr error
	for attempt := 0; attempt <= n.Retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		start := time.Now()
		resp, err := n.exchangeUDP(ctx, server, q, wire)
		if err == nil && resp.Truncated {
			resp, err = n.exchangeTCP(ctx, server, q, wire)
		}
		if err == nil {
			return resp, time.Since(start), nil
		}
		lastErr = err
		var ne net.Error
		if !(errors.As(err, &ne) && ne.Timeout()) {
			break // only timeouts are worth retrying
		}
	}
	return nil, 0, lastErr
}

func (n *Net) exchangeUDP(ctx context.Context, server netip.AddrPort, q *dnswire.Msg, wire []byte) (*dnswire.Msg, error) {
	actx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	conn, err := n.dialer().DialContext(actx, "udp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := actx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		nr, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		resp, err := dnswire.Unpack(buf[:nr])
		if err != nil {
			continue // garbage; keep waiting for the real answer until timeout
		}
		if err := match(q, resp); err != nil {
			continue // possible spoofing / stale packet: ignore
		}
		return resp, nil
	}
}

func (n *Net) exchangeTCP(ctx context.Context, server netip.AddrPort, q *dnswire.Msg, wire []byte) (*dnswire.Msg, error) {
	actx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	conn, err := n.dialer().DialContext(actx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := actx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
	frame = append(frame, wire...)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	resp, err := dnswire.Unpack(buf)
	if err != nil {
		return nil, err
	}
	if err := match(q, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func match(q, r *dnswire.Msg) error {
	if !r.Response || r.ID != q.ID {
		return ErrMismatch
	}
	// Some servers omit the question on FORMERR/NOTIMP; accept that.
	if len(r.Question) == 0 && (r.Rcode == dnswire.RcodeFormErr || r.Rcode == dnswire.RcodeNotImp) {
		return nil
	}
	if len(r.Question) != 1 || len(q.Question) != 1 {
		return ErrMismatch
	}
	a, b := q.Question[0], r.Question[0]
	if a.Type != b.Type || a.Class != b.Class || !dnswire.EqualNames(a.Name, b.Name) {
		return fmt.Errorf("%w: asked %s/%s, got %s/%s", ErrMismatch, a.Name, a.Type, b.Name, b.Type)
	}
	return nil
}

// IsNetworkUnreachable reports whether err means the local host has no
// route for the address family (typically IPv6 on IPv4-only hosts).
func IsNetworkUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

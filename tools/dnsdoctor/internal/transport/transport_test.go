package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

// server starts UDP and TCP listeners on the same localhost port.
// udpMode: "truncate" sets TC; "spoof" sends a wrong-ID packet first;
// "silent" never answers.
func server(t *testing.T, udpMode string) netip.AddrPort {
	t.Helper()
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tl.Addr().(*net.TCPAddr).Port
	ul, err := net.ListenPacket("udp", tl.Addr().String())
	if err != nil {
		t.Skipf("cannot bind UDP on same port: %v", err)
	}
	t.Cleanup(func() { tl.Close(); ul.Close() })

	answer := func(q *dnswire.Msg, tc bool) []byte {
		r := &dnswire.Msg{Header: dnswire.Header{ID: q.ID, Response: true, Authoritative: true, Truncated: tc}, Question: q.Question}
		if !tc {
			r.Answer = []dnswire.RR{{Name: q.Question[0].Name, Type: dnswire.TypeA, Class: 1, TTL: 60, Data: &dnswire.A{Addr: netip.MustParseAddr("192.0.2.7")}}}
		}
		b, _ := r.Pack()
		return b
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := dnswire.Unpack(buf[:n])
			if err != nil {
				continue
			}
			switch udpMode {
			case "silent":
				continue
			case "truncate":
				_, _ = ul.WriteTo(answer(q, true), addr)
			case "spoof":
				bad := *q
				bad.ID++
				_, _ = ul.WriteTo(answer(&bad, false), addr)
				_, _ = ul.WriteTo([]byte{1, 2, 3}, addr)
				_, _ = ul.WriteTo(answer(q, false), addr)
			default:
				_, _ = ul.WriteTo(answer(q, false), addr)
			}
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				q, err := dnswire.Unpack(buf)
				if err != nil {
					return
				}
				b := answer(q, false)
				_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
			}(c)
		}
	}()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

func query() *dnswire.Msg {
	return dnswire.NewQuery(RandomID(), "host.example.test.", dnswire.TypeA, false)
}

func TestUDPAnswer(t *testing.T) {
	addr := server(t, "")
	n := &Net{Timeout: 2 * time.Second}
	r, _, err := n.Exchange(context.Background(), addr, query())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) != 1 || r.Truncated {
		t.Fatalf("unexpected answer %+v", r)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	addr := server(t, "truncate")
	n := &Net{Timeout: 2 * time.Second}
	r, _, err := n.Exchange(context.Background(), addr, query())
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated || len(r.Answer) != 1 {
		t.Fatalf("expected full TCP answer, got %+v", r)
	}
}

func TestSpoofedAndGarbagePacketsIgnored(t *testing.T) {
	addr := server(t, "spoof")
	n := &Net{Timeout: 2 * time.Second}
	q := query()
	r, _, err := n.Exchange(context.Background(), addr, q)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != q.ID {
		t.Fatalf("accepted response with wrong ID")
	}
}

func TestTimeout(t *testing.T) {
	addr := server(t, "silent")
	n := &Net{Timeout: 150 * time.Millisecond, Retries: 1}
	start := time.Now()
	_, _, err := n.Exchange(context.Background(), addr, query())
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
	if el := time.Since(start); el < 250*time.Millisecond || el > 2*time.Second {
		t.Fatalf("retry timing off: %v", el)
	}
}

func TestMatch(t *testing.T) {
	q := query()
	r := &dnswire.Msg{Header: dnswire.Header{ID: q.ID, Response: true}, Question: []dnswire.Question{{Name: "HOST.example.test.", Type: dnswire.TypeA, Class: 1}}}
	if err := match(q, r); err != nil {
		t.Fatalf("case-insensitive question should match: %v", err)
	}
	r.Question[0].Type = dnswire.TypeAAAA
	if err := match(q, r); err == nil {
		t.Fatal("type mismatch accepted")
	}
	r.Question = nil
	r.Rcode = dnswire.RcodeFormErr
	if err := match(q, r); err != nil {
		t.Fatal("FORMERR without question should be accepted")
	}
}

func TestIsNetworkUnreachable(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: &netSyscallErr{syscall.ENETUNREACH}}
	if !IsNetworkUnreachable(err) {
		t.Fatal("ENETUNREACH not detected")
	}
	if IsNetworkUnreachable(errors.New("boom")) {
		t.Fatal("false positive")
	}
}

type netSyscallErr struct{ errno syscall.Errno }

func (e *netSyscallErr) Error() string { return e.errno.Error() }
func (e *netSyscallErr) Unwrap() error { return e.errno }

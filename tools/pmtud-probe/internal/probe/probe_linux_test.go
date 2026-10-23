//go:build linux

package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// closedUDPPort returns a loopback UDP port with nothing listening.
func closedUDPPort(t *testing.T, network, addr string) int {
	t.Helper()
	c, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Skipf("%s unavailable: %v", network, err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return port
}

func TestUDPLoopbackReply(t *testing.T) {
	for _, tc := range []struct{ network, addr, target string }{
		{"udp4", "127.0.0.1:0", "127.0.0.1"},
		{"udp6", "[::1]:0", "::1"},
	} {
		t.Run(tc.network, func(t *testing.T) { udpLoopback(t, tc.network, tc.addr, tc.target) })
	}
}

func udpLoopback(t *testing.T, network, addr, target string) {
	{
		tc := struct{ target string }{target}
		port := closedUDPPort(t, network, addr)
		p, err := New(netip.MustParseAddr(tc.target), MethodUDP, port)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{MinProbe(p.Target()), 1500, 9000, 65535} {
			r, err := p.Probe(context.Background(), size, 2*time.Second)
			if err != nil {
				t.Fatalf("%s size %d: %v", tc.target, size, err)
			}
			if r.Outcome != Reply || r.From != p.Target() {
				t.Fatalf("%s size %d: got %+v, want reply from target", tc.target, size, r)
			}
		}
	}
}

func TestUDPAnswerCountsAsReply(t *testing.T) {
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			_, a, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = srv.WriteTo([]byte("ok"), a)
		}
	}()
	p, err := New(netip.MustParseAddr("127.0.0.1"), MethodUDP, srv.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Probe(context.Background(), 1200, 2*time.Second)
	if err != nil || r.Outcome != Reply {
		t.Fatalf("got %+v %v", r, err)
	}
}

func TestICMPLoopback(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1"} {
		t.Run(a, func(t *testing.T) {
			p, err := New(netip.MustParseAddr(a), MethodICMP, 33434)
			if errors.Is(err, ErrPermission) {
				t.Skip("unprivileged ICMP sockets disabled (ping_group_range)")
			}
			if err != nil {
				t.Skipf("%s: %v", a, err) // e.g. kernel without IPv6
			}
			for _, size := range []int{MinProbe(p.Target()), 1500, 9000} {
				r, err := p.Probe(context.Background(), size, 2*time.Second)
				if err != nil || r.Outcome != Reply {
					t.Fatalf("size %d: got %+v %v", size, r, err)
				}
			}
		})
	}
}

func TestProbeTimeoutAndCancel(t *testing.T) {
	// A UDP socket that swallows datagrams: no answer, no ICMP.
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	p, err := New(netip.MustParseAddr("127.0.0.1"), MethodUDP, srv.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r, err := p.Probe(context.Background(), 100, 150*time.Millisecond)
	if err != nil || r.Outcome != Timeout {
		t.Fatalf("got %+v %v", r, err)
	}
	if el := time.Since(start); el < 100*time.Millisecond || el > 2*time.Second {
		t.Fatalf("timeout took %v", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start = time.Now()
	if _, err := p.Probe(ctx, 100, 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation not honoured")
	}
}

func TestProbeSizeValidation(t *testing.T) {
	p, err := New(netip.MustParseAddr("127.0.0.1"), MethodUDP, 9)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []int{0, 20, 35, 65536} {
		if _, err := p.Probe(context.Background(), s, time.Second); err == nil {
			t.Errorf("size %d accepted", s)
		}
	}
	if _, err := New(netip.Addr{}, MethodUDP, 9); err == nil {
		t.Error("invalid address accepted")
	}
	if _, err := New(netip.MustParseAddr("127.0.0.1"), "tcp", 9); err == nil {
		t.Error("bad method accepted")
	}
	if _, err := New(netip.MustParseAddr("127.0.0.1"), MethodUDP, 0); err == nil {
		t.Error("port 0 accepted")
	}
}

func TestPacketLayout(t *testing.T) {
	p := &sockProber{target: netip.MustParseAddr("192.0.2.1"), method: MethodUDP}
	n := Nonce(0xdeadbeef, 7)
	b := p.packet(1500, 7, n)
	if len(b) != 1500-28 || [NonceLen]byte(b[:NonceLen]) != n {
		t.Fatalf("udp payload len %d", len(b))
	}
	p.method = MethodICMP
	b = p.packet(1500, 7, n)
	if len(b) != 1480 || b[0] != 8 || b[7] != 7 || !p.isReply(append([]byte{0}, b[1:]...), 7, n) {
		t.Fatal("icmp v4 layout")
	}
	if p.isReply(append([]byte{0}, b[1:]...), 8, n) {
		t.Fatal("wrong seq accepted")
	}
	p = &sockProber{target: netip.MustParseAddr("2001:db8::1"), method: MethodICMP, v6: true}
	b = p.packet(1280, 1, n)
	if len(b) != 1240 || b[0] != 128 {
		t.Fatal("icmp v6 layout")
	}
	if !p.quoteMatches(b[:8], 1, n) || p.quoteMatches(b[:8], 2, n) || !p.quoteMatches(b[:12], 1, n) {
		t.Fatal("quote matching")
	}
}

func TestLookupRouteLoopback(t *testing.T) {
	r, err := LookupRoute(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Local != netip.MustParseAddr("127.0.0.1") || r.Interface == "" || r.IfMTU < 1500 || r.RouteMTU < 1500 {
		t.Fatalf("unexpected route %+v", r)
	}
}

func TestTCPCheckLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ti, err := TCPCheck(context.Background(), netip.MustParseAddr("127.0.0.1"), ln.Addr().(*net.TCPAddr).Port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ti.SndMSS == 0 || ti.PMTU < 1500 {
		t.Fatalf("unexpected tcp_info %+v", ti)
	}
	if _, err := TCPCheck(context.Background(), netip.MustParseAddr("127.0.0.1"), closedTCPPort(t), time.Second); err == nil {
		t.Fatal("closed port accepted")
	}
}

func closedTCPPort(t *testing.T) int {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

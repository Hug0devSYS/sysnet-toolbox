package ntp

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// stepClock advances by step at every call, so t1 -> t4 = step.
type stepClock struct {
	mu   sync.Mutex
	cur  time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cur = c.cur.Add(c.step)
	return c.cur
}

func (c *stepClock) last() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

// fakeConn answers each request through handler, synchronously.
type fakeConn struct {
	clock    *stepClock
	handler  func(req Packet, t1 time.Time) [][]byte
	queue    [][]byte
	block    chan struct{} // when set, Read blocks until closed or deadline
	deadline time.Time
	mu       sync.Mutex
	writes   int
	writeErr error
	readErr  error
}

func (f *fakeConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	req, err := Decode(b)
	if err != nil {
		return 0, err
	}
	if f.handler != nil {
		f.queue = append(f.queue, f.handler(req, f.clock.last())...)
	}
	return len(b), nil
}

func (f *fakeConn) Read(b []byte) (int, error) {
	f.mu.Lock()
	if f.readErr != nil {
		f.mu.Unlock()
		return 0, f.readErr
	}
	if len(f.queue) > 0 {
		n := copy(b, f.queue[0])
		f.queue = f.queue[1:]
		f.mu.Unlock()
		return n, nil
	}
	block := f.block
	f.mu.Unlock()
	if block != nil {
		for {
			f.mu.Lock()
			d := f.deadline
			f.mu.Unlock()
			if !d.IsZero() && time.Now().After(d) {
				return 0, os.ErrDeadlineExceeded
			}
			select {
			case <-block:
				return 0, os.ErrDeadlineExceeded
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	return 0, os.ErrDeadlineExceeded
}

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) Close() error { return nil }

// server builds a handler answering with the given clock offset; T2 is
// 4ms after T1 (+offset) and the server holds the packet 2ms.
func server(offset time.Duration, mutate func(*Packet)) func(Packet, time.Time) [][]byte {
	return func(req Packet, t1 time.Time) [][]byte {
		t2 := t1.Add(4*time.Millisecond + offset)
		resp := Packet{
			Version: 4, Mode: ModeServer, Stratum: 2, Precision: -20, RefID: [4]byte{192, 0, 2, 1},
			RootDelay: DurationToShort(10 * time.Millisecond), RootDispersion: DurationToShort(5 * time.Millisecond),
			RefTime: TimeToNTP(t2.Add(-time.Minute)), OrigTime: req.XmitTime,
			RecvTime: TimeToNTP(t2), XmitTime: TimeToNTP(t2.Add(2 * time.Millisecond)),
		}
		if mutate != nil {
			mutate(&resp)
		}
		return [][]byte{resp.Encode()}
	}
}

func newClock() *stepClock {
	return &stepClock{cur: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC), step: 10 * time.Millisecond}
}

func TestQueryOffsetAndDelay(t *testing.T) {
	for _, off := range []time.Duration{0, 123 * time.Millisecond, -3 * time.Second, 2 * time.Hour} {
		c := newClock()
		conn := &fakeConn{clock: c, handler: server(off, nil)}
		s, err := Query(context.Background(), conn, c.Now, time.Second)
		if err != nil {
			t.Fatalf("offset %v: %v", off, err)
		}
		if d := (s.Offset - off).Abs(); d > time.Microsecond {
			t.Errorf("offset %v: measured %v", off, s.Offset)
		}
		if d := (s.Delay - 8*time.Millisecond).Abs(); d > time.Microsecond {
			t.Errorf("offset %v: delay %v, want 8ms", off, s.Delay)
		}
		if s.Inconsistent {
			t.Errorf("offset %v: flagged inconsistent", off)
		}
	}
}

func TestQueryRequestIsMinimal(t *testing.T) {
	c := newClock()
	var seen []Packet
	conn := &fakeConn{clock: c, handler: func(req Packet, t1 time.Time) [][]byte {
		seen = append(seen, req)
		return server(0, nil)(req, t1)
	}}
	for i := 0; i < 2; i++ {
		if _, err := Query(context.Background(), conn, c.Now, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range seen {
		if r.Mode != ModeClient || r.Version != 4 || r.XmitTime == 0 {
			t.Fatalf("request %+v", r)
		}
		r.XmitTime = 0
		r.Mode, r.Version = 0, 0
		if r != (Packet{}) {
			t.Fatalf("request leaks client data: %+v", r)
		}
	}
	if seen[0].XmitTime == seen[1].XmitTime {
		t.Fatal("transmit cookie is not random")
	}
}

func TestQueryIgnoresSpoofedAndWrongMode(t *testing.T) {
	c := newClock()
	conn := &fakeConn{clock: c, handler: func(req Packet, t1 time.Time) [][]byte {
		good := server(time.Second, nil)(req, t1)[0]
		spoof := server(-time.Hour, func(p *Packet) { p.OrigTime++ })(req, t1)[0]
		mode := server(-time.Hour, func(p *Packet) { p.Mode = 5 })(req, t1)[0]
		return [][]byte{spoof, mode, []byte("short"), good}
	}}
	s, err := Query(context.Background(), conn, c.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s.Ignored != 3 {
		t.Fatalf("ignored %d, want 3", s.Ignored)
	}
	// Each read advances the step clock, so allow for the longer round trip.
	if (s.Offset - time.Second).Abs() > 50*time.Millisecond {
		t.Fatalf("spoofed answer used: offset %v", s.Offset)
	}
}

func TestQueryErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Packet)
		check  func(error) bool
	}{
		{"kod", func(p *Packet) { p.Stratum = 0; p.RefID = [4]byte{'R', 'A', 'T', 'E'} }, func(err error) bool {
			var k *KoDError
			return errors.As(err, &k) && k.Code == "RATE"
		}},
		{"unsynchronised chrony", func(p *Packet) { p.Stratum = 0; p.Leap = 3; p.RefID = [4]byte{} }, isUnsync},
		{"unsynchronised ntpd", func(p *Packet) { p.Stratum = 0; p.Leap = 3; p.RefID = [4]byte{'I', 'N', 'I', 'T'} }, isUnsync},
		{"xmit zero", func(p *Packet) { p.XmitTime = 0 }, isBogus},
		{"recv zero", func(p *Packet) { p.RecvTime = 0 }, isBogus},
		{"version", func(p *Packet) { p.Version = 7 }, isBogus},
		{"t3 before t2", func(p *Packet) { p.XmitTime = p.RecvTime - 1<<32 }, isBogus},
	}
	for _, tc := range cases {
		c := newClock()
		conn := &fakeConn{clock: c, handler: server(0, tc.mutate)}
		_, err := Query(context.Background(), conn, c.Now, time.Second)
		if !tc.check(err) {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
	}
	// Silence.
	c := newClock()
	if _, err := Query(context.Background(), &fakeConn{clock: c}, c.Now, time.Second); !errors.Is(err, ErrTimeout) {
		t.Errorf("silence: %v", err)
	}
	// ICMP port unreachable.
	if _, err := Query(context.Background(), &fakeConn{clock: c, readErr: syscall.ECONNREFUSED}, c.Now, time.Second); !errors.Is(err, ErrRefused) {
		t.Errorf("refused: %v", err)
	}
	// Send failure.
	if _, err := Query(context.Background(), &fakeConn{clock: c, writeErr: syscall.ENETUNREACH}, c.Now, time.Second); err == nil {
		t.Error("send error swallowed")
	}
}

func isUnsync(err error) bool {
	var u *UnsyncError
	return errors.As(err, &u)
}

func isBogus(err error) bool {
	var b *BogusError
	return errors.As(err, &b)
}

func TestQueryInconsistentTimestamps(t *testing.T) {
	c := newClock()
	// Server claims 500ms of processing during a 10ms round trip.
	conn := &fakeConn{clock: c, handler: server(0, func(p *Packet) {
		p.XmitTime += uint64(DurationToShort(500*time.Millisecond)) << 16
	})}
	s, err := Query(context.Background(), conn, c.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Inconsistent || s.Delay != 0 {
		t.Fatalf("inconsistent=%v delay=%v", s.Inconsistent, s.Delay)
	}
}

func TestQueryCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &fakeConn{clock: newClock(), block: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := Query(ctx, conn, time.Now, time.Minute)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("query not interrupted")
	}
}

func dialer(conn Conn) Dialer {
	return func(context.Context, netip.AddrPort) (Conn, error) { return conn, nil }
}

func noSleep(context.Context, time.Duration) error { return nil }

func TestMeasureClockFilterAndJitter(t *testing.T) {
	c := newClock()
	calls := 0
	// Delays: 8ms + extra; offsets distorted by half the extra delay on
	// the outbound leg, as a congested path would.
	extras := []time.Duration{30 * time.Millisecond, 0, 10 * time.Millisecond, 20 * time.Millisecond}
	conn := &fakeConn{clock: c, handler: func(req Packet, t1 time.Time) [][]byte {
		e := extras[calls]
		calls++
		c.mu.Lock()
		c.cur = c.cur.Add(e) // the round trip takes e longer
		c.mu.Unlock()
		return server(50*time.Millisecond+e, nil)(req, t1)
	}}
	m := Measure(context.Background(), netip.MustParseAddrPort("192.0.2.1:123"), Options{
		Samples: 4, Interval: time.Second, Timeout: time.Second, Dial: dialer(conn), Now: c.Now, Sleep: noSleep,
	})
	if !m.Usable() || m.Sent != 4 || m.Received != 4 {
		t.Fatalf("measurement %+v", m)
	}
	if (m.Best.Delay - 8*time.Millisecond).Abs() > time.Microsecond {
		t.Fatalf("best delay %v", m.Best.Delay)
	}
	if (m.Best.Offset - 50*time.Millisecond).Abs() > time.Microsecond {
		t.Fatalf("best offset %v", m.Best.Offset)
	}
	if m.Jitter <= 0 {
		t.Fatal("jitter not computed")
	}
	// Root distance: max(MINDISP, rootdelay+delay)/2 + rootdisp + disp + jitter.
	// (short-format encoding of the root delay/dispersion loses ~10us)
	min := 9*time.Millisecond + 5*time.Millisecond + m.Jitter - 20*time.Microsecond
	if m.RootDist < min || m.RootDist > min+time.Millisecond {
		t.Fatalf("root distance %v, expected about %v", m.RootDist, min)
	}
}

func TestMeasureStopsOnKoDAndRefused(t *testing.T) {
	c := newClock()
	conn := &fakeConn{clock: c, handler: server(0, func(p *Packet) { p.Stratum = 0; p.RefID = [4]byte{'D', 'E', 'N', 'Y'} })}
	m := Measure(context.Background(), netip.MustParseAddrPort("192.0.2.1:123"), Options{
		Samples: 4, Timeout: time.Second, Dial: dialer(conn), Now: c.Now, Sleep: noSleep,
	})
	if m.KoD != "DENY" || conn.writes != 1 || m.Usable() {
		t.Fatalf("kod: %+v writes=%d", m, conn.writes)
	}
	conn = &fakeConn{clock: c, readErr: syscall.ECONNREFUSED}
	m = Measure(context.Background(), netip.MustParseAddrPort("192.0.2.1:123"), Options{
		Samples: 4, Timeout: time.Second, Dial: dialer(conn), Now: c.Now, Sleep: noSleep,
	})
	if conn.writes != 1 || m.Received != 0 || len(m.Errors) != 1 {
		t.Fatalf("refused: %+v writes=%d", m, conn.writes)
	}
	// Timeouts are retried and deduplicated in the error list.
	conn = &fakeConn{clock: c}
	m = Measure(context.Background(), netip.MustParseAddrPort("192.0.2.1:123"), Options{
		Samples: 3, Timeout: time.Second, Dial: dialer(conn), Now: c.Now, Sleep: noSleep,
	})
	if conn.writes != 3 || len(m.Errors) != 1 || m.Errors[0] != ErrTimeout.Error()+" (x3)" {
		t.Fatalf("timeouts: %+v", m.Errors)
	}
	// Dial errors.
	m = Measure(context.Background(), netip.MustParseAddrPort("192.0.2.1:123"), Options{
		Dial: func(context.Context, netip.AddrPort) (Conn, error) { return nil, syscall.EACCES },
	})
	if m.Usable() || len(m.Errors) != 1 {
		t.Fatalf("dial error: %+v", m)
	}
}

func TestDialUDPLoopback(t *testing.T) {
	// The real socket path, against a silent local port.
	conn, err := DialUDP(context.Background(), netip.MustParseAddrPort("127.0.0.1:9"))
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	defer conn.Close()
	_, err = Query(context.Background(), conn, time.Now, 200*time.Millisecond)
	if !errors.Is(err, ErrRefused) && !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

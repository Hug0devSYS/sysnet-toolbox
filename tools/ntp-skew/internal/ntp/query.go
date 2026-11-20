package ntp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// Conn is the part of a connected UDP socket used by a query; tests
// replace it with an in-memory server.
type Conn interface {
	Write(b []byte) (int, error)
	Read(b []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// Dialer opens a connected datagram socket to an NTP server.
type Dialer func(ctx context.Context, addr netip.AddrPort) (Conn, error)

// DialUDP is the default Dialer: a connected UDP socket on a random
// ephemeral source port (RFC 9109), so the kernel drops datagrams from
// other sources.
func DialUDP(ctx context.Context, addr netip.AddrPort) (Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// Clock gives the local time. time.Now carries a monotonic reading, which
// is what makes the round-trip measurement immune to clock steps.
type Clock func() time.Time

// KoDError is returned when the server answers with a Kiss-o'-Death.
type KoDError struct{ Code string }

func (e *KoDError) Error() string { return fmt.Sprintf("kiss-o'-death %q", e.Code) }

// UnsyncError is returned when the server answers with stratum 0 but no
// access-control kiss code: it is running but not synchronised.
type UnsyncError struct{ Code string }

func (e *UnsyncError) Error() string {
	if e.Code == "" {
		return "server not synchronised (stratum 0)"
	}
	return fmt.Sprintf("server not synchronised (stratum 0, %s)", e.Code)
}

// ErrTimeout is returned when no valid answer arrived in time.
var ErrTimeout = errors.New("no answer (timeout)")

// ErrRefused is returned when the host answers with ICMP port unreachable.
var ErrRefused = errors.New("port unreachable (ICMP), no NTP service")

// BogusError reports an answer that failed the RFC 5905 packet sanity
// tests; the exchange is unusable.
type BogusError struct{ Reason string }

func (e *BogusError) Error() string { return "bogus answer: " + e.Reason }

// Sample is one client/server exchange.
type Sample struct {
	T1 time.Time `json:"t1"` // client transmit (local clock)
	T2 time.Time `json:"t2"` // server receive
	T3 time.Time `json:"t3"` // server transmit
	T4 time.Time `json:"t4"` // client receive (T1 + monotonic round trip)

	Offset time.Duration `json:"offset_ns"` // server clock minus local clock
	Delay  time.Duration `json:"delay_ns"`  // round trip minus server processing
	Packet Packet        `json:"-"`

	// Inconsistent is set when the server's processing time (T3-T2)
	// exceeds the round trip by more than InconsistencyTolerance: its
	// timestamps cannot both be right.
	Inconsistent bool `json:"inconsistent,omitempty"`

	// Ignored counts datagrams discarded while waiting (wrong origin
	// timestamp, wrong mode, short): replays, late duplicates or spoofing.
	Ignored int `json:"ignored,omitempty"`
}

// Query performs one exchange on conn. The request carries a random
// transmit timestamp and no other client information (RFC 9109 data
// minimisation); the answer must echo it in its origin field.
func Query(ctx context.Context, conn Conn, now Clock, timeout time.Duration) (Sample, error) {
	if now == nil {
		now = time.Now
	}
	var cookie [8]byte
	for binary.BigEndian.Uint64(cookie[:]) == 0 {
		if _, err := rand.Read(cookie[:]); err != nil {
			return Sample{}, fmt.Errorf("random cookie: %w", err)
		}
	}
	req := Packet{Version: 4, Mode: ModeClient, XmitTime: binary.BigEndian.Uint64(cookie[:])}

	deadline := now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	t1 := now()
	if _, err := conn.Write(req.Encode()); err != nil {
		return Sample{}, fmt.Errorf("send: %w", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return Sample{}, err
	}
	// Unblock the read when the context is cancelled (SIGINT).
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()

	buf := make([]byte, 1024)
	ignored := 0
	for {
		n, err := conn.Read(buf)
		t4 := now()
		if err != nil {
			if ctx.Err() != nil {
				return Sample{}, ctx.Err()
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return Sample{}, ErrTimeout
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return Sample{}, ErrTimeout
			}
			if errors.Is(err, syscall.ECONNREFUSED) {
				return Sample{}, ErrRefused
			}
			return Sample{}, fmt.Errorf("receive: %w", err)
		}
		resp, err := Decode(buf[:n])
		if err != nil || resp.Mode != ModeServer || resp.OrigTime != req.XmitTime {
			ignored++
			continue
		}
		s, err := sampleFrom(resp, t1, t4)
		s.Ignored = ignored
		return s, err
	}
}

func sampleFrom(resp Packet, t1, t4 time.Time) (Sample, error) {
	if resp.IsKoD() {
		switch code := resp.KissCode(); code {
		case "", "INIT", "STEP":
			// Stratum 0 without a kiss code (chrony) or with INIT/STEP
			// (ntpd): the server has no synchronised clock yet.
			return Sample{Packet: resp}, &UnsyncError{Code: code}
		default:
			return Sample{Packet: resp}, &KoDError{Code: code}
		}
	}
	if resp.Version < 1 || resp.Version > 4 {
		return Sample{Packet: resp}, &BogusError{Reason: fmt.Sprintf("version %d", resp.Version)}
	}
	if resp.XmitTime == 0 {
		return Sample{Packet: resp}, &BogusError{Reason: "server transmit timestamp is zero"}
	}
	if resp.RecvTime == 0 {
		return Sample{Packet: resp}, &BogusError{Reason: "server receive timestamp is zero"}
	}
	rtt := t4.Sub(t1) // monotonic
	if rtt < 0 {
		rtt = 0
	}
	w1 := t1.Round(0) // wall clock only
	s := Sample{T1: w1, T4: w1.Add(rtt), Packet: resp}
	s.T2 = NTPToTime(resp.RecvTime, w1)
	s.T3 = NTPToTime(resp.XmitTime, w1)
	proc := s.T3.Sub(s.T2)
	if proc < 0 {
		return s, &BogusError{Reason: "server transmit time precedes its receive time"}
	}
	s.Offset = (s.T2.Sub(s.T1) + s.T3.Sub(s.T4)) / 2
	s.Delay = rtt - proc
	if s.Delay < 0 {
		// Possible with a coarse server clock; RFC 5905 clamps to precision.
		if -s.Delay > InconsistencyTolerance+PrecisionDuration(resp.Precision) {
			s.Inconsistent = true
		}
		s.Delay = 0
	}
	return s, nil
}

// Physical constants of RFC 5905.
const (
	PHI     = 15e-6 // frequency tolerance (s/s)
	MinDisp = 0.01  // minimum dispersion increment (s)
	MaxDist = 1.5   // distance threshold for selection (s)
)

// InconsistencyTolerance is how much longer than the round trip the
// server's processing time may look before the sample is flagged.
const InconsistencyTolerance = time.Millisecond

// ClientPrecision is the assumed precision of the local timestamps
// (userland clock_gettime around a socket call).
const ClientPrecision = time.Microsecond

// Options control a multi-sample measurement of one server.
type Options struct {
	Samples  int           // exchanges (stops early on KoD or fatal errors)
	Interval time.Duration // spacing between exchanges
	Timeout  time.Duration // per exchange
	Dial     Dialer
	Now      Clock
	Sleep    func(ctx context.Context, d time.Duration) error
}

// Measurement summarises several exchanges with one server, after the
// RFC 5905 clock filter (minimum-delay sample).
type Measurement struct {
	Addr      netip.AddrPort `json:"-"`
	Samples   []Sample       `json:"-"`
	Sent      int            `json:"sent"`
	Received  int            `json:"received"`
	Ignored   int            `json:"ignored_datagrams,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
	KoD       string         `json:"kiss_code,omitempty"`
	Unsync    bool           `json:"unsynchronised,omitempty"`
	Best      *Sample        `json:"-"`
	Jitter    time.Duration  `json:"jitter_ns"`
	Disp      time.Duration  `json:"dispersion_ns"`
	RootDist  time.Duration  `json:"root_distance_ns"`
	LastError error          `json:"-"`
}

// Usable reports whether at least one valid sample was obtained.
func (m *Measurement) Usable() bool { return m.Best != nil }

// Measure queries addr opts.Samples times and applies the clock filter.
func Measure(ctx context.Context, addr netip.AddrPort, opts Options) *Measurement {
	if opts.Dial == nil {
		opts.Dial = DialUDP
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepCtx
	}
	if opts.Samples < 1 {
		opts.Samples = 1
	}
	m := &Measurement{Addr: addr}
	conn, err := opts.Dial(ctx, addr)
	if err != nil {
		m.LastError = err
		m.Errors = append(m.Errors, err.Error())
		return m
	}
	defer conn.Close()
	for i := 0; i < opts.Samples; i++ {
		if i > 0 && opts.Interval > 0 {
			if err := opts.Sleep(ctx, opts.Interval); err != nil {
				m.LastError = err
				break
			}
		}
		if ctx.Err() != nil {
			m.LastError = ctx.Err()
			break
		}
		m.Sent++
		s, err := Query(ctx, conn, opts.Now, opts.Timeout)
		m.Ignored += s.Ignored
		var kod *KoDError
		var unsync *UnsyncError
		switch {
		case err == nil:
			m.Received++
			m.Samples = append(m.Samples, s)
			continue
		case errors.As(err, &kod):
			m.Received++
			m.KoD = kod.Code
			m.LastError = err
			m.Errors = append(m.Errors, err.Error())
			// RFC 5905 7.4: stop sending after any kiss code.
			finish(m, opts.Now())
			return m
		case errors.As(err, &unsync):
			m.Received++
			m.Unsync = true
			m.LastError = err
			m.Errors = append(m.Errors, err.Error())
			finish(m, opts.Now())
			return m
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			m.LastError = err
			finish(m, opts.Now())
			return m
		default:
			var bogus *BogusError
			if errors.As(err, &bogus) {
				m.Received++
			}
			m.LastError = err
			m.Errors = append(m.Errors, err.Error())
			if !errors.Is(err, ErrTimeout) && bogus == nil {
				// ICMP unreachable, no route...: retrying is pointless.
				finish(m, opts.Now())
				return m
			}
		}
	}
	finish(m, opts.Now())
	return m
}

func finish(m *Measurement, now time.Time) {
	m.Errors = dedupe(m.Errors)
	if len(m.Samples) == 0 {
		return
	}
	best := 0
	for i, s := range m.Samples {
		if s.Delay < m.Samples[best].Delay {
			best = i
		}
	}
	b := m.Samples[best]
	m.Best = &m.Samples[best]
	// Jitter: RMS of the other samples' offsets relative to the best one.
	if n := len(m.Samples); n > 1 {
		var sum float64
		for i, s := range m.Samples {
			if i == best {
				continue
			}
			d := (s.Offset - b.Offset).Seconds()
			sum += d * d
		}
		m.Jitter = secs(math.Sqrt(sum / float64(n-1)))
	}
	// Dispersion: precisions plus frequency tolerance over the round trip
	// and over the time elapsed since the sample.
	age := now.Sub(b.T4)
	if age < 0 {
		age = 0
	}
	disp := PrecisionDuration(b.Packet.Precision) + ClientPrecision +
		secs(PHI*(b.T4.Sub(b.T1).Seconds()+age.Seconds()))
	m.Disp = disp
	rd := ShortToDuration(b.Packet.RootDelay)
	m.RootDist = secs(math.Max(MinDisp, (rd+b.Delay).Seconds())/2) +
		ShortToDuration(b.Packet.RootDispersion) + disp + m.Jitter
}

func secs(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := map[string]int{}
	var order []string
	for _, s := range in {
		if seen[s] == 0 {
			order = append(order, s)
		}
		seen[s]++
	}
	out := make([]string, 0, len(order))
	for _, s := range order {
		if c := seen[s]; c > 1 {
			out = append(out, fmt.Sprintf("%s (x%d)", s, c))
		} else {
			out = append(out, s)
		}
	}
	return out
}

package check

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/ntp"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/sources"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

type srv struct {
	name    string
	addr    string
	stratum uint8
	refid   string // dotted quad or ASCII
	offset  time.Duration
	dist    time.Duration
	leap    uint8
	refAge  time.Duration
	kod     string
	down    bool
}

func (s srv) input() Input {
	ap := netip.AddrPortFrom(netip.MustParseAddr(s.addr), 123)
	in := Input{Source: sources.Source{Spec: sources.Spec{Host: s.name, Port: 123}, Addr: ap}}
	m := &ntp.Measurement{Addr: ap, Sent: 4}
	in.M = m
	if s.down {
		m.Errors = []string{"no answer (timeout) (x4)"}
		return in
	}
	m.Received = 4
	if s.kod != "" {
		m.KoD = s.kod
		m.Errors = []string{"kiss-o'-death"}
		return in
	}
	p := ntp.Packet{Version: 4, Mode: 4, Stratum: s.stratum, Leap: s.leap, Precision: -20}
	if a, err := netip.ParseAddr(s.refid); err == nil {
		p.RefID = a.As4()
	} else {
		copy(p.RefID[:], s.refid)
	}
	t1 := now.Add(-time.Second)
	t3 := t1.Add(s.offset + 5*time.Millisecond)
	age := s.refAge
	if age == 0 {
		age = time.Minute
	}
	p.RefTime = ntp.TimeToNTP(t3.Add(-age))
	sample := ntp.Sample{T1: t1, T2: t3, T3: t3, T4: t1.Add(10 * time.Millisecond), Offset: s.offset, Delay: 10 * time.Millisecond, Packet: p}
	m.Samples = []ntp.Sample{sample}
	m.Best = &m.Samples[0]
	m.RootDist = s.dist
	if m.RootDist == 0 {
		m.RootDist = 10 * time.Millisecond
	}
	return in
}

func analyse(cfg Config, servers ...srv) *Report {
	var in []Input
	for _, s := range servers {
		in = append(in, s.input())
	}
	if cfg.Now.IsZero() {
		cfg.Now = now
	}
	return Analyse(in, nil, cfg)
}

func codes(r *Report) string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Severity.String()+":"+f.Code)
	}
	return strings.Join(out, " ")
}

func state(r *Report, name string) string {
	for _, s := range r.Servers {
		if s.Name == name {
			return s.State
		}
	}
	return "?"
}

var defaults = Config{WarnOffset: 100 * time.Millisecond, CritOffset: time.Second, MinSources: 1, MaxRefAge: 24 * time.Hour}

func TestHealthyEnsemble(t *testing.T) {
	r := analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", offset: 2 * time.Millisecond},
		srv{name: "b", addr: "192.0.2.2", stratum: 2, refid: "198.51.100.1", offset: 3 * time.Millisecond},
		srv{name: "c", addr: "192.0.2.3", stratum: 2, refid: "198.51.100.2", offset: 1 * time.Millisecond},
	)
	if r.Status != OK || len(r.Findings) != 0 {
		t.Fatalf("status %v findings %s", r.Status, codes(r))
	}
	if r.Selection.Truechimers != 3 || !r.Selection.Majority {
		t.Fatalf("selection %+v", r.Selection)
	}
	if off := *r.Selection.Offset; off < 0.001 || off > 0.003 {
		t.Fatalf("consensus %v", off)
	}
	if c := r.Servers[1].OffsetConsensus; c == nil || *c <= 0 {
		t.Fatal("offset vs consensus not set")
	}
}

func TestFalsetickerAndLocalOffset(t *testing.T) {
	r := analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", offset: 300 * time.Millisecond},
		srv{name: "b", addr: "192.0.2.2", stratum: 1, refid: "PPS", offset: 302 * time.Millisecond},
		srv{name: "c", addr: "192.0.2.3", stratum: 1, refid: "GNSS", offset: 299 * time.Millisecond},
		srv{name: "liar", addr: "192.0.2.4", stratum: 1, refid: "GPS", offset: 4 * time.Second},
	)
	if r.Status != Critical || state(r, "liar") != StateFalseticker || state(r, "a") != StateTruechimer {
		t.Fatalf("status %v %s", r.Status, codes(r))
	}
	if !strings.Contains(codes(r), "CRITICAL:falseticker") || !strings.Contains(codes(r), "WARNING:local-offset") {
		t.Fatalf("findings %s", codes(r))
	}
	// Local clock is behind: reported as negative (local minus consensus).
	for _, f := range r.Findings {
		if f.Code == "local-offset" && !strings.Contains(f.Message, "-300") {
			t.Fatalf("local offset message %q", f.Message)
		}
	}
	// Critical threshold.
	r = analyse(defaults, srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", offset: -2 * time.Second})
	if r.Status != Critical || !strings.Contains(codes(r), "CRITICAL:local-offset") {
		t.Fatalf("crit offset: %s", codes(r))
	}
}

func TestNoMajority(t *testing.T) {
	r := analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", offset: 0},
		srv{name: "b", addr: "192.0.2.2", stratum: 1, refid: "GPS", offset: time.Second},
	)
	if r.Status != Critical || !strings.Contains(codes(r), "no-majority") {
		t.Fatalf("%v %s", r.Status, codes(r))
	}
	if len(r.Notes) == 0 {
		t.Fatal("missing note about fewer than 3 sources")
	}
}

func TestExcludedSources(t *testing.T) {
	r := analyse(defaults,
		srv{name: "ok", addr: "192.0.2.1", stratum: 1, refid: "GPS"},
		srv{name: "unsync", addr: "192.0.2.2", stratum: 16, refid: "INIT", leap: 3},
		srv{name: "far", addr: "192.0.2.3", stratum: 3, refid: "198.51.100.9", dist: 3 * time.Second},
		srv{name: "down", addr: "192.0.2.4", down: true},
		srv{name: "rate", addr: "192.0.2.5", kod: "RATE"},
		srv{name: "deny", addr: "192.0.2.6", kod: "DENY"},
		srv{name: "stale", addr: "192.0.2.7", stratum: 2, refid: "198.51.100.1", refAge: 72 * time.Hour},
	)
	want := map[string]string{"unsync": StateUnsynchronised, "far": StateTooFar, "down": StateUnreachable, "rate": StateKoD, "deny": StateKoD, "ok": StateTruechimer, "stale": StateTruechimer}
	for n, st := range want {
		if got := state(r, n); got != st {
			t.Errorf("%s: state %s want %s", n, got, st)
		}
	}
	c := codes(r)
	for _, code := range []string{"unsynchronised", "too-far", "unreachable", "kod-rate", "kod-deny", "stale-reference"} {
		if !strings.Contains(c, "WARNING:"+code) {
			t.Errorf("missing %s in %s", code, c)
		}
	}
	if r.Status != Warning || r.Selection.Candidates != 2 {
		t.Fatalf("status %v candidates %d", r.Status, r.Selection.Candidates)
	}
}

func TestNoUsableSourceAndMinSources(t *testing.T) {
	r := Analyse(nil, []Unresolved{{Spec: sources.Spec{Host: "x.example", Port: 123}, Err: errors.New("no such host")}}, Config{Now: now, MinSources: 1})
	if r.Status != Unknown || state(r, "x.example") != StateUnresolved {
		t.Fatalf("%v %s", r.Status, codes(r))
	}
	cfg := defaults
	cfg.MinSources = 3
	r = analyse(cfg,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS"},
		srv{name: "b", addr: "192.0.2.2", stratum: 1, refid: "GPS"},
		srv{name: "c", addr: "192.0.2.3", down: true},
	)
	if r.Status != Critical || !strings.Contains(codes(r), "CRITICAL:min-sources") {
		t.Fatalf("%v %s", r.Status, codes(r))
	}
}

func TestTopology(t *testing.T) {
	// a and b synchronised to each other; c to a.
	r := analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 3, refid: "192.0.2.2"},
		srv{name: "b", addr: "192.0.2.2", stratum: 4, refid: "192.0.2.1"},
		srv{name: "c", addr: "192.0.2.3", stratum: 4, refid: "192.0.2.1"},
	)
	if !strings.Contains(codes(r), "WARNING:sync-loop") {
		t.Fatalf("loop not found: %s", codes(r))
	}
	if r.Servers[2].RefIDServer != "a" {
		t.Fatalf("refid match %q", r.Servers[2].RefIDServer)
	}
	// Common upstream.
	r = analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 2, refid: "198.51.100.1"},
		srv{name: "b", addr: "192.0.2.2", stratum: 2, refid: "198.51.100.1"},
		srv{name: "c", addr: "192.0.2.3", stratum: 2, refid: "198.51.100.1"},
	)
	if !strings.Contains(codes(r), "WARNING:common-upstream") {
		t.Fatalf("common upstream not found: %s", codes(r))
	}
	cfg := defaults
	cfg.AllowCommonUpstream = true
	r = analyse(cfg,
		srv{name: "a", addr: "192.0.2.1", stratum: 2, refid: "198.51.100.1"},
		srv{name: "b", addr: "192.0.2.2", stratum: 2, refid: "198.51.100.1"},
	)
	if r.Status != OK || len(r.Notes) < 2 {
		t.Fatalf("allow-common-upstream: %v %s %v", r.Status, codes(r), r.Notes)
	}
	// Server synchronised to this host (IPv6 refid hash).
	cfg = defaults
	local := netip.MustParseAddr("2001:db8::1")
	cfg.LocalAddrs = []netip.Addr{netip.MustParseAddr("127.0.0.1"), local}
	id := ntp.RefIDFor(local)
	r = analyse(cfg, srv{name: "a", addr: "192.0.2.1", stratum: 3, refid: netip.AddrFrom4(id).String()})
	if !strings.Contains(codes(r), "WARNING:sync-from-this-host") {
		t.Fatalf("sync from this host: %s", codes(r))
	}
	// Undisciplined local clock (chrony "local", ntpd LOCAL driver).
	r = analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 10, refid: "127.127.1.1"},
		srv{name: "b", addr: "192.0.2.2", stratum: 10, refid: "127.127.1.1"},
	)
	if c := codes(r); !strings.Contains(c, "local-reference") || strings.Contains(c, "common-upstream") {
		t.Fatalf("local reference: %s", c)
	}
}

func TestLeap(t *testing.T) {
	r := analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", leap: 1},
		srv{name: "b", addr: "192.0.2.2", stratum: 1, refid: "GPS"},
		srv{name: "c", addr: "192.0.2.3", stratum: 1, refid: "GPS"},
	)
	if !strings.Contains(codes(r), "WARNING:leap-disagreement") {
		t.Fatalf("leap: %s", codes(r))
	}
	r = analyse(defaults,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", leap: 1},
		srv{name: "b", addr: "192.0.2.2", stratum: 1, refid: "GPS", leap: 1},
	)
	if r.Status != OK || len(r.Notes) == 0 {
		t.Fatalf("agreed leap: %v %s", r.Status, codes(r))
	}
}

func TestSkewAndStratum(t *testing.T) {
	cfg := defaults
	cfg.MaxSkew = 5 * time.Millisecond
	cfg.MaxStratum = 3
	r := analyse(cfg,
		srv{name: "a", addr: "192.0.2.1", stratum: 1, refid: "GPS", offset: 0, dist: 50 * time.Millisecond},
		srv{name: "b", addr: "192.0.2.2", stratum: 1, refid: "GPS", offset: 1 * time.Millisecond, dist: 50 * time.Millisecond},
		srv{name: "c", addr: "192.0.2.3", stratum: 4, refid: "198.51.100.1", offset: 30 * time.Millisecond, dist: 50 * time.Millisecond},
	)
	c := codes(r)
	if !strings.Contains(c, "WARNING:skew") || !strings.Contains(c, "WARNING:stratum") || state(r, "c") != StateTruechimer {
		t.Fatalf("skew/stratum: %s", c)
	}
}

func TestWorseAndFormatting(t *testing.T) {
	if Worse(Warning, Unknown) != Unknown || Worse(Critical, Unknown) != Critical || Worse(OK, Warning) != Warning {
		t.Fatal("severity order")
	}
	for d, want := range map[time.Duration]string{
		1500 * time.Nanosecond:  "1.5us",
		2500 * time.Microsecond: "2.500ms",
		1500 * time.Millisecond: "1.500s",
		90 * time.Minute:        "1.5h",
		72 * time.Hour:          "3.0d",
	} {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%v) = %s want %s", d, got, want)
		}
	}
	if fmtSigned(-time.Millisecond) != "-1.000ms" || fmtSigned(0) != "+0.0us" {
		t.Fatal("signed format")
	}
}

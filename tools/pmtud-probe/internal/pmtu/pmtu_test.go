package pmtu

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/probe"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/simpath"
)

var (
	dst4 = netip.MustParseAddr("192.0.2.10")
	dst6 = netip.MustParseAddr("2001:db8::10")
	r1   = netip.MustParseAddr("198.51.100.1")
	r2   = netip.MustParseAddr("198.51.100.2")
	r6   = netip.MustParseAddr("2001:db8::1")
)

func route(mtu int) probe.Route {
	return probe.Route{Local: netip.MustParseAddr("192.0.2.1"), Interface: "eth0", IfMTU: mtu, RouteMTU: mtu}
}

func run(t *testing.T, p *simpath.Path, rt probe.Route, opt Options) *Report {
	t.Helper()
	if opt.Timeout == 0 {
		opt.Timeout = time.Second
	}
	if opt.Retries == 0 {
		opt.Retries = 2
	}
	return Run(context.Background(), "target.example", p, rt, opt)
}

func has(rep *Report, code string, sev Severity) bool {
	for _, f := range rep.Findings {
		if f.Code == code && f.Severity == sev {
			return true
		}
	}
	return false
}

func mustFinding(t *testing.T, rep *Report, code string, sev Severity) {
	t.Helper()
	if !has(rep, code, sev) {
		t.Fatalf("missing finding %s/%s in %+v", code, sev, rep.Findings)
	}
}

func TestCleanPath(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1500, SendPTB: true}}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1500 || rep.PMTUD != PMTUDNotNeeded || rep.Status != SevOK || len(p.Sizes) != 2 {
		t.Fatalf("got %+v (probes %v)", rep, p.Sizes)
	}
	if rep.MaxUDP != 1472 || rep.TCPMSS != 1460 {
		t.Fatalf("derived sizes %d %d", rep.MaxUDP, rep.TCPMSS)
	}
	mustFinding(t, rep, "no-constriction", SevOK)
}

func TestWorkingPMTUDConvergesFast(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{
		{Addr: r1, MTU: 1500, SendPTB: true},
		{Addr: r2, MTU: 1400, SendPTB: true},
	}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1400 || rep.PMTUD != PMTUDWorking || rep.Status != SevInfo {
		t.Fatalf("got %+v", rep)
	}
	// control, 1500 (PTB 1400), 1400 (ok), 1401 (PTB): the search jumps to
	// the advertised MTU and confirms it is exact.
	if len(p.Sizes) != 4 || p.Sizes[2] != 1400 || p.Sizes[3] != 1401 {
		t.Fatalf("probe sequence %v", p.Sizes)
	}
	if len(rep.PTB) != 1 || rep.PTB[0].From != r2.String() || rep.PTB[0].MTU != 1400 {
		t.Fatalf("ptb %+v", rep.PTB)
	}
	mustFinding(t, rep, "pmtud-working", SevInfo)
}

func TestBlackHole(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1420}}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1420 || rep.PMTUD != PMTUDBlackHole || rep.Status != SevCritical {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "pmtud-black-hole", SevCritical)
	if !strings.Contains(rep.Findings[0].Message, "clamp the TCP MSS to 1380") {
		t.Fatalf("remediation missing: %s", rep.Findings[0].Message)
	}
}

func TestBlackHoleBehindSignallingHop(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{
		{Addr: r1, MTU: 1450, SendPTB: true},
		{Addr: r2, MTU: 1400},
	}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1400 || rep.PMTUD != PMTUDBlackHole {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "pmtud-black-hole", SevCritical)
	if !strings.Contains(rep.Findings[len(rep.Findings)-1].Message, "further along the path") {
		t.Fatalf("missing earlier-hop note: %+v", rep.Findings)
	}
}

func TestPTBWithoutMTU(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1492, SendPTB: true, Advertise: -1}}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1492 || rep.PMTUD != PMTUDWorking {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "ptb-no-mtu", SevWarning)
}

func TestBogusPTB(t *testing.T) {
	// The router claims MTU 1500 for a 1500-byte packet it refuses, and
	// later 1500 again: the value is useless and must be reported.
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1300, SendPTB: true, Advertise: 1500}}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1300 {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "ptb-bogus", SevWarning)
	mustFinding(t, rep, "ptb-inconsistent", SevWarning)
}

func TestRejectedOversize(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1400, Reject: "ICMP communication administratively prohibited"}}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1400 || rep.PMTUD != PMTUDFiltered {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "oversize-rejected", SevWarning)
}

func TestLocalRouteMTU(t *testing.T) {
	p := &simpath.Path{Dst: dst4, LocalMTU: 1400}
	rt := route(1500)
	rt.RouteMTU = 1400
	rep := run(t, p, rt, Options{})
	if rep.PathMTU != 1400 || rep.PMTUD != PMTUDLocal || len(p.Sizes) != 4 {
		t.Fatalf("got %+v %v", rep, p.Sizes)
	}
	mustFinding(t, rep, "local-route-mtu", SevInfo)
	mustFinding(t, rep, "kernel-pmtu-cache", SevInfo)
}

func TestTargetSilent(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Silent: true}
	rep := run(t, p, route(1500), Options{Retries: 1})
	if rep.PathMTU != 0 || rep.Status != SevUnknown || len(p.Sizes) != 2 {
		t.Fatalf("got %+v %v", rep, p.Sizes)
	}
	mustFinding(t, rep, "unreachable", SevUnknown)
	if !strings.Contains(rep.Findings[0].Message, "--method udp") {
		t.Fatal("missing hint")
	}
}

func TestPathLost(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1400}}, StopAfter: 1}
	rep := run(t, p, route(1500), Options{})
	if rep.Status != SevUnknown || rep.PathMTU != 0 {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "path-lost", SevUnknown)
}

func TestNoUpperBound(t *testing.T) {
	rep := run(t, &simpath.Path{Dst: dst4}, probe.Route{}, Options{})
	mustFinding(t, rep, "no-upper-bound", SevUnknown)
	rep = run(t, &simpath.Path{Dst: dst4}, route(1500), Options{Max: 20})
	mustFinding(t, rep, "bad-upper-bound", SevUnknown)
}

func TestMaxOverride(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 9000, SendPTB: true}}}
	rep := run(t, p, route(9000), Options{Max: 1500})
	if rep.PathMTU != 1500 || rep.UpperBound != 1500 || rep.PMTUD != PMTUDNotNeeded {
		t.Fatalf("got %+v", rep)
	}
}

func TestIPv6(t *testing.T) {
	p := &simpath.Path{Dst: dst6, Hops: []*simpath.Hop{{Addr: r6, MTU: 1280, SendPTB: true}}}
	rep := run(t, p, route(1500), Options{})
	if rep.Family != "ipv6" || rep.PathMTU != 1280 || rep.MaxUDP != 1232 || rep.TCPMSS != 1220 || rep.Status != SevInfo {
		t.Fatalf("got %+v", rep)
	}
	if !strings.Contains(rep.Findings[0].Message, "ICMPv6 Packet Too Big") {
		t.Fatal(rep.Findings[0].Message)
	}
	p = &simpath.Path{Dst: dst6, Hops: []*simpath.Hop{{Addr: r6, MTU: 1200}}}
	rep = run(t, p, route(1500), Options{})
	if rep.PathMTU != 1200 {
		t.Fatalf("got %+v", rep)
	}
	mustFinding(t, rep, "ipv6-below-minimum", SevCritical)
	mustFinding(t, rep, "pmtud-black-hole", SevCritical)
}

func TestExpectMTU(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1400, SendPTB: true}}}
	rep := run(t, p, route(1500), Options{ExpectMTU: 1500})
	mustFinding(t, rep, "unexpected-mtu", SevWarning)
	if rep.Status != SevWarning {
		t.Fatal(rep.Status)
	}
	p = &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1400, SendPTB: true}}}
	if rep = run(t, p, route(1500), Options{ExpectMTU: 1400}); has(rep, "unexpected-mtu", SevWarning) {
		t.Fatal("false unexpected-mtu")
	}
}

func TestLossDoesNotFakeABlackHole(t *testing.T) {
	// Every other probe is lost, wherever it goes.
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1400, SendPTB: true}},
		Drop: func(n, _ int) bool { return n%2 == 0 }}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1400 || rep.PMTUD != PMTUDWorking {
		t.Fatalf("got %+v", rep)
	}
	p = &simpath.Path{Dst: dst4, Drop: func(n, _ int) bool { return n%3 == 0 }}
	if rep = run(t, p, route(1500), Options{}); rep.PathMTU != 1500 {
		t.Fatalf("got %+v", rep)
	}
}

func TestRateLimitedTarget(t *testing.T) {
	// Linux-like ICMP rate limit on the target (6 burst, 1/s) in UDP mode:
	// a size that fits must never be classified as dropped.
	for _, mtu := range []int{1500, 1472, 1400, 1337, 1280, 900} {
		p := &simpath.Path{Dst: dst4, Meth: probe.MethodUDP, Burst: 6, Refill: time.Second,
			Hops: []*simpath.Hop{{Addr: r1, MTU: mtu}}}
		rep := run(t, p, route(1500), Options{Retries: 1})
		if rep.PathMTU != mtu {
			t.Fatalf("mtu %d: got %+v", mtu, rep)
		}
	}
}

func TestRateLimitedPTB(t *testing.T) {
	p := &simpath.Path{Dst: dst4, Hops: []*simpath.Hop{{Addr: r1, MTU: 1400, SendPTB: true, PTBEvery: 3}}}
	rep := run(t, p, route(1500), Options{})
	if rep.PathMTU != 1400 || rep.PMTUD != PMTUDWorking {
		t.Fatalf("got %+v", rep)
	}
}

func TestExhaustive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 400; i++ {
		upper := []int{1500, 9000, 1500, 4470}[rng.Intn(4)]
		var hops []*simpath.Hop
		want := upper
		for h := rng.Intn(4); h >= 0; h-- {
			mtu := 576 + rng.Intn(upper-575)
			hop := &simpath.Hop{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(h + 1)}), MTU: mtu, SendPTB: rng.Intn(2) == 0}
			if rng.Intn(5) == 0 {
				hop.PTBEvery = 2
			}
			hops = append(hops, hop)
			want = min(want, mtu)
		}
		p := &simpath.Path{Dst: dst4, Hops: hops}
		if rng.Intn(3) == 0 {
			p.Drop = func(n, _ int) bool { return n%4 == 0 }
		}
		rep := run(t, p, route(upper), Options{})
		if rep.PathMTU != want {
			t.Fatalf("case %d: upper %d hops %+v: got %d want %d", i, upper, hops, rep.PathMTU, want)
		}
		// Verdict consistency: the first hop that constrains to want decides.
		var first *simpath.Hop
		for _, h := range hops {
			if h.MTU == want && want < upper {
				first = h
				break
			}
		}
		switch {
		case first == nil:
			if rep.PMTUD != PMTUDNotNeeded {
				t.Fatalf("case %d: %s", i, rep.PMTUD)
			}
		case first.SendPTB && rep.PMTUD != PMTUDWorking:
			t.Fatalf("case %d: signalling hop reported as %s (%+v)", i, rep.PMTUD, rep.Findings)
		case !first.SendPTB && rep.PMTUD != PMTUDBlackHole:
			// a silent hop with an equal-MTU signalling hop before it is still signalled
			signalled := false
			for _, h := range hops {
				if h.MTU == want && h.SendPTB {
					signalled = true
				}
			}
			if !signalled {
				t.Fatalf("case %d: silent hop reported as %s", i, rep.PMTUD)
			}
		}
		if len(p.Sizes) > 60 {
			t.Fatalf("case %d: %d probes", i, len(p.Sizes))
		}
	}
}

func TestCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := Run(ctx, "x", &simpath.Path{Dst: dst4}, route(1500), Options{})
	mustFinding(t, rep, "interrupted", SevUnknown)
}

type fakeTCP struct {
	info  probe.TCPInfo
	err   error
	calls int
	seen  int // probes sent before the TCP check
	path  *simpath.Path
}

func (f *fakeTCP) fn(_ context.Context, _ netip.Addr, _ int, _ time.Duration) (probe.TCPInfo, error) {
	f.calls++
	f.seen = len(f.path.Sizes)
	return f.info, f.err
}

func TestMSSCheck(t *testing.T) {
	cases := []struct {
		name    string
		hops    []*simpath.Hop
		info    probe.TCPInfo
		err     error
		verdict string
		code    string
		sev     Severity
		peer    int
		lower   bool
	}{
		{"black hole, not clamped", []*simpath.Hop{{Addr: r1, MTU: 1400}},
			probe.TCPInfo{SndMSS: 1448, Options: probe.TCPIOptTimestamps, PMTU: 1500}, nil, MSSTooLarge, "mss-not-clamped", SevCritical, 1460, true},
		{"working pmtud, not clamped", []*simpath.Hop{{Addr: r1, MTU: 1400, SendPTB: true}},
			probe.TCPInfo{SndMSS: 1460, PMTU: 1500}, nil, MSSTooLarge, "mss-not-clamped", SevWarning, 1460, true},
		{"black hole, clamped", []*simpath.Hop{{Addr: r1, MTU: 1400}},
			probe.TCPInfo{SndMSS: 1348, Options: probe.TCPIOptTimestamps, PMTU: 1500}, nil, MSSFits, "mss-fits", SevOK, 1360, false},
		{"cached pmtu hides peer", []*simpath.Hop{{Addr: r1, MTU: 1400, SendPTB: true}},
			probe.TCPInfo{SndMSS: 1348, Options: probe.TCPIOptTimestamps, PMTU: 1400}, nil, MSSInconclusive, "mss-inconclusive", SevInfo, 1360, true},
		{"clean path", nil,
			probe.TCPInfo{SndMSS: 1448, Options: probe.TCPIOptTimestamps, PMTU: 1500}, nil, MSSFits, "mss-fits", SevOK, 1460, true},
		{"connect error", nil, probe.TCPInfo{}, errors.New("connection refused"), "", "tcp-connect", SevWarning, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &simpath.Path{Dst: dst4, Hops: c.hops}
			f := &fakeTCP{info: c.info, err: c.err, path: p}
			rep := run(t, p, route(1500), Options{TCPPort: 443, TCP: f.fn})
			if f.calls != 1 || f.seen != 0 {
				t.Fatalf("TCP check must run once, before probing (calls %d, after %d probes)", f.calls, f.seen)
			}
			mustFinding(t, rep, c.code, c.sev)
			if rep.TCP.Verdict != c.verdict || rep.TCP.PeerMSS != c.peer || rep.TCP.PeerMSSMin != c.lower {
				t.Fatalf("tcp %+v", rep.TCP)
			}
		})
	}
}

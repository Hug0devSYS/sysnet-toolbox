// Package pmtu discovers the path MTU towards a target with a robust
// bisection over single probes, tells PMTUD that works (routers answer
// "fragmentation needed" / "packet too big") from PMTUD black holes
// (oversized packets vanish silently), and checks whether the TCP MSS seen
// from the target fits the discovered path (MSS clamping).
package pmtu

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/probe"
)

// Severity of a finding. The order is ok < info < warning < critical <
// unknown for the purpose of computing a report's status.
type Severity string

// Severities.
const (
	SevOK       Severity = "ok"
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
	SevUnknown  Severity = "unknown"
)

// Rank orders severities.
func (s Severity) Rank() int {
	switch s {
	case SevInfo:
		return 1
	case SevWarning:
		return 2
	case SevCritical:
		return 3
	case SevUnknown:
		return 4
	}
	return 0
}

// PMTUD states.
const (
	PMTUDNotNeeded = "not-needed" // the full local MTU reaches the target
	PMTUDWorking   = "working"    // a router signals the constriction with ICMP
	PMTUDBlackHole = "black-hole" // oversized packets are dropped silently
	PMTUDFiltered  = "filtered"   // oversized packets are rejected with another ICMP error
	PMTUDLocal     = "local"      // the limit is the local route MTU
	PMTUDUnknown   = "unknown"
)

// Finding is one diagnostic statement.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// ProbeLog records one probe for the report.
type ProbeLog struct {
	Size    int           `json:"size"`
	Outcome probe.Outcome `json:"outcome"`
	MTU     int           `json:"mtu,omitempty"`
	From    string        `json:"from,omitempty"`
	RTTms   float64       `json:"rtt_ms"`
	Detail  string        `json:"detail"`
}

// PTB is one distinct "fragmentation needed" / "packet too big" message.
type PTB struct {
	From      string `json:"from"`
	MTU       int    `json:"mtu"`
	ProbeSize int    `json:"probe_size"`
}

// TCPCheck is the result of the MSS check.
type TCPCheck struct {
	Port        int    `json:"port"`
	Error       string `json:"error,omitempty"`
	SndMSS      int    `json:"snd_mss,omitempty"`      // kernel sending MSS (options excluded)
	OptionBytes int    `json:"option_bytes,omitempty"` // per-segment TCP option overhead
	PeerMSS     int    `json:"peer_mss,omitempty"`     // MSS advertised by the target as received here
	PeerMSSMin  bool   `json:"peer_mss_lower_bound"`   // true: PeerMSS is only a lower bound
	KernelPMTU  int    `json:"kernel_pmtu,omitempty"`  // tcpi_pmtu at connect time
	SegmentSize int    `json:"segment_size,omitempty"` // largest IP packet this side will send
	Verdict     string `json:"verdict,omitempty"`      // fits, too-large, inconclusive
	VerdictText string `json:"verdict_text,omitempty"` // human explanation
}

// Report is the outcome of one target.
type Report struct {
	Target     string      `json:"target"`
	Address    string      `json:"address"`
	Family     string      `json:"family"`
	Method     string      `json:"method"`
	Route      probe.Route `json:"route"`
	UpperBound int         `json:"upper_bound"`
	PathMTU    int         `json:"path_mtu"` // 0 when unknown
	MaxUDP     int         `json:"max_udp_payload,omitempty"`
	TCPMSS     int         `json:"tcp_mss_for_path,omitempty"`
	PMTUD      string      `json:"pmtud"`
	PTB        []PTB       `json:"ptb,omitempty"`
	TCP        *TCPCheck   `json:"tcp,omitempty"`
	Findings   []Finding   `json:"findings"`
	Status     Severity    `json:"status"`
	Probes     []ProbeLog  `json:"probes"`
	DurationMs int64       `json:"duration_ms"`
}

// Options control a run.
type Options struct {
	Max       int           // upper bound; 0 = outgoing interface MTU
	Timeout   time.Duration // per probe
	Retries   int           // extra attempts after a timeout
	ExpectMTU int           // warn when the path MTU differs
	TCPPort   int           // run the MSS check against this port (0 = off)
	Logf      func(format string, a ...any)
	// TCP opens a TCP connection and returns TCP_INFO (replaced in tests).
	TCP func(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (probe.TCPInfo, error)
	Now func() time.Time
}

// MaxIPPacket is the largest IP packet (IPv4 total length / IPv6 payload
// without jumbograms); the kernel caps IP_MTU at this value.
const MaxIPPacket = 65535

// MinIPv6MTU is the IPv6 minimum link MTU (RFC 8200).
const MinIPv6MTU = 1280

// errPathLost aborts a search when even the smallest probe stops working.
var errPathLost = errors.New("path lost")

type search struct {
	p       probe.Prober
	opt     Options
	rep     *Report
	ctrl    int
	failure map[int]probe.Result
	cand    int
}

// Run measures the path MTU to the prober's target. target is the name as
// given by the user; route describes the local side (see probe.LookupRoute).
func Run(ctx context.Context, target string, p probe.Prober, route probe.Route, opt Options) *Report {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	start := now()
	addr := p.Target()
	rep := &Report{
		Target:  target,
		Address: addr.String(),
		Family:  "ipv4",
		Method:  string(p.Method()),
		Route:   route,
		PMTUD:   PMTUDUnknown,
		Probes:  []ProbeLog{},
	}
	if probe.IPHeader(addr) == probe.IPv6Header {
		rep.Family = "ipv6"
	}
	defer func() {
		rep.DurationMs = now().Sub(start).Milliseconds()
		rep.Status = SevOK
		for _, f := range rep.Findings {
			if f.Severity.Rank() > rep.Status.Rank() {
				rep.Status = f.Severity
			}
		}
	}()
	if opt.Timeout <= 0 {
		opt.Timeout = time.Second
	}
	if opt.Retries < 0 {
		opt.Retries = 0
	}

	upper := opt.Max
	if upper == 0 {
		upper = route.IfMTU
	}
	if upper == 0 {
		upper = route.RouteMTU
	}
	if upper == 0 {
		rep.add("no-upper-bound", SevUnknown, "cannot determine the outgoing interface MTU; pass --max")
		return rep
	}
	upper = min(upper, MaxIPPacket)
	s := &search{p: p, opt: opt, rep: rep, ctrl: probe.MinProbe(addr), failure: map[int]probe.Result{}}
	if upper < s.ctrl {
		rep.add("bad-upper-bound", SevUnknown, fmt.Sprintf("upper bound %d is below the smallest probe (%d bytes)", upper, s.ctrl))
		return rep
	}
	rep.UpperBound = upper
	if route.IfMTU > 0 && route.RouteMTU > 0 && route.RouteMTU < min(route.IfMTU, MaxIPPacket) {
		rep.add("kernel-pmtu-cache", SevInfo, fmt.Sprintf(
			"regular traffic to %s uses MTU %d, not the %d of interface %s: a route MTU or a PMTU learnt from an earlier ICMP message (probes bypass it; see ip route get)",
			addr, route.RouteMTU, route.IfMTU, route.Interface))
	}

	// The MSS check runs first, before our own probes make the kernel cache
	// the path MTU (which would cap the MSS and hide the peer's value).
	if opt.TCPPort > 0 {
		rep.TCP = s.tcpCheck(ctx)
	}

	pmtu, err := s.bisect(ctx, upper)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			rep.add("interrupted", SevUnknown, "probing interrupted: "+ctx.Err().Error())
		case errors.Is(err, errPathLost):
			rep.add("path-lost", SevUnknown, fmt.Sprintf(
				"%s stopped answering even minimal probes during the search (loss or ICMP rate limiting); retry with a larger --timeout or --retries", addr))
		default:
			rep.add("probe-error", SevUnknown, err.Error())
		}
		return rep
	}
	if pmtu == 0 {
		return rep // reachability finding already recorded
	}
	rep.PathMTU = pmtu
	rep.MaxUDP = pmtu - probe.Overhead(addr)
	rep.TCPMSS = pmtu - probe.IPHeader(addr) - probe.TCPHeader
	s.verdict(upper)
	if rep.TCP != nil && rep.TCP.Error == "" {
		s.tcpVerdict(upper)
	}
	return rep
}

func (r *Report) add(code string, sev Severity, msg string) {
	r.Findings = append(r.Findings, Finding{Code: code, Severity: sev, Message: msg})
}

func (s *search) logf(format string, a ...any) {
	if s.opt.Logf != nil {
		s.opt.Logf(format, a...)
	}
}

// attempt sends one probe and records it.
func (s *search) attempt(ctx context.Context, size int) (probe.Result, error) {
	r, err := s.p.Probe(ctx, size, s.opt.Timeout)
	if err != nil {
		return r, err
	}
	l := ProbeLog{Size: size, Outcome: r.Outcome, MTU: r.MTU, RTTms: float64(r.RTT.Microseconds()) / 1000, Detail: r.Detail}
	if r.From.IsValid() {
		l.From = r.From.String()
	}
	s.rep.Probes = append(s.rep.Probes, l)
	s.logf("%s: probe %5d bytes -> %-13s %s", s.rep.Target, size, r.Outcome, r.Detail)
	return r, nil
}

// test probes size until something other than a timeout comes back, at
// most 1+Retries times.
func (s *search) test(ctx context.Context, size int) (probe.Result, error) {
	var r probe.Result
	var err error
	for i := 0; i <= s.opt.Retries; i++ {
		if r, err = s.attempt(ctx, size); err != nil || r.Outcome != probe.Timeout {
			return r, err
		}
	}
	return r, nil
}

// classify probes size; a timeout is only accepted as a silent drop after
// a minimal control probe proves the target still answers and one more
// probe of the same size (sent after the control, so after any ICMP rate
// limiter had time to refill) stays unanswered.
func (s *search) classify(ctx context.Context, size int) (probe.Result, error) {
	r, err := s.test(ctx, size)
	if err != nil || r.Outcome != probe.Timeout || size == s.ctrl {
		return r, err
	}
	c, err := s.test(ctx, s.ctrl)
	if err != nil {
		return r, err
	}
	if c.Outcome != probe.Reply {
		return r, errPathLost
	}
	return s.attempt(ctx, size)
}

// bisect returns the largest size in [ctrl, upper] that reaches the target,
// or 0 when not even the control probe does.
func (s *search) bisect(ctx context.Context, upper int) (int, error) {
	addr := s.p.Target()
	r, err := s.test(ctx, s.ctrl)
	if err != nil {
		return 0, err
	}
	if r.Outcome != probe.Reply {
		hint := "use --method udp"
		if s.p.Method() == probe.MethodUDP {
			hint = "use --method icmp, or --port to target a port the firewall lets through"
		}
		msg := fmt.Sprintf("%s does not answer minimal %s probes (%s); cannot measure the path MTU (%s)", addr, s.p.Method(), r.Detail, hint)
		if r.Outcome == probe.TooBig || r.Outcome == probe.LocalTooBig {
			msg = fmt.Sprintf("even a %d-byte probe is refused (%s)", s.ctrl, r.Detail)
		}
		s.rep.add("unreachable", SevUnknown, msg)
		return 0, nil
	}
	lo, hi := s.ctrl, upper+1 // lo reaches the target, hi does not (or is out of range)
	if upper > lo {
		r, err := s.classify(ctx, upper)
		if err != nil {
			return 0, err
		}
		if r.Outcome == probe.Reply {
			return upper, nil
		}
		s.fail(upper, r, lo)
		hi = upper
	}
	for hi-lo > 1 {
		size := (lo + hi) / 2
		fromCand := s.cand > lo && s.cand < hi
		if fromCand {
			size = s.cand
		}
		s.cand = 0
		r, err := s.classify(ctx, size)
		if err != nil {
			return 0, err
		}
		if r.Outcome == probe.Reply {
			lo = size
			if fromCand {
				s.cand = size + 1 // confirm the advertised MTU is the exact limit
			}
			continue
		}
		s.fail(size, r, lo)
		hi = size
	}
	return lo, nil
}

// fail records a failed size and derives the next candidate from an
// advertised MTU, which lets a working PMTUD converge in two probes.
func (s *search) fail(size int, r probe.Result, lo int) {
	s.failure[size] = r
	if r.Outcome == probe.TooBig {
		ptb := PTB{From: r.From.String(), MTU: r.MTU, ProbeSize: size}
		dup := false
		for _, p := range s.rep.PTB {
			if p.From == ptb.From && p.MTU == ptb.MTU {
				dup = true
			}
		}
		if !dup {
			s.rep.PTB = append(s.rep.PTB, ptb)
		}
	}
	if (r.Outcome == probe.TooBig || r.Outcome == probe.LocalTooBig) && r.MTU > lo && r.MTU < size {
		s.cand = r.MTU
	}
}

func (s *search) verdict(upper int) {
	rep, addr := s.rep, s.p.Target()
	pmtu := rep.PathMTU
	if pmtu == upper {
		rep.PMTUD = PMTUDNotNeeded
		rep.add("no-constriction", SevOK, fmt.Sprintf("%d-byte packets reach %s unfragmented (the local upper bound)", upper, addr))
	} else {
		var signalled *PTB
		for i := range rep.PTB {
			if rep.PTB[i].MTU == pmtu {
				signalled = &rep.PTB[i]
			}
		}
		edge := s.failure[pmtu+1]
		switch {
		case signalled != nil:
			rep.PMTUD = PMTUDWorking
			rep.add("pmtud-working", SevInfo, fmt.Sprintf(
				"path MTU %d: %s reports the constriction with ICMP (%s, MTU %d), so PMTUD works",
				pmtu, signalled.From, ptbName(addr), pmtu))
		case edge.Outcome == probe.TooBig:
			rep.PMTUD = PMTUDWorking
			if edge.MTU == 0 {
				rep.add("ptb-no-mtu", SevWarning, fmt.Sprintf(
					"path MTU %d: %s sends ICMP fragmentation needed without the next-hop MTU (pre-RFC 1191); hosts must guess the MTU from plateau tables",
					pmtu, edge.From))
			} else {
				rep.add("ptb-inconsistent", SevWarning, fmt.Sprintf(
					"path MTU %d but %s advertises MTU %d: the advertised value does not match what the path carries",
					pmtu, edge.From, edge.MTU))
			}
		case edge.Outcome == probe.LocalTooBig:
			rep.PMTUD = PMTUDLocal
			rep.add("local-route-mtu", SevInfo, fmt.Sprintf(
				"the limit (%d bytes) is local: the outgoing interface or route refuses larger packets (upper bound %d)", pmtu, upper))
		case edge.Outcome == probe.Unreachable:
			rep.PMTUD = PMTUDFiltered
			rep.add("oversize-rejected", SevWarning, fmt.Sprintf(
				"packets larger than %d bytes are rejected with %q instead of %s: PMTUD cannot work, senders only see errors",
				pmtu, edge.Detail, ptbName(addr)))
		default:
			rep.PMTUD = PMTUDBlackHole
			msg := fmt.Sprintf(
				"PMTUD black hole: packets larger than %d bytes towards %s are dropped silently, without %s. "+
					"TCP sessions that rely on PMTUD will hang after the handshake. Allow %s through the firewalls on the path "+
					"(never filter it) or clamp the TCP MSS to %d on the tunnel/edge router",
				pmtu, addr, ptbName(addr), ptbType(addr), pmtu-probe.IPHeader(addr)-probe.TCPHeader)
			if len(rep.PTB) > 0 {
				msg += fmt.Sprintf(" (an earlier hop, %s, did signal MTU %d: the black hole is further along the path)", rep.PTB[0].From, rep.PTB[0].MTU)
			}
			rep.add("pmtud-black-hole", SevCritical, msg)
		}
	}
	for _, p := range rep.PTB {
		if p.MTU >= p.ProbeSize {
			rep.add("ptb-bogus", SevWarning, fmt.Sprintf(
				"%s answered a %d-byte probe with %s advertising MTU %d (not smaller than the packet): broken or spoofed ICMP",
				p.From, p.ProbeSize, ptbName(addr), p.MTU))
		}
	}
	if rep.Family == "ipv6" && pmtu < MinIPv6MTU {
		rep.add("ipv6-below-minimum", SevCritical, fmt.Sprintf(
			"IPv6 path MTU %d is below the 1280-byte minimum every IPv6 link must support (RFC 8200)", pmtu))
	}
	if s.opt.ExpectMTU > 0 && pmtu != s.opt.ExpectMTU {
		rep.add("unexpected-mtu", SevWarning, fmt.Sprintf("path MTU %d differs from the expected %d", pmtu, s.opt.ExpectMTU))
	}
}

func ptbName(a netip.Addr) string {
	if probe.IPHeader(a) == probe.IPv6Header {
		return "ICMPv6 Packet Too Big"
	}
	return "ICMP Fragmentation Needed"
}

func ptbType(a netip.Addr) string {
	if probe.IPHeader(a) == probe.IPv6Header {
		return "ICMPv6 type 2"
	}
	return "ICMP type 3 code 4"
}

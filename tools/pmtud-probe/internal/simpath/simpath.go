// Package simpath simulates a network path for tests: a chain of routers
// with their own link MTUs and ICMP behaviour, packet loss, and ICMP rate
// limiting on a virtual clock. It implements probe.Prober.
package simpath

import (
	"context"
	"net/netip"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/probe"
)

// Hop is one router on the path.
type Hop struct {
	Addr netip.Addr
	MTU  int // MTU of the link this router forwards onto
	// SendPTB: the router answers oversized packets with ICMP
	// fragmentation needed / packet too big. Otherwise it drops silently.
	SendPTB bool
	// Advertise overrides the MTU placed in the ICMP message (-1 sends 0,
	// i.e. a pre-RFC 1191 router; 0 means "the real MTU").
	Advertise int
	// PTBEvery limits ICMP to one message per N oversized packets.
	PTBEvery int
	// Reject answers oversized packets with this ICMP error instead.
	Reject string

	oversize int
}

// Path is a simulated path to Dst.
type Path struct {
	Dst      netip.Addr
	Meth     probe.Method
	LocalMTU int // route/interface MTU enforced by the local stack
	Hops     []*Hop
	// Silent: the target never answers.
	Silent bool
	// Drop decides whether the n-th probe (1-based) is lost.
	Drop func(n, size int) bool
	// StopAfter: the target stops answering after this many probes (0 = never).
	StopAfter int
	// Rate limiting of the target's answers: Burst tokens, one more per
	// Refill of virtual time (0 = unlimited). Typical Linux: 6 and 1s.
	Burst  int
	Refill time.Duration

	// Sizes lists every probe size in order.
	Sizes []int
	// Clock is the virtual time consumed so far.
	Clock time.Duration

	tokens   float64
	lastFill time.Duration
	started  bool
}

var _ probe.Prober = (*Path)(nil)

// Overhead implements probe.Prober.
func (p *Path) Overhead() int { return probe.Overhead(p.Dst) }

// Method implements probe.Prober.
func (p *Path) Method() probe.Method {
	if p.Meth == "" {
		return probe.MethodICMP
	}
	return p.Meth
}

// Target implements probe.Prober.
func (p *Path) Target() netip.Addr { return p.Dst }

const rtt = 2 * time.Millisecond

// Probe implements probe.Prober.
func (p *Path) Probe(ctx context.Context, size int, timeout time.Duration) (probe.Result, error) {
	if err := ctx.Err(); err != nil {
		return probe.Result{}, err
	}
	if !p.started {
		p.started, p.tokens = true, float64(p.Burst)
	}
	p.Sizes = append(p.Sizes, size)
	n := len(p.Sizes)
	r := probe.Result{Size: size, ICMPType: -1, ICMPCode: -1, RTT: rtt}
	silence := func() (probe.Result, error) {
		p.Clock += timeout
		r.Outcome, r.RTT, r.Detail = probe.Timeout, timeout, "no answer"
		return r, nil
	}
	if p.LocalMTU > 0 && size > p.LocalMTU {
		r.Outcome, r.MTU, r.Detail = probe.LocalTooBig, p.LocalMTU, "local route MTU"
		return r, nil
	}
	p.Clock += rtt
	if p.Drop != nil && p.Drop(n, size) {
		return silence()
	}
	for _, h := range p.Hops {
		if size <= h.MTU {
			continue
		}
		h.oversize++
		switch {
		case h.Reject != "":
			r.Outcome, r.From, r.Detail = probe.Unreachable, h.Addr, h.Reject
			return r, nil
		case h.SendPTB && (h.PTBEvery <= 1 || h.oversize%h.PTBEvery == 1):
			mtu := h.MTU
			if h.Advertise > 0 {
				mtu = h.Advertise
			} else if h.Advertise < 0 {
				mtu = 0
			}
			r.Outcome, r.From, r.MTU, r.Detail = probe.TooBig, h.Addr, mtu, "packet too big"
			return r, nil
		}
		return silence()
	}
	if p.Silent || (p.StopAfter > 0 && n > p.StopAfter) {
		return silence()
	}
	if p.Burst > 0 {
		p.tokens += float64(p.Clock-p.lastFill) / float64(p.Refill)
		p.lastFill = p.Clock
		p.tokens = min(p.tokens, float64(p.Burst))
		if p.tokens < 1 {
			return silence()
		}
		p.tokens--
	}
	r.Outcome, r.From, r.Detail = probe.Reply, p.Dst, "echo reply"
	return r, nil
}

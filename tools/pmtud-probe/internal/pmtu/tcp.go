package pmtu

import (
	"context"
	"fmt"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/probe"
)

// TCP verdicts.
const (
	MSSFits         = "fits"
	MSSTooLarge     = "too-large"
	MSSInconclusive = "inconclusive"
)

// tcpCheck connects to the target (handshake only) and infers the MSS the
// target advertised, as received here: possibly clamped by a middlebox on
// the way, which is exactly what MSS clamping is meant to do.
//
// Linux's sending MSS is min(peer MSS, kernel PMTU - headers) minus TCP
// option bytes. When it is below the PMTU-derived limit it reveals the
// peer's MSS exactly; otherwise only a lower bound is known.
func (s *search) tcpCheck(ctx context.Context) *TCPCheck {
	tc := &TCPCheck{Port: s.opt.TCPPort}
	fn := s.opt.TCP
	if fn == nil {
		fn = probe.TCPCheck
	}
	addr := s.p.Target()
	ti, err := fn(ctx, addr, s.opt.TCPPort, max(3*s.opt.Timeout, 3*time.Second))
	if err != nil {
		tc.Error = err.Error()
		s.rep.add("tcp-connect", SevWarning, fmt.Sprintf("MSS check: cannot connect to %s port %d: %v", addr, s.opt.TCPPort, err))
		return tc
	}
	hdr := probe.IPHeader(addr) + probe.TCPHeader
	tc.SndMSS = int(ti.SndMSS)
	tc.OptionBytes = ti.OptionBytes()
	tc.KernelPMTU = int(ti.PMTU)
	tc.PeerMSS = tc.SndMSS + tc.OptionBytes
	tc.PeerMSSMin = ti.PMTU == 0 || tc.PeerMSS >= int(ti.PMTU)-hdr
	tc.SegmentSize = tc.PeerMSS + hdr
	s.logf("%s: tcp/%d snd_mss=%d options=%d pmtu=%d -> peer MSS %d (lower bound: %v)",
		s.rep.Target, tc.Port, tc.SndMSS, tc.OptionBytes, tc.KernelPMTU, tc.PeerMSS, tc.PeerMSSMin)
	return tc
}

func (s *search) tcpVerdict(upper int) {
	tc, rep := s.rep.TCP, s.rep
	pmtu := rep.PathMTU
	mssForPath := rep.TCPMSS
	bound := ""
	if tc.PeerMSSMin {
		bound = "at least "
	}
	switch {
	case tc.SegmentSize > pmtu:
		tc.Verdict = MSSTooLarge
		sev := SevWarning
		tail := "TCP towards the target depends on PMTUD"
		if rep.PMTUD == PMTUDBlackHole || rep.PMTUD == PMTUDFiltered {
			sev = SevCritical
			tail = "PMTUD is broken on this path, so TCP transfers will stall after the handshake"
		}
		tc.VerdictText = fmt.Sprintf("MSS not clamped: the target's MSS arrives as %s%d, so full segments are %d-byte packets but the path carries %d; %s. Clamp the MSS to %d (e.g. nftables: tcp flags syn tcp option maxseg size set rt mtu)",
			bound, tc.PeerMSS, tc.SegmentSize, pmtu, tail, mssForPath)
		rep.add("mss-not-clamped", sev, tc.VerdictText)
	case !tc.PeerMSSMin:
		tc.Verdict = MSSFits
		tc.VerdictText = fmt.Sprintf("the target's MSS arrives as %d: full segments (%d bytes) fit the %d-byte path", tc.PeerMSS, tc.SegmentSize, pmtu)
		if pmtu < upper {
			tc.VerdictText += " (MSS clamping or a smaller server-side MTU keeps TCP independent of PMTUD)"
		}
		rep.add("mss-fits", SevOK, tc.VerdictText)
	default:
		tc.Verdict = MSSInconclusive
		tc.VerdictText = fmt.Sprintf(
			"the kernel already caps the MSS with a cached path MTU of %d, which hides the target's advertised MSS; flush the cache (ip route flush cache) and re-run to check MSS clamping",
			tc.KernelPMTU)
		if pmtu == upper {
			tc.Verdict = MSSFits
			tc.VerdictText = fmt.Sprintf("full segments (%d bytes) fit the unconstrained path", tc.SegmentSize)
			rep.add("mss-fits", SevOK, tc.VerdictText)
			return
		}
		rep.add("mss-inconclusive", SevInfo, tc.VerdictText)
	}
}

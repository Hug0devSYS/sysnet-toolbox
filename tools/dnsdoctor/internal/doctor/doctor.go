package doctor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/transport"
)

// Options tunes a diagnosis.
type Options struct {
	// DNSSEC enables chain-of-trust validation.
	DNSSEC bool
	// TrustAnchors are the root DS records; nil means RootAnchors.
	TrustAnchors []*dnswire.DS
	// SigExpiryWarn raises a warning when a validated signature expires
	// sooner than this.
	SigExpiryWarn time.Duration
	// Concurrency bounds parallel name server probes.
	Concurrency int
	// Now returns the current time (overridable for tests).
	Now func() time.Time
}

// Doctor runs zone diagnostics.
type Doctor struct {
	R    *Resolver
	Opts Options
}

// ErrOperational wraps failures that prevented a diagnosis.
var ErrOperational = errors.New("diagnosis incomplete")

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

func (d *Doctor) now() time.Time {
	if d.Opts.Now != nil {
		return d.Opts.Now().UTC()
	}
	return time.Now().UTC()
}

// Diagnose runs every check against zone. The returned error is non-nil
// (wrapping ErrOperational) only when the diagnosis could not be performed;
// DNS problems are reported as findings.
func (d *Doctor) Diagnose(ctx context.Context, zone string) (*Report, error) {
	start := time.Now()
	rep := &Report{Zone: dnswire.CanonicalName(zone), CheckedAt: d.now(), Delegation: []Referral{}, Findings: []Finding{}}
	q0 := d.R.Queries()
	err := d.diagnose(ctx, rep)
	rep.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	rep.Queries = d.R.Queries() - q0
	if err != nil {
		rep.Error = err.Error()
	}
	rep.summarize()
	if err != nil {
		return rep, fmt.Errorf("%w: %w", ErrOperational, err)
	}
	return rep, nil
}

func (d *Doctor) diagnose(ctx context.Context, rep *Report) error {
	zone := rep.Zone
	if err := dnswire.ValidateName(zone); err != nil {
		return fmt.Errorf("invalid zone name %q: %w", zone, err)
	}

	// 1. Walk the delegation chain from the root.
	res, err := d.R.walk(ctx, zone, dnswire.TypeNS, true, 0)
	if res != nil {
		rep.Delegation = append(rep.Delegation, res.Referrals...)
	}
	if err != nil {
		if errors.Is(err, ErrNXDomain) && res != nil {
			rep.add(CheckDelegation, SevError, "%s does not exist: NXDOMAIN from %s (zone %s)", zone, res.Server, res.Zone)
			return fmt.Errorf("%s: %w", zone, ErrNXDomain)
		}
		rep.add(CheckDelegation, SevError, "delegation walk failed: %v", err)
		return err
	}
	final := res.Final
	for _, rr := range final.Answer {
		if c, ok := rr.Data.(*dnswire.CNAME); ok && dnswire.EqualNames(rr.Name, zone) {
			rep.add(CheckDelegation, SevError, "%s is an alias (CNAME to %s), not a zone", zone, c.Target)
			return fmt.Errorf("%s: %w", zone, ErrNotZoneApex)
		}
	}
	childNS := nsOwnedBy(final.Answer, zone)
	if len(childNS) == 0 {
		enclosing := res.Zone
		for _, rr := range final.Authority {
			if rr.Type == dnswire.TypeSOA {
				enclosing = dnswire.CanonicalName(rr.Name)
			}
		}
		rep.add(CheckDelegation, SevError, "%s exists but is not a zone apex (no NS RRset); enclosing zone is %s", zone, enclosing)
		return fmt.Errorf("%s: %w (enclosing zone %s)", zone, ErrNotZoneApex, enclosing)
	}
	rep.ChildNS = childNS

	// The parent's view of the delegation is the last referral to zone.
	var parentRef *Referral
	if n := len(res.Referrals); n > 0 && res.Referrals[n-1].Child == zone {
		parentRef = &res.Referrals[n-1]
		rep.ParentZone = parentRef.Parent
		rep.ParentNS = parentRef.NS
	} else if zone != "." {
		rep.ParentZone = res.Zone
		rep.add(CheckDelegation, SevInfo, "servers of %s are also authoritative for %s; the parent-side delegation could not be observed separately", res.Zone, zone)
	}
	if rep.ParentNS == nil {
		rep.ParentNS = []string{}
	}

	// 2. Resolve and probe every name server (parent ∪ child).
	hosts := d.collectHosts(ctx, rep, parentRef)
	d.probeAll(ctx, zone, hosts)
	rep.Nameservers = hosts

	// 3. Consistency checks.
	checkNSSets(rep)
	checkProbes(rep)
	checkSerials(rep)
	checkDiversity(rep)

	// 4. DNSSEC chain of trust.
	if d.Opts.DNSSEC {
		rep.DNSSEC = d.validateChain(ctx, rep, res)
	} else {
		rep.DNSSEC = &DNSSECReport{Status: DNSSECSkipped, Chain: []ChainLink{}}
	}
	sortFindings(rep.Findings)
	return nil
}

func nsOwnedBy(rrs []dnswire.RR, zone string) []string {
	var out []string
	for _, rr := range rrs {
		if ns, ok := rr.Data.(*dnswire.NS); ok && dnswire.EqualNames(rr.Name, zone) {
			out = append(out, dnswire.CanonicalName(ns.Host))
		}
	}
	return uniqSorted(out)
}

// collectHosts merges parent and child NS sets and resolves addresses.
func (d *Doctor) collectHosts(ctx context.Context, rep *Report, parentRef *Referral) []NSHost {
	names := map[string]*NSHost{}
	get := func(n string) *NSHost {
		if h, ok := names[n]; ok {
			return h
		}
		h := &NSHost{Name: n, Addresses: []AddrResult{}}
		names[n] = h
		return h
	}
	for _, n := range rep.ParentNS {
		get(n).InParent = true
	}
	for _, n := range rep.ChildNS {
		get(n).InChild = true
	}
	var order []string
	for n := range names {
		order = append(order, n)
	}
	sort.Strings(order)

	var out []NSHost
	for _, n := range order {
		h := names[n]
		var glue []netip.Addr
		if parentRef != nil {
			glue = d.R.FilterFamily(parentRef.glueAddrs[n])
			for _, g := range glue {
				h.Glue = append(h.Glue, g.String())
			}
		}
		auth, err := d.R.ResolveAddrs(ctx, n)
		auth = d.R.FilterFamily(auth)
		if err != nil {
			h.ResolveError = err.Error()
		}
		if len(glue) > 0 && len(auth) > 0 && !sameAddrs(glue, auth) {
			rep.add(CheckGlue, SevWarning, "glue for %s at parent %s (%s) differs from its authoritative addresses (%s)",
				n, rep.ParentZone, joinAddrs(glue), joinAddrs(auth))
		}
		if parentRef != nil && len(parentRef.glueAddrs[n]) == 0 && dnswire.IsSubdomain(n, rep.Zone) && h.InParent {
			rep.add(CheckGlue, SevError, "in-bailiwick name server %s has no glue at parent %s", n, rep.ParentZone)
		}
		for _, a := range unionAddrs(glue, auth) {
			h.Addresses = append(h.Addresses, AddrResult{Address: a.String()})
		}
		if len(h.Addresses) == 0 {
			msg := "no addresses"
			if h.ResolveError != "" {
				msg = h.ResolveError
			}
			rep.add(CheckLame, SevError, "name server %s cannot be resolved (%s)", n, msg)
		}
		out = append(out, *h)
	}
	return out
}

// probeAll queries SOA and NS on every address concurrently.
func (d *Doctor) probeAll(ctx context.Context, zone string, hosts []NSHost) {
	conc := d.Opts.Concurrency
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i := range hosts {
		for j := range hosts[i].Addresses {
			ar := &hosts[i].Addresses[j]
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				d.probe(ctx, zone, ar)
			}()
		}
	}
	wg.Wait()
}

func (d *Doctor) probe(ctx context.Context, zone string, ar *AddrResult) {
	addr, err := netip.ParseAddr(ar.Address)
	if err != nil {
		ar.Status, ar.Error = StatusUnreachable, err.Error()
		return
	}
	resp, rtt, err := d.R.Query(ctx, addr, zone, dnswire.TypeSOA, false)
	if err != nil {
		if transport.IsNetworkUnreachable(err) {
			ar.Status, ar.Error = StatusSkipped, "no route from this host"
			return
		}
		ar.Status, ar.Error = StatusUnreachable, err.Error()
		return
	}
	ar.RTTMillis = float64(rtt.Microseconds()) / 1000
	ar.Rcode = dnswire.RcodeString(resp.Rcode)
	ar.Authoritative = resp.Authoritative
	if resp.Rcode != dnswire.RcodeSuccess {
		ar.Status, ar.Error = StatusLame, "answered "+ar.Rcode
		return
	}
	if !resp.Authoritative {
		ar.Status, ar.Error = StatusLame, "non-authoritative answer (AA bit not set)"
		return
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.Data.(*dnswire.SOA); ok && dnswire.EqualNames(rr.Name, zone) {
			s := soa.Serial
			ar.Serial = &s
		}
	}
	if ar.Serial == nil {
		ar.Status, ar.Error = StatusLame, "authoritative answer without the zone's SOA"
		return
	}
	ar.Status = StatusOK
	if nsResp, _, err := d.R.Query(ctx, addr, zone, dnswire.TypeNS, false); err == nil && nsResp.Rcode == dnswire.RcodeSuccess {
		ar.NS = nsOwnedBy(nsResp.Answer, zone)
	}
}

func checkNSSets(rep *Report) {
	if len(rep.ChildNS) < 2 {
		rep.add(CheckNS, SevWarning, "zone lists only %d name server(s); at least 2 are required (RFC 1034 section 4.1)", len(rep.ChildNS))
	}
	if rep.Zone == "." || len(rep.Delegation) == 0 || rep.Delegation[len(rep.Delegation)-1].Child != rep.Zone {
		return
	}
	onlyParent := diff(rep.ParentNS, rep.ChildNS)
	onlyChild := diff(rep.ChildNS, rep.ParentNS)
	if len(onlyParent) > 0 || len(onlyChild) > 0 {
		rep.add(CheckNS, SevWarning, "NS set mismatch between parent %s and child: only at parent [%s], only at child [%s]",
			rep.ParentZone, joinOrNone(onlyParent), joinOrNone(onlyChild))
	} else {
		rep.add(CheckNS, SevInfo, "parent and child NS sets match (%d servers)", len(rep.ChildNS))
	}
	for _, h := range rep.Nameservers {
		for _, a := range h.Addresses {
			if a.Status == StatusOK && a.NS != nil && !equalStrings(a.NS, rep.ChildNS) {
				rep.add(CheckNS, SevWarning, "%s (%s) serves a different NS RRset: [%s]", h.Name, a.Address, strings.Join(a.NS, " "))
			}
		}
	}
}

func checkProbes(rep *Report) {
	skipped := 0
	tested := 0
	v6 := 0
	for _, h := range rep.Nameservers {
		okCount := 0
		for _, a := range h.Addresses {
			if strings.Contains(a.Address, ":") {
				v6++
			}
			switch a.Status {
			case StatusOK:
				okCount++
				tested++
			case StatusSkipped:
				skipped++
			case StatusLame:
				tested++
				rep.add(CheckLame, SevError, "lame delegation: %s (%s) %s for %s", h.Name, a.Address, a.Error, rep.Zone)
			case StatusUnreachable:
				tested++
				rep.add(CheckLame, SevError, "%s (%s) did not answer: %s", h.Name, a.Address, a.Error)
			}
		}
		if okCount == 0 && len(h.Addresses) > 0 && !allSkipped(h.Addresses) {
			rep.add(CheckLame, SevError, "name server %s has no working address", h.Name)
		}
	}
	if skipped > 0 {
		rep.add(CheckLame, SevInfo, "%d address(es) not tested: no route from this host (IPv6 unavailable?)", skipped)
	}
	if v6 == 0 && tested > 0 {
		rep.add(CheckDiversity, SevInfo, "no name server has an IPv6 address")
	}
}

func allSkipped(as []AddrResult) bool {
	for _, a := range as {
		if a.Status != StatusSkipped {
			return false
		}
	}
	return true
}

// serialNewer reports whether a is newer than b in RFC 1982 arithmetic.
func serialNewer(a, b uint32) bool {
	return a != b && int32(a-b) > 0
}

func checkSerials(rep *Report) {
	type obs struct {
		who    string
		serial uint32
	}
	var all []obs
	for _, h := range rep.Nameservers {
		for _, a := range h.Addresses {
			if a.Status == StatusOK && a.Serial != nil {
				all = append(all, obs{fmt.Sprintf("%s (%s)", h.Name, a.Address), *a.Serial})
			}
		}
	}
	if len(all) == 0 {
		return
	}
	newest := all[0].serial
	for _, o := range all[1:] {
		if serialNewer(o.serial, newest) {
			newest = o.serial
		}
	}
	drift := false
	for _, o := range all {
		if o.serial != newest {
			drift = true
			rep.add(CheckSOA, SevWarning, "SOA serial drift: %s serves %d, newest is %d (behind by %d)", o.who, o.serial, newest, newest-o.serial)
		}
	}
	if !drift {
		rep.add(CheckSOA, SevInfo, "all %d responding server address(es) serve SOA serial %d", len(all), newest)
	}
}

func checkDiversity(rep *Report) {
	prefixes := map[netip.Prefix]bool{}
	n := 0
	for _, h := range rep.Nameservers {
		for _, a := range h.Addresses {
			ip, err := netip.ParseAddr(a.Address)
			if err != nil || a.Status == StatusSkipped {
				continue
			}
			n++
			bits := 24
			if ip.Is6() {
				bits = 48
			}
			p, _ := ip.Prefix(bits)
			prefixes[p] = true
		}
	}
	if n > 1 && len(prefixes) == 1 {
		for p := range prefixes {
			rep.add(CheckDiversity, SevWarning, "all name server addresses are in %s: no network diversity (RFC 2182 section 3.1)", p)
		}
	}
}

func sortFindings(fs []Finding) {
	rank := map[Severity]int{SevError: 0, SevWarning: 1, SevInfo: 2}
	sort.SliceStable(fs, func(i, j int) bool { return rank[fs[i].Severity] < rank[fs[j].Severity] })
}

func diff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func unionAddrs(a, b []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, x := range append(append([]netip.Addr{}, a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func sameAddrs(a, b []netip.Addr) bool {
	ua, ub := unionAddrs(a, nil), unionAddrs(b, nil)
	if len(ua) != len(ub) {
		return false
	}
	for i := range ua {
		if ua[i] != ub[i] {
			return false
		}
	}
	return true
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range unionAddrs(as, nil) {
		s[i] = a.String()
	}
	return strings.Join(s, " ")
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}

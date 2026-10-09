// Package doctor implements dnsdoctor's iterative resolver and the zone
// health checks built on top of it.
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

// RootServers are the IPv4 and IPv6 addresses of a.root-servers.net through
// m.root-servers.net (IANA root hints).
var RootServers = []string{
	"198.41.0.4", "2001:503:ba3e::2:30", // a
	"170.247.170.2", "2801:1b8:10::b", // b
	"192.33.4.12", "2001:500:2::c", // c
	"199.7.91.13", "2001:500:2d::d", // d
	"192.203.230.10", "2001:500:a8::e", // e
	"192.5.5.241", "2001:500:2f::f", // f
	"192.112.36.4", "2001:500:12::d0d", // g
	"198.97.190.53", "2001:500:1::53", // h
	"192.36.148.17", "2001:7fe::53", // i
	"192.58.128.30", "2001:503:c27::2:30", // j
	"193.0.14.129", "2001:7fd::1", // k
	"199.7.83.42", "2001:500:9f::42", // l
	"202.12.27.33", "2001:dc3::35", // m
}

// Errors reported by the resolver.
var (
	ErrNXDomain     = errors.New("name does not exist (NXDOMAIN)")
	ErrNoServers    = errors.New("no usable name server addresses")
	ErrAllFailed    = errors.New("all name servers failed to answer")
	ErrDepth        = errors.New("resolution depth exceeded")
	ErrLoop         = errors.New("referral loop or upward referral")
	ErrNotZoneApex  = errors.New("name is not a zone apex")
	ErrLameReferral = errors.New("lame or unusable referral")
)

// Resolver is a minimal, non-recursive (RD=0) iterative resolver that starts
// from the root servers. It is safe for concurrent use.
type Resolver struct {
	X       transport.Exchanger
	Roots   []netip.Addr
	UseIPv4 bool
	UseIPv6 bool
	// Port is the DNS port (53 unless testing).
	Port uint16
	// MaxDepth bounds nested resolutions of glueless name servers.
	MaxDepth int
	// MaxReferrals bounds the referral chain length for a single name.
	MaxReferrals int
	// Logf, if set, receives a line per query (verbose mode).
	Logf func(format string, args ...any)

	mu      sync.Mutex
	addrs   map[string][]netip.Addr // NS host -> addresses
	cuts    map[string][]netip.Addr // zone cut -> server addresses
	queries int
}

// NewResolver returns a resolver using the built-in root servers.
func NewResolver(x transport.Exchanger) *Resolver {
	r := &Resolver{X: x, UseIPv4: true, UseIPv6: true, Port: 53, MaxDepth: 6, MaxReferrals: 24}
	for _, s := range RootServers {
		r.Roots = append(r.Roots, netip.MustParseAddr(s))
	}
	return r
}

// Queries returns the number of queries sent so far.
func (r *Resolver) Queries() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries
}

func (r *Resolver) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// FilterFamily keeps the addresses of enabled address families.
func (r *Resolver) FilterFamily(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if (a.Is4() || a.Is4In6()) && r.UseIPv4 || a.Is6() && !a.Is4In6() && r.UseIPv6 {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func (r *Resolver) port() uint16 {
	if r.Port == 0 {
		return 53
	}
	return r.Port
}

// Query sends one query to one server.
func (r *Resolver) Query(ctx context.Context, server netip.Addr, name string, t dnswire.Type, do bool) (*dnswire.Msg, time.Duration, error) {
	r.mu.Lock()
	r.queries++
	r.mu.Unlock()
	q := dnswire.NewQuery(transport.RandomID(), name, t, do)
	resp, rtt, err := r.X.Exchange(ctx, netip.AddrPortFrom(server, r.port()), q)
	if err != nil {
		r.logf("  %-40s %-6s @%-39s error: %v", name, t, server, err)
		return nil, 0, err
	}
	// Retry once without EDNS on FORMERR/NOTIMP/BADVERS from very old servers.
	if resp.Rcode == dnswire.RcodeFormErr || resp.Rcode == dnswire.RcodeNotImp || resp.Rcode == dnswire.RcodeBadVers {
		q2 := dnswire.NewQuery(transport.RandomID(), name, t, false)
		q2.EDNS = nil
		if resp2, rtt2, err2 := r.X.Exchange(ctx, netip.AddrPortFrom(server, r.port()), q2); err2 == nil {
			resp, rtt = resp2, rtt2
		}
	}
	r.logf("  %-40s %-6s @%-39s %s aa=%v an=%d ns=%d ar=%d %s", name, t, server,
		dnswire.RcodeString(resp.Rcode), resp.Authoritative, len(resp.Answer), len(resp.Authority), len(resp.Additional), rtt.Round(time.Millisecond))
	return resp, rtt, nil
}

// Referral describes one delegation step observed while walking down.
type Referral struct {
	// Parent is the zone whose servers issued the referral.
	Parent string `json:"parent"`
	// Child is the delegated zone.
	Child string `json:"child"`
	// Server is the address that returned the referral.
	Server string `json:"server"`
	// RTTMillis is the round-trip time of that query.
	RTTMillis float64 `json:"rtt_ms"`
	// NS is the delegation NS set (lowercased, sorted).
	NS []string `json:"ns"`
	// Glue maps NS host names to glue addresses from the referral.
	Glue map[string][]string `json:"glue,omitempty"`
	// HasDS reports whether the referral carried DS records.
	HasDS bool `json:"has_ds"`
	// Servers holds the resolved addresses of the child's servers (not
	// serialised; used by the DNSSEC walk).
	Servers   []netip.Addr `json:"-"`
	glueAddrs map[string][]netip.Addr
}

// walkResult is the outcome of an iterative walk.
type walkResult struct {
	Final     *dnswire.Msg
	Server    netip.Addr
	Zone      string       // zone whose servers gave the final answer
	Servers   []netip.Addr // addresses of those servers
	Referrals []Referral
}

// walk resolves (name, t) iteratively. If fromRoot is false the walk starts
// at the closest cached zone cut.
func (r *Resolver) walk(ctx context.Context, name string, t dnswire.Type, fromRoot bool, depth int) (*walkResult, error) {
	if depth > r.MaxDepth {
		return nil, ErrDepth
	}
	name = dnswire.CanonicalName(name)
	zone := "."
	servers := r.FilterFamily(r.Roots)
	if !fromRoot {
		zone, servers = r.closestCut(name)
	}
	res := &walkResult{}
	for hops := 0; hops < r.MaxReferrals; hops++ {
		if len(servers) == 0 {
			return res, fmt.Errorf("%w for zone %s", ErrNoServers, zone)
		}
		resp, server, rtt, err := r.queryAny(ctx, servers, name, t, true)
		if err != nil {
			return res, fmt.Errorf("zone %s: %w", zone, err)
		}
		res.Final, res.Server, res.Zone, res.Servers = resp, server, zone, servers

		if resp.Rcode == dnswire.RcodeNXDomain {
			return res, ErrNXDomain
		}
		if len(resp.Answer) > 0 || resp.Authoritative {
			return res, nil
		}
		ref, ok := parseReferral(resp, zone, name)
		if !ok {
			// Non-authoritative empty answer without a usable referral.
			return res, fmt.Errorf("%w from %s (zone %s)", ErrLameReferral, server, zone)
		}
		ref.Server = server.String()
		ref.RTTMillis = float64(rtt.Microseconds()) / 1000
		next, err := r.serversFor(ctx, ref, depth)
		if err != nil {
			return res, fmt.Errorf("delegation %s: %w", ref.Child, err)
		}
		ref.Servers = next
		res.Referrals = append(res.Referrals, ref)
		r.mu.Lock()
		if r.cuts == nil {
			r.cuts = map[string][]netip.Addr{}
		}
		r.cuts[ref.Child] = next
		r.mu.Unlock()
		zone, servers = ref.Child, next
	}
	return res, ErrLoop
}

// queryAny tries servers in order until one gives a usable response.
func (r *Resolver) queryAny(ctx context.Context, servers []netip.Addr, name string, t dnswire.Type, do bool) (*dnswire.Msg, netip.Addr, time.Duration, error) {
	var errs []string
	for _, s := range servers {
		if err := ctx.Err(); err != nil {
			return nil, netip.Addr{}, 0, err
		}
		resp, rtt, err := r.Query(ctx, s, name, t, do)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s, err))
			continue
		}
		switch resp.Rcode {
		case dnswire.RcodeSuccess, dnswire.RcodeNXDomain:
			return resp, s, rtt, nil
		default:
			errs = append(errs, fmt.Sprintf("%s: %s", s, dnswire.RcodeString(resp.Rcode)))
		}
	}
	if len(errs) > 3 {
		errs = append(errs[:3], fmt.Sprintf("and %d more", len(errs)-3))
	}
	return nil, netip.Addr{}, 0, fmt.Errorf("%w (%s)", ErrAllFailed, strings.Join(errs, "; "))
}

func (r *Resolver) closestCut(name string) (string, []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	best := "."
	var servers []netip.Addr
	for z, s := range r.cuts {
		if dnswire.IsSubdomain(name, z) && dnswire.CountLabels(z) > dnswire.CountLabels(best) && len(s) > 0 {
			best, servers = z, s
		}
	}
	if best == "." {
		return ".", r.FilterFamily(r.Roots)
	}
	return best, servers
}

// parseReferral extracts a downward referral from a non-authoritative response.
func parseReferral(resp *dnswire.Msg, zone, qname string) (Referral, bool) {
	ref := Referral{Parent: zone, Glue: map[string][]string{}, glueAddrs: map[string][]netip.Addr{}}
	for _, rr := range resp.Authority {
		switch d := rr.Data.(type) {
		case *dnswire.NS:
			child := dnswire.CanonicalName(rr.Name)
			if ref.Child == "" {
				ref.Child = child
			}
			if child != ref.Child {
				continue
			}
			ref.NS = append(ref.NS, dnswire.CanonicalName(d.Host))
		case *dnswire.DS:
			ref.HasDS = true
		}
	}
	if ref.Child == "" || len(ref.NS) == 0 {
		return ref, false
	}
	// Must be strictly below the current zone and an ancestor of qname.
	if !dnswire.IsSubdomain(qname, ref.Child) || !dnswire.IsSubdomain(ref.Child, zone) ||
		dnswire.CanonicalName(ref.Child) == dnswire.CanonicalName(zone) {
		return ref, false
	}
	ref.NS = uniqSorted(ref.NS)
	for _, rr := range resp.Additional {
		host := dnswire.CanonicalName(rr.Name)
		if !contains(ref.NS, host) {
			continue
		}
		var a netip.Addr
		switch d := rr.Data.(type) {
		case *dnswire.A:
			a = d.Addr
		case *dnswire.AAAA:
			a = d.Addr
		default:
			continue
		}
		// Ignore out-of-bailiwick glue (cache poisoning hygiene): glue is
		// only trusted for hosts under the zone that issued the referral.
		if !dnswire.IsSubdomain(host, zone) {
			continue
		}
		ref.glueAddrs[host] = append(ref.glueAddrs[host], a)
		ref.Glue[host] = append(ref.Glue[host], a.String())
	}
	if len(ref.Glue) == 0 {
		ref.Glue = nil
	}
	return ref, true
}

// serversFor returns the addresses of a referral's name servers, using glue
// where available and resolving glueless hosts otherwise.
func (r *Resolver) serversFor(ctx context.Context, ref Referral, depth int) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, host := range ref.NS {
		out = append(out, r.FilterFamily(ref.glueAddrs[host])...)
	}
	if len(out) > 0 {
		return out, nil
	}
	var lastErr error
	for _, host := range ref.NS {
		// A glueless in-zone host cannot be resolved (it would loop).
		if dnswire.IsSubdomain(host, ref.Child) {
			continue
		}
		addrs, err := r.resolveAddrs(ctx, host, depth+1)
		if err != nil {
			lastErr = err
			continue
		}
		out = append(out, r.FilterFamily(addrs)...)
		if len(out) > 0 {
			return out, nil // one working host is enough to continue
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoServers, lastErr)
	}
	return nil, ErrNoServers
}

// ResolveAddrs returns the A and AAAA addresses of host (iteratively).
func (r *Resolver) ResolveAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.resolveAddrs(ctx, host, 0)
}

func (r *Resolver) resolveAddrs(ctx context.Context, host string, depth int) ([]netip.Addr, error) {
	host = dnswire.CanonicalName(host)
	r.mu.Lock()
	if a, ok := r.addrs[host]; ok {
		r.mu.Unlock()
		return a, nil
	}
	r.mu.Unlock()

	var out []netip.Addr
	var errs []error
	types := []dnswire.Type{}
	if r.UseIPv4 {
		types = append(types, dnswire.TypeA)
	}
	if r.UseIPv6 {
		types = append(types, dnswire.TypeAAAA)
	}
	for _, t := range types {
		addrs, err := r.lookupAddr(ctx, host, t, depth, 0)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("resolve %s: %w", host, errors.Join(errs...))
		}
		return nil, fmt.Errorf("resolve %s: no A/AAAA records", host)
	}
	r.mu.Lock()
	if r.addrs == nil {
		r.addrs = map[string][]netip.Addr{}
	}
	r.addrs[host] = out
	r.mu.Unlock()
	return out, nil
}

func (r *Resolver) lookupAddr(ctx context.Context, name string, t dnswire.Type, depth, cnames int) ([]netip.Addr, error) {
	if cnames > 8 {
		return nil, errors.New("CNAME chain too long")
	}
	res, err := r.walk(ctx, name, t, false, depth)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	var cname string
	for _, rr := range res.Final.Answer {
		if !dnswire.EqualNames(rr.Name, name) {
			continue
		}
		switch d := rr.Data.(type) {
		case *dnswire.A:
			if t == dnswire.TypeA {
				out = append(out, d.Addr)
			}
		case *dnswire.AAAA:
			if t == dnswire.TypeAAAA {
				out = append(out, d.Addr)
			}
		case *dnswire.CNAME:
			cname = d.Target
		}
	}
	if len(out) == 0 && cname != "" {
		return r.lookupAddr(ctx, cname, t, depth, cnames+1)
	}
	return out, nil
}

func uniqSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

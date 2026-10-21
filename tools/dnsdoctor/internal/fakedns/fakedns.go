// Package fakedns provides an in-memory authoritative DNS hierarchy with
// optional DNSSEC signing. It implements transport.Exchanger so the
// resolver and checks can be tested end to end without network access.
package fakedns

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnssec"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

type key struct {
	name string
	t    dnswire.Type
}

// Key is a DNSSEC key pair.
type Key struct {
	DNSKEY *dnswire.DNSKEY
	Signer crypto.Signer
}

// NewKey generates an Ed25519 zone key; ksk sets the SEP flag.
func NewKey(ksk bool) *Key {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	flags := dnssec.FlagZone
	if ksk {
		flags |= dnssec.FlagSEP
	}
	return &Key{DNSKEY: &dnswire.DNSKEY{Flags: flags, Protocol: 3, Algorithm: dnssec.AlgED25519, PublicKey: priv.Public().(ed25519.PublicKey)}, Signer: priv}
}

// Zone is an authoritative zone.
type Zone struct {
	Name     string
	KSK, ZSK *Key
	records  map[key][]dnswire.RR
	sigs     map[key][]dnswire.RR
	cuts     map[string]bool
}

// NewZone creates a zone with an SOA. If signed, KSK and ZSK are generated
// and their DNSKEY RRset added.
func NewZone(name string, serial uint32, signed bool) *Zone {
	z := &Zone{Name: dnswire.CanonicalName(name), records: map[key][]dnswire.RR{}, sigs: map[key][]dnswire.RR{}, cuts: map[string]bool{}}
	z.Add(dnswire.RR{Name: z.Name, Type: dnswire.TypeSOA, TTL: 3600, Data: &dnswire.SOA{
		MName: "ns1." + strings.TrimPrefix(z.Name, "."), RName: "hostmaster." + strings.TrimPrefix(z.Name, "."),
		Serial: serial, Refresh: 7200, Retry: 900, Expire: 1209600, Minimum: 300,
	}})
	if signed {
		z.KSK, z.ZSK = NewKey(true), NewKey(false)
		z.Add(dnswire.RR{Name: z.Name, Type: dnswire.TypeDNSKEY, TTL: 3600, Data: z.KSK.DNSKEY},
			dnswire.RR{Name: z.Name, Type: dnswire.TypeDNSKEY, TTL: 3600, Data: z.ZSK.DNSKEY})
	}
	return z
}

// Add inserts records.
func (z *Zone) Add(rrs ...dnswire.RR) *Zone {
	for _, rr := range rrs {
		rr.Name = dnswire.CanonicalName(rr.Name)
		if rr.Class == 0 {
			rr.Class = dnswire.ClassINET
		}
		k := key{rr.Name, rr.Type}
		z.records[k] = append(z.records[k], rr)
	}
	return z
}

// Remove deletes the RRset (name, t).
func (z *Zone) Remove(name string, t dnswire.Type) {
	delete(z.records, key{dnswire.CanonicalName(name), t})
	delete(z.sigs, key{dnswire.CanonicalName(name), t})
}

// SetSerial changes the SOA serial (call Sign again if signed).
func (z *Zone) SetSerial(s uint32) {
	for _, rr := range z.records[key{z.Name, dnswire.TypeSOA}] {
		rr.Data.(*dnswire.SOA).Serial = s
	}
}

// Clone returns a deep-enough copy (records slices and SOA are copied).
func (z *Zone) Clone() *Zone {
	c := &Zone{Name: z.Name, KSK: z.KSK, ZSK: z.ZSK, records: map[key][]dnswire.RR{}, sigs: map[key][]dnswire.RR{}, cuts: map[string]bool{}}
	for k, v := range z.records {
		cp := append([]dnswire.RR(nil), v...)
		if k.t == dnswire.TypeSOA {
			for i := range cp {
				s := *cp[i].Data.(*dnswire.SOA)
				cp[i].Data = &s
			}
		}
		c.records[k] = cp
	}
	for k, v := range z.sigs {
		c.sigs[k] = append([]dnswire.RR(nil), v...)
	}
	for k := range z.cuts {
		c.cuts[k] = true
	}
	return c
}

// NS adds an NS record at the zone apex.
func (z *Zone) NS(hosts ...string) *Zone {
	for _, h := range hosts {
		z.Add(dnswire.RR{Name: z.Name, Type: dnswire.TypeNS, TTL: 3600, Data: &dnswire.NS{Host: dnswire.CanonicalName(h)}})
	}
	return z
}

// Addr adds A/AAAA records for name.
func (z *Zone) Addr(name string, addrs ...string) *Zone {
	for _, a := range addrs {
		ip := netip.MustParseAddr(a)
		if ip.Is4() {
			z.Add(dnswire.RR{Name: name, Type: dnswire.TypeA, TTL: 3600, Data: &dnswire.A{Addr: ip}})
		} else {
			z.Add(dnswire.RR{Name: name, Type: dnswire.TypeAAAA, TTL: 3600, Data: &dnswire.AAAA{Addr: ip}})
		}
	}
	return z
}

// Delegate adds a delegation from z to child with the given NS hosts and
// glue. If withDS and the child is signed, a SHA-256 DS for its KSK is added.
func (z *Zone) Delegate(child *Zone, ns []string, glue map[string][]string, withDS bool) *Zone {
	c := child.Name
	z.cuts[c] = true
	for _, h := range ns {
		z.Add(dnswire.RR{Name: c, Type: dnswire.TypeNS, TTL: 86400, Data: &dnswire.NS{Host: dnswire.CanonicalName(h)}})
	}
	for h, addrs := range glue {
		z.Addr(h, addrs...)
	}
	if withDS && child.KSK != nil {
		ds, err := dnssec.ComputeDS(c, child.KSK.DNSKEY, dnssec.DigestSHA256)
		if err != nil {
			panic(err)
		}
		z.Add(dnswire.RR{Name: c, Type: dnswire.TypeDS, TTL: 86400, Data: ds})
	}
	return z
}

// isGlueOrDelegation reports whether (name, t) is non-authoritative data.
func (z *Zone) isGlueOrDelegation(name string, t dnswire.Type) bool {
	for c := range z.cuts {
		if dnswire.IsSubdomain(name, c) {
			if name == c && t == dnswire.TypeDS {
				return false
			}
			return true
		}
	}
	return false
}

// Sign (re)signs every authoritative RRset with the given validity window.
func (z *Zone) Sign(inception, expiration time.Time) *Zone {
	if z.KSK == nil {
		return z
	}
	z.sigs = map[key][]dnswire.RR{}
	for k, rrs := range z.records {
		if z.isGlueOrDelegation(k.name, k.t) {
			continue
		}
		signer := z.ZSK
		if k.t == dnswire.TypeDNSKEY {
			signer = z.KSK
		}
		sig := &dnswire.RRSIG{
			TypeCovered: k.t, Algorithm: signer.DNSKEY.Algorithm, Labels: uint8(dnswire.CountLabels(k.name)),
			OrigTTL: rrs[0].TTL, Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix()),
			KeyTag: dnssec.KeyTag(signer.DNSKEY), SignerName: z.Name,
		}
		if err := dnssec.Sign(rrs, sig, signer.Signer); err != nil {
			panic(err)
		}
		z.sigs[k] = []dnswire.RR{{Name: k.name, Type: dnswire.TypeRRSIG, Class: 1, TTL: rrs[0].TTL, Data: sig}}
	}
	return z
}

// Behavior alters how a server answers.
type Behavior int

// Server behaviors.
const (
	Normal         Behavior = iota
	Refuse                  // REFUSED for everything
	NonAuth                 // answers without the AA bit
	Down                    // times out
	ServFail                // SERVFAIL for everything
	Unreachable             // "network is unreachable" dial error
	UpwardReferral          // lame: NOERROR, no AA, referral to the root
)

// Server is an authoritative server hosting zones.
type Server struct {
	Zones    []*Zone
	Behavior Behavior
}

// Net is an in-memory network of servers keyed by address.
type Net struct {
	mu      sync.Mutex
	Servers map[netip.Addr]*Server
	Log     []string
}

// NewNet returns an empty network.
func NewNet() *Net { return &Net{Servers: map[netip.Addr]*Server{}} }

// Host attaches zones to the server at addr (creating it).
func (n *Net) Host(addr string, zones ...*Zone) *Server {
	a := netip.MustParseAddr(addr)
	s := n.Servers[a]
	if s == nil {
		s = &Server{}
		n.Servers[a] = s
	}
	s.Zones = append(s.Zones, zones...)
	return s
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Exchange implements transport.Exchanger.
func (n *Net) Exchange(ctx context.Context, ap netip.AddrPort, q *dnswire.Msg) (*dnswire.Msg, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	n.mu.Lock()
	s := n.Servers[ap.Addr()]
	n.Log = append(n.Log, fmt.Sprintf("%s %s %s", ap.Addr(), q.Question[0].Name, q.Question[0].Type))
	n.mu.Unlock()
	if s == nil || s.Behavior == Down {
		return nil, 0, &net.OpError{Op: "read", Net: "udp", Err: timeoutErr{}}
	}
	if s.Behavior == Unreachable {
		return nil, 0, &net.OpError{Op: "dial", Net: "udp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH}}
	}
	// Round-trip through the wire format to exercise packing/unpacking.
	wire, err := q.Pack()
	if err != nil {
		return nil, 0, err
	}
	q, err = dnswire.Unpack(wire)
	if err != nil {
		return nil, 0, err
	}
	r := s.answer(q)
	wire, err = r.Pack()
	if err != nil {
		return nil, 0, err
	}
	r, err = dnswire.Unpack(wire)
	return r, time.Millisecond, err
}

func (s *Server) answer(q *dnswire.Msg) *dnswire.Msg {
	r := &dnswire.Msg{Header: dnswire.Header{ID: q.ID, Response: true}, Question: q.Question}
	if q.EDNS != nil {
		r.EDNS = &dnswire.EDNS{UDPSize: 1232, DO: q.EDNS.DO}
	}
	switch s.Behavior {
	case Refuse:
		r.Rcode = dnswire.RcodeRefused
		return r
	case ServFail:
		r.Rcode = dnswire.RcodeServFail
		return r
	case UpwardReferral:
		r.Authority = []dnswire.RR{{Name: ".", Type: dnswire.TypeNS, Class: 1, TTL: 518400,
			Data: &dnswire.NS{Host: "a.root-servers.test."}}}
		return r
	}
	qn := dnswire.CanonicalName(q.Question[0].Name)
	qt := q.Question[0].Type
	do := q.EDNS != nil && q.EDNS.DO

	var cands []*Zone
	for _, z := range s.Zones {
		if dnswire.IsSubdomain(qn, z.Name) {
			cands = append(cands, z)
		}
	}
	if len(cands) == 0 {
		r.Rcode = dnswire.RcodeRefused
		return r
	}
	sort.Slice(cands, func(i, j int) bool { return dnswire.CountLabels(cands[i].Name) > dnswire.CountLabels(cands[j].Name) })
	z := cands[0]
	if qt == dnswire.TypeDS && qn == z.Name && len(cands) > 1 {
		z = cands[1] // DS lives in the parent
	}
	withSigs := func(rrs []dnswire.RR, k key) []dnswire.RR {
		if do {
			rrs = append(rrs, z.sigs[k]...)
		}
		return rrs
	}
	soa := func() []dnswire.RR {
		k := key{z.Name, dnswire.TypeSOA}
		return withSigs(append([]dnswire.RR(nil), z.records[k]...), k)
	}

	// Referral?
	for c := range z.cuts {
		if dnswire.IsSubdomain(qn, c) && !(qn == c && qt == dnswire.TypeDS) {
			nsk := key{c, dnswire.TypeNS}
			r.Authority = append(r.Authority, z.records[nsk]...)
			dsk := key{c, dnswire.TypeDS}
			if do {
				r.Authority = append(r.Authority, withSigs(append([]dnswire.RR(nil), z.records[dsk]...), dsk)...)
			}
			for _, ns := range z.records[nsk] {
				h := ns.Data.(*dnswire.NS).Host
				r.Additional = append(r.Additional, z.records[key{h, dnswire.TypeA}]...)
				r.Additional = append(r.Additional, z.records[key{h, dnswire.TypeAAAA}]...)
			}
			return r
		}
	}

	r.Authoritative = s.Behavior != NonAuth
	k := key{qn, qt}
	if rrs := z.records[k]; len(rrs) > 0 {
		r.Answer = withSigs(append([]dnswire.RR(nil), rrs...), k)
		return r
	}
	ck := key{qn, dnswire.TypeCNAME}
	if rrs := z.records[ck]; len(rrs) > 0 {
		r.Answer = withSigs(append([]dnswire.RR(nil), rrs...), ck)
		return r
	}
	exists := false
	for kk := range z.records {
		if dnswire.IsSubdomain(kk.name, qn) {
			exists = true
			break
		}
	}
	if !exists {
		r.Rcode = dnswire.RcodeNXDomain
	}
	r.Authority = soa()
	return r
}

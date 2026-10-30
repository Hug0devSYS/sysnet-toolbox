package ipmath

import (
	"fmt"
	"net/netip"
	"strings"
)

// SpecialBlock is an entry of the IANA special-purpose address registries
// (RFC 6890 and updates) or another well-known allocation.
type SpecialBlock struct {
	Prefix netip.Prefix
	Name   string
	RFC    string
	// Global is false when addresses from this block must not appear on the
	// public Internet.
	Global bool
}

// rawRange is PrefixRange without unmapping IPv4-mapped IPv6 prefixes
// (needed for ::ffff:0:0/96 itself).
func rawRange(p netip.Prefix) Range {
	if p.Addr().Is4() {
		return PrefixRange(p)
	}
	b := p.Masked().Addr().As16()
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	start := U128{hi, lo}
	return Range{Start: start, End: start.Or(LowMask(128 - p.Bits())), V6: true}
}

var special = func() []SpecialBlock {
	raw := []struct {
		p, name, rfc string
		global       bool
	}{
		{"0.0.0.0/8", "\"this network\"", "RFC 791", false},
		{"10.0.0.0/8", "private-use", "RFC 1918", false},
		{"100.64.0.0/10", "shared address space (CGNAT)", "RFC 6598", false},
		{"127.0.0.0/8", "loopback", "RFC 1122", false},
		{"169.254.0.0/16", "link-local", "RFC 3927", false},
		{"172.16.0.0/12", "private-use", "RFC 1918", false},
		{"192.0.0.0/24", "IETF protocol assignments", "RFC 6890", false},
		{"192.0.0.8/32", "IPv4 dummy address", "RFC 7600", false},
		{"192.0.0.170/31", "NAT64/DNS64 discovery", "RFC 7050", false},
		{"192.0.2.0/24", "documentation (TEST-NET-1)", "RFC 5737", false},
		{"192.31.196.0/24", "AS112-v4", "RFC 7535", true},
		{"192.52.193.0/24", "AMT", "RFC 7450", true},
		{"192.88.99.0/24", "deprecated 6to4 relay anycast", "RFC 7526", false},
		{"192.168.0.0/16", "private-use", "RFC 1918", false},
		{"192.175.48.0/24", "direct delegation AS112 service", "RFC 7534", true},
		{"198.18.0.0/15", "benchmarking", "RFC 2544", false},
		{"198.51.100.0/24", "documentation (TEST-NET-2)", "RFC 5737", false},
		{"203.0.113.0/24", "documentation (TEST-NET-3)", "RFC 5737", false},
		{"224.0.0.0/4", "multicast", "RFC 5771", false},
		{"240.0.0.0/4", "reserved", "RFC 1112", false},
		{"255.255.255.255/32", "limited broadcast", "RFC 919", false},
		{"::/128", "unspecified address", "RFC 4291", false},
		{"::1/128", "loopback", "RFC 4291", false},
		{"::ffff:0:0/96", "IPv4-mapped", "RFC 4291", false},
		{"64:ff9b::/96", "NAT64 well-known prefix", "RFC 6052", true},
		{"64:ff9b:1::/48", "local-use NAT64", "RFC 8215", false},
		{"100::/64", "discard-only", "RFC 6666", false},
		{"2001::/23", "IETF protocol assignments", "RFC 2928", false},
		{"2001::/32", "TEREDO", "RFC 4380", true},
		{"2001:db8::/32", "documentation", "RFC 3849", false},
		{"2002::/16", "6to4", "RFC 3056", true},
		{"3fff::/20", "documentation", "RFC 9637", false},
		{"5f00::/16", "SRv6 SIDs", "RFC 9602", false},
		{"fc00::/7", "unique local (ULA)", "RFC 4193", false},
		{"fe80::/10", "link-local unicast", "RFC 4291", false},
		{"ff00::/8", "multicast", "RFC 4291", false},
	}
	out := make([]SpecialBlock, 0, len(raw))
	for _, r := range raw {
		out = append(out, SpecialBlock{netip.MustParsePrefix(r.p), r.name, r.rfc, r.global})
	}
	return out
}()

// Classify returns the most specific special-purpose block containing p,
// or a synthetic "global unicast" block, or ok=false when p is larger than
// every block that intersects it (e.g. 0.0.0.0/0).
func Classify(p netip.Prefix) (SpecialBlock, bool) {
	p = Canonical(p)
	pr := PrefixRange(p)
	best := -1
	for i, s := range special {
		if rawRange(s.Prefix).Contains(pr) && (best < 0 || s.Prefix.Bits() > special[best].Prefix.Bits()) {
			best = i
		}
	}
	if best >= 0 {
		return special[best], true
	}
	for _, s := range special {
		if pr.Overlaps(rawRange(s.Prefix)) {
			return SpecialBlock{}, false
		}
	}
	if p.Addr().Is6() {
		gua := netip.MustParsePrefix("2000::/3")
		if !PrefixRange(gua).Contains(pr) {
			return SpecialBlock{Prefix: netip.MustParsePrefix("::/0"), Name: "unassigned / reserved by IETF", RFC: "RFC 4291", Global: false}, true
		}
		return SpecialBlock{Prefix: gua, Name: "global unicast", RFC: "RFC 4291", Global: true}, true
	}
	return SpecialBlock{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Name: "global unicast", Global: true}, true
}

// ReverseZones describes the reverse DNS zones covering a prefix.
type ReverseZones struct {
	Zones []string `json:"zones"`
	// Total is the number of zones (Zones may be truncated).
	Total U128 `json:"total"`
	// Classless is set when the prefix is smaller than one zone and
	// needs RFC 2317 delegation (IPv4) or is not nibble-aligned (IPv6).
	Classless bool   `json:"classless"`
	Note      string `json:"note,omitempty"`
}

// ReverseDNSZones returns the in-addr.arpa / ip6.arpa zones covering p,
// listing at most limit zones.
func ReverseDNSZones(p netip.Prefix, limit int) ReverseZones {
	p = Canonical(p)
	v6 := p.Addr().Is6()
	step := 8
	if v6 {
		step = 4
	}
	l := p.Bits()
	var rz ReverseZones
	zoneLen := ((l + step - 1) / step) * step
	if !v6 && l > 24 {
		// Smaller than a /24: lives inside the parent /24 zone (RFC 2317).
		parent := netip.PrefixFrom(p.Addr(), 24).Masked()
		rz.Zones = []string{zoneName(parent.Addr(), 24, false)}
		rz.Total = FromUint64(1)
		if l < 32 {
			rz.Classless = true
			rz.Note = fmt.Sprintf("smaller than a /24: delegate with RFC 2317 classless CNAMEs inside %s", rz.Zones[0])
		}
		return rz
	}
	if v6 && l%4 != 0 {
		rz.Note = fmt.Sprintf("not nibble-aligned: covered by %d /%d zones", 1<<(zoneLen-l), zoneLen)
	}
	if !v6 && l%8 != 0 {
		rz.Note = fmt.Sprintf("not octet-aligned: covered by %d /%d zones", 1<<(zoneLen-l), zoneLen)
	}
	n := zoneLen - l
	rz.Total = Pow2(n)
	pr := PrefixRange(p)
	cur := pr.Start
	step128 := PrefixSize(zoneLen, v6)
	for i := 0; i < limit && (n >= 63 || uint64(i) < uint64(1)<<n); i++ {
		rz.Zones = append(rz.Zones, zoneName(ToAddr(cur, v6), zoneLen, v6))
		next, ovf := cur.Add(step128)
		if ovf || next.Cmp(pr.End) > 0 {
			break
		}
		cur = next
	}
	return rz
}

func zoneName(a netip.Addr, l int, v6 bool) string {
	var labels []string
	if v6 {
		b := a.As16()
		for i := 0; i < l/4; i++ {
			nib := b[i/2]
			if i%2 == 0 {
				nib >>= 4
			}
			labels = append(labels, fmt.Sprintf("%x", nib&0x0f))
		}
	} else {
		b := a.As4()
		for i := 0; i < l/8; i++ {
			labels = append(labels, fmt.Sprintf("%d", b[i]))
		}
	}
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	suffix := "in-addr.arpa"
	if v6 {
		suffix = "ip6.arpa"
	}
	if len(labels) == 0 {
		return suffix
	}
	return strings.Join(labels, ".") + "." + suffix
}

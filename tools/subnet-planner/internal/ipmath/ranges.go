package ipmath

import (
	"fmt"
	"net/netip"
	"sort"
)

// Range is an inclusive range of addresses of one family.
type Range struct {
	Start, End U128
	V6         bool
}

// Bits returns the address width of r's family (32 or 128).
func (r Range) Bits() int { return familyBits(r.V6) }

func familyBits(v6 bool) int {
	if v6 {
		return 128
	}
	return 32
}

// Count returns the number of addresses in r (saturating at MaxU128 for
// the whole IPv6 space).
func (r Range) Count() U128 {
	d, _ := r.End.Sub(r.Start)
	return d.SatAdd(U128{0, 1})
}

// Contains reports whether r fully contains o (same family).
func (r Range) Contains(o Range) bool {
	return r.V6 == o.V6 && r.Start.Cmp(o.Start) <= 0 && r.End.Cmp(o.End) >= 0
}

// Overlaps reports whether r and o share at least one address.
func (r Range) Overlaps(o Range) bool {
	return r.V6 == o.V6 && r.Start.Cmp(o.End) <= 0 && o.Start.Cmp(r.End) <= 0
}

// String formats r as "first-last".
func (r Range) String() string {
	return ToAddr(r.Start, r.V6).String() + "-" + ToAddr(r.End, r.V6).String()
}

// FromAddr converts an address to an integer. IPv4-mapped IPv6 addresses
// are treated as IPv4.
func FromAddr(a netip.Addr) (U128, bool) {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return U128{0, uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])}, false
	}
	b := a.As16()
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	return U128{hi, lo}, true
}

// ToAddr converts an integer back to an address of the given family.
func ToAddr(u U128, v6 bool) netip.Addr {
	if !v6 {
		v := uint32(u.Lo)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	var b [16]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(u.Hi >> (8 * (7 - i)))
		b[8+i] = byte(u.Lo >> (8 * (7 - i)))
	}
	return netip.AddrFrom16(b)
}

// PrefixRange returns the address range covered by p (host bits ignored).
func PrefixRange(p netip.Prefix) Range {
	p = Canonical(p)
	start, v6 := FromAddr(p.Addr())
	host := familyBits(v6) - p.Bits()
	return Range{Start: start, End: start.Or(LowMask(host)), V6: v6}
}

// Canonical unmaps IPv4-mapped addresses and clears host bits.
func Canonical(p netip.Prefix) netip.Prefix {
	a := p.Addr()
	bitsLen := p.Bits()
	if a.Is4In6() {
		a = a.Unmap()
		bitsLen -= 96
		if bitsLen < 0 {
			bitsLen = 0
		}
	}
	return netip.PrefixFrom(a, bitsLen).Masked()
}

// PrefixOf builds the prefix of length l starting at start.
func PrefixOf(start U128, l int, v6 bool) netip.Prefix {
	return netip.PrefixFrom(ToAddr(start, v6), l)
}

// PrefixSize returns the number of addresses in a prefix of length l.
func PrefixSize(l int, v6 bool) U128 { return Pow2(familyBits(v6) - l) }

// floorLog2Count returns the largest k with 2^k <= span+1, where span is
// End-Start of a range (so span+1 may be 2^128).
func floorLog2Count(span U128) int {
	if span == MaxU128 {
		return 128
	}
	c, _ := span.Inc()
	return c.BitLen() - 1
}

// ToPrefixes returns the minimal list of CIDR prefixes exactly covering r,
// in ascending order.
func (r Range) ToPrefixes() []netip.Prefix {
	var out []netip.Prefix
	bitsLen := r.Bits()
	cur := r.Start
	for {
		k := cur.TrailingZeros()
		if k > bitsLen {
			k = bitsLen
		}
		span, _ := r.End.Sub(cur)
		if m := floorLog2Count(span); m < k {
			k = m
		}
		out = append(out, PrefixOf(cur, bitsLen-k, r.V6))
		blockEnd := cur.Or(LowMask(k))
		if blockEnd.Cmp(r.End) >= 0 {
			return out
		}
		cur, _ = blockEnd.Inc()
	}
}

// SortRanges sorts ranges by family (IPv4 first), start, then end.
func SortRanges(rs []Range) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].V6 != rs[j].V6 {
			return !rs[i].V6
		}
		if c := rs[i].Start.Cmp(rs[j].Start); c != 0 {
			return c < 0
		}
		return rs[i].End.Cmp(rs[j].End) < 0
	})
}

// MergeRanges sorts rs and merges overlapping and adjacent ranges. The
// input slice is reordered; the result is a new slice.
func MergeRanges(rs []Range) []Range {
	if len(rs) == 0 {
		return nil
	}
	tmp := append([]Range(nil), rs...)
	SortRanges(tmp)
	out := []Range{tmp[0]}
	for _, r := range tmp[1:] {
		last := &out[len(out)-1]
		if last.V6 == r.V6 {
			next, ovf := last.End.Inc()
			if ovf || r.Start.Cmp(next) <= 0 {
				if r.End.Cmp(last.End) > 0 {
					last.End = r.End
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// Subtract returns the parts of from that are not covered by minus. Both
// inputs may be unsorted and overlapping; the result is merged and sorted.
func Subtract(from, minus []Range) []Range {
	base := MergeRanges(from)
	cut := MergeRanges(minus)
	var out []Range
	for _, b := range base {
		cur := b
		alive := true
		for _, m := range cut {
			if !alive {
				break
			}
			if m.V6 != cur.V6 || m.End.Cmp(cur.Start) < 0 {
				continue
			}
			if m.Start.Cmp(cur.End) > 0 {
				break
			}
			if m.Start.Cmp(cur.Start) > 0 {
				end, _ := m.Start.Sub(U128{0, 1})
				out = append(out, Range{Start: cur.Start, End: end, V6: cur.V6})
			}
			if m.End.Cmp(cur.End) >= 0 {
				alive = false
				break
			}
			cur.Start, _ = m.End.Inc()
		}
		if alive {
			out = append(out, cur)
		}
	}
	return out
}

// Aggregate returns the minimal list of prefixes covering exactly the same
// addresses as ps (IPv4 first, ascending).
func Aggregate(ps []netip.Prefix) []netip.Prefix {
	rs := make([]Range, 0, len(ps))
	for _, p := range ps {
		rs = append(rs, PrefixRange(p))
	}
	var out []netip.Prefix
	for _, r := range MergeRanges(rs) {
		out = append(out, r.ToPrefixes()...)
	}
	return out
}

// CommonSupernet returns the longest prefix containing both a and b (same
// family required).
func CommonSupernet(a, b netip.Prefix) (netip.Prefix, error) {
	ra, rb := PrefixRange(a), PrefixRange(b)
	if ra.V6 != rb.V6 {
		return netip.Prefix{}, fmt.Errorf("%s and %s are different address families", a, b)
	}
	bitsLen := ra.Bits()
	diff := ra.Start.Xor(rb.Start)
	l := diff.LeadingZeros() - (128 - bitsLen)
	ca, cb := Canonical(a), Canonical(b)
	if ca.Bits() < l {
		l = ca.Bits()
	}
	if cb.Bits() < l {
		l = cb.Bits()
	}
	start := ra.Start.And(LowMask(bitsLen - l).Not())
	return PrefixOf(start, l, ra.V6), nil
}

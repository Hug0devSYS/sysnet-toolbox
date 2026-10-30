package ipmath

import "net/netip"

// LooseResult describes a lossy aggregation.
type LooseResult struct {
	Prefixes []netip.Prefix
	// Extra is the number of addresses covered by Prefixes that were not
	// covered by the input, per family.
	ExtraV4, ExtraV6 U128
}

// LooseAggregate reduces ps to at most max prefixes per address family by
// repeatedly replacing two neighbouring prefixes with their common
// supernet, always choosing the merge that adds the fewest addresses not
// covered by the input (ties: more prefixes absorbed, then lowest
// address). Each step is optimal; the overall result is a greedy
// approximation. max <= 0 means exact aggregation only.
func LooseAggregate(ps []netip.Prefix, max int) LooseResult {
	exact := Aggregate(ps)
	var v4, v6 []netip.Prefix
	for _, p := range exact {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	var res LooseResult
	o4, e4 := looseFamily(v4, max)
	o6, e6 := looseFamily(v6, max)
	res.Prefixes = append(o4, o6...)
	res.ExtraV4, res.ExtraV6 = e4, e6
	return res
}

func looseFamily(list []netip.Prefix, max int) ([]netip.Prefix, U128) {
	var extra U128
	if max <= 0 || len(list) <= max {
		return list, extra
	}
	// Work on integer ranges of CIDR blocks; list is sorted and disjoint.
	rs := make([]Range, len(list))
	for i, p := range list {
		rs[i] = PrefixRange(p)
	}
	bitsLen := rs[0].Bits()
	blockLen := func(r Range) int { return bitsLen - floorLog2Count(mustSub(r.End, r.Start)) }
	for len(rs) > max {
		bestI, bestJ := -1, -1
		var bestSup Range
		var bestCost U128
		for i := 0; i+1 < len(rs); i++ {
			l := rs[i].Start.Xor(rs[i+1].Start).LeadingZeros() - (128 - bitsLen)
			host := LowMask(bitsLen - l)
			sr := Range{Start: rs[i].Start.And(host.Not()), V6: rs[i].V6}
			sr.End = sr.Start.Or(host)
			// The prefixes covered by the supernet form a contiguous run
			// around i, i+1.
			lo := i
			for lo > 0 && sr.Contains(rs[lo-1]) {
				lo--
			}
			hi := i + 1
			for hi+1 < len(rs) && sr.Contains(rs[hi+1]) {
				hi++
			}
			var covered U128
			for k := lo; k <= hi; k++ {
				covered = covered.SatAdd(rs[k].Count())
			}
			cost, _ := sr.Count().Sub(covered)
			better := bestI < 0
			if !better {
				switch c := cost.Cmp(bestCost); {
				case c < 0:
					better = true
				case c == 0 && hi-lo > bestJ-bestI:
					better = true
				}
			}
			if better {
				bestI, bestJ, bestSup, bestCost = lo, hi, sr, cost
			}
		}
		if bestI < 0 {
			break
		}
		extra = extra.SatAdd(bestCost)
		rs = append(rs[:bestI+1], rs[bestJ+1:]...)
		rs[bestI] = bestSup
		// Re-aggregate locally: the new block may complete a sibling pair,
		// and the merged parent may in turn complete another one.
		i := bestI
		for {
			merged := false
			if i > 0 && siblings(rs[i-1], rs[i], blockLen) {
				rs[i-1].End = rs[i].End
				rs = append(rs[:i], rs[i+1:]...)
				i--
				merged = true
			} else if i+1 < len(rs) && siblings(rs[i], rs[i+1], blockLen) {
				rs[i].End = rs[i+1].End
				rs = append(rs[:i+1], rs[i+2:]...)
				merged = true
			}
			if !merged {
				break
			}
		}
	}
	out := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		out[i] = PrefixOf(r.Start, blockLen(r), r.V6)
	}
	return out, extra
}

func mustSub(a, b U128) U128 {
	d, _ := a.Sub(b)
	return d
}

// siblings reports whether a and b are the two halves of one CIDR block.
func siblings(a, b Range, blockLen func(Range) int) bool {
	la := blockLen(a)
	if la == 0 || la != blockLen(b) {
		return false
	}
	next, ovf := a.End.Inc()
	if ovf || next != b.Start {
		return false
	}
	bitsLen := a.Bits()
	parentHost := LowMask(bitsLen - la + 1)
	return a.Start.And(parentHost) == (U128{})
}

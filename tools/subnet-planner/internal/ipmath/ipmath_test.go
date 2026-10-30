package ipmath

import (
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func pfx(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func TestU128(t *testing.T) {
	a := U128{0, ^uint64(0)}
	s, o := a.Inc()
	if o || s != (U128{1, 0}) {
		t.Fatalf("carry: %v %v", s, o)
	}
	if _, o := MaxU128.Inc(); !o {
		t.Fatal("overflow not detected")
	}
	if d, b := (U128{1, 0}).Sub(U128{0, 1}); b || d != a {
		t.Fatalf("borrow: %v", d)
	}
	if LowMask(70) != (U128{63, ^uint64(0)}) || LowMask(0) != (U128{}) || LowMask(128) != MaxU128 {
		t.Fatal("LowMask")
	}
	if Pow2(64) != (U128{1, 0}) || Pow2(3).Lo != 8 {
		t.Fatal("Pow2")
	}
	if MaxU128.String() != "340282366920938463463374607431768211455" {
		t.Fatal(MaxU128.String())
	}
	if (U128{}).TrailingZeros() != 128 || (U128{1, 0}).TrailingZeros() != 64 {
		t.Fatal("TrailingZeros")
	}
	if j, _ := Pow2(60).MarshalJSON(); string(j) != `"1152921504606846976"` {
		t.Fatalf("json: %s", j)
	}
	if j, _ := FromUint64(256).MarshalJSON(); string(j) != `256` {
		t.Fatalf("json: %s", j)
	}
	for _, v := range []U128{{}, FromUint64(256), Pow2(60), MaxU128, {12345, 678}} {
		j, _ := v.MarshalJSON()
		var back U128
		if err := back.UnmarshalJSON(j); err != nil || back != v {
			t.Fatalf("round trip %v: %v %v", v, back, err)
		}
	}
	var x U128
	if x.UnmarshalJSON([]byte(`"-1"`)) == nil || x.UnmarshalJSON([]byte(`"340282366920938463463374607431768211456"`)) == nil {
		t.Fatal("invalid values accepted")
	}
}

func TestAddrRoundTrip(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "10.1.2.3", "255.255.255.255", "::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::abcd:1"} {
		a := netip.MustParseAddr(s)
		u, v6 := FromAddr(a)
		if got := ToAddr(u, v6); got != a {
			t.Errorf("%s -> %v", s, got)
		}
	}
	if _, v6 := FromAddr(netip.MustParseAddr("::ffff:10.0.0.1")); v6 {
		t.Error("mapped address should be IPv4")
	}
}

func TestCanonical(t *testing.T) {
	if got := Canonical(netip.MustParsePrefix("::ffff:10.1.2.3/120")); got.String() != "10.1.2.0/24" {
		t.Fatal(got)
	}
	if got := Canonical(netip.MustParsePrefix("192.168.1.77/26")); got.String() != "192.168.1.64/26" {
		t.Fatal(got)
	}
}

func TestRangeToPrefixes(t *testing.T) {
	cases := []struct {
		from, to string
		want     []string
	}{
		{"10.0.0.0", "10.0.0.255", []string{"10.0.0.0/24"}},
		{"10.0.0.1", "10.0.0.6", []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"::/0"}},
		{"2001:db8::", "2001:db8:0:2:ffff:ffff:ffff:ffff", []string{"2001:db8::/63", "2001:db8:0:2::/64"}},
		{"255.255.255.254", "255.255.255.255", []string{"255.255.255.254/31"}},
	}
	for _, c := range cases {
		s, v6 := FromAddr(netip.MustParseAddr(c.from))
		e, _ := FromAddr(netip.MustParseAddr(c.to))
		got := strs(Range{s, e, v6}.ToPrefixes())
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s-%s: got %v want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestAggregate(t *testing.T) {
	got := strs(Aggregate(pfx(t,
		"10.0.1.0/24", "10.0.0.0/24", "10.0.2.0/23", "10.0.0.128/25", // nested + adjacent
		"2001:db8:1::/48", "2001:db8::/48", "192.168.0.0/24", "192.168.2.0/24")))
	want := []string{"10.0.0.0/22", "192.168.0.0/24", "192.168.2.0/24", "2001:db8::/47"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

// TestAggregateProperty compares Aggregate with a bitmap model on random
// sets inside a /22.
func TestAggregateProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	base := netip.MustParseAddr("172.20.0.0")
	bu, _ := FromAddr(base)
	for iter := 0; iter < 300; iter++ {
		var in []netip.Prefix
		var bitmap [1024]bool
		for n := r.Intn(12); n >= 0; n-- {
			l := 22 + r.Intn(11)
			off := uint64(r.Intn(1024)) &^ (uint64(1)<<(32-l) - 1)
			p := PrefixOf(U128{0, bu.Lo + off}, l, false)
			in = append(in, p)
			for k := uint64(0); k < uint64(1)<<(32-l); k++ {
				bitmap[off+k] = true
			}
		}
		out := Aggregate(in)
		var got [1024]bool
		for i, p := range out {
			if p != p.Masked() {
				t.Fatalf("non-canonical %v", p)
			}
			if i > 0 {
				// Minimality: two consecutive prefixes must not be mergeable siblings.
				a, b := out[i-1], p
				if a.Bits() == b.Bits() {
					sup, _ := CommonSupernet(a, b)
					if sup.Bits() == a.Bits()-1 {
						t.Fatalf("mergeable siblings %v %v", a, b)
					}
				}
			}
			rg := PrefixRange(p)
			for u := rg.Start.Lo; u <= rg.End.Lo; u++ {
				if got[u-bu.Lo] {
					t.Fatalf("overlap in output %v", out)
				}
				got[u-bu.Lo] = true
			}
		}
		if got != bitmap {
			t.Fatalf("coverage mismatch for %v -> %v", in, out)
		}
	}
}

func TestSubtract(t *testing.T) {
	from := []Range{PrefixRange(netip.MustParsePrefix("10.0.0.0/24"))}
	minus := []Range{
		PrefixRange(netip.MustParsePrefix("10.0.0.64/26")),
		PrefixRange(netip.MustParsePrefix("10.0.0.0/30")),
		PrefixRange(netip.MustParsePrefix("10.1.0.0/16")),
		PrefixRange(netip.MustParsePrefix("2001:db8::/32")),
	}
	var got []string
	for _, r := range Subtract(from, minus) {
		got = append(got, strs(r.ToPrefixes())...)
	}
	want := []string{"10.0.0.4/30", "10.0.0.8/29", "10.0.0.16/28", "10.0.0.32/27", "10.0.0.128/25"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if rest := Subtract(from, []Range{PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))}); len(rest) != 0 {
		t.Fatalf("expected nothing left: %v", rest)
	}
	whole := []Range{PrefixRange(netip.MustParsePrefix("::/0"))}
	rest := Subtract(whole, []Range{PrefixRange(netip.MustParsePrefix("::/1"))})
	if len(rest) != 1 || strs(rest[0].ToPrefixes())[0] != "8000::/1" {
		t.Fatalf("v6 tail: %v", rest)
	}
}

func TestCommonSupernet(t *testing.T) {
	cases := [][3]string{
		{"10.0.0.0/24", "10.0.1.0/24", "10.0.0.0/23"},
		{"10.0.0.0/24", "10.0.3.0/24", "10.0.0.0/22"},
		{"10.0.0.0/16", "10.0.3.0/24", "10.0.0.0/16"},
		{"0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"},
		{"2001:db8::/64", "2001:db8:0:ff::/64", "2001:db8::/56"},
	}
	for _, c := range cases {
		got, err := CommonSupernet(netip.MustParsePrefix(c[0]), netip.MustParsePrefix(c[1]))
		if err != nil || got.String() != c[2] {
			t.Errorf("%s + %s = %v (%v), want %s", c[0], c[1], got, err, c[2])
		}
	}
	if _, err := CommonSupernet(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::/0")); err == nil {
		t.Error("expected family error")
	}
}

func TestLooseAggregate(t *testing.T) {
	in := pfx(t, "10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.4.0/24", "10.0.5.0/24", "10.0.100.0/24")
	res := LooseAggregate(in, 0)
	if !reflect.DeepEqual(strs(res.Prefixes), []string{"10.0.0.0/23", "10.0.2.0/24", "10.0.4.0/23", "10.0.100.0/24"}) {
		t.Fatalf("exact: %v", strs(res.Prefixes))
	}
	res = LooseAggregate(in, 2)
	// Cheapest: 10.0.0.0/23 + 10.0.2.0/24 -> /22 (+256), then /22 + 10.0.4.0/23 -> /21 (+512).
	if !reflect.DeepEqual(strs(res.Prefixes), []string{"10.0.0.0/21", "10.0.100.0/24"}) || res.ExtraV4.Lo != 768 {
		t.Fatalf("loose: %v extra %v", strs(res.Prefixes), res.ExtraV4)
	}
	res = LooseAggregate(in, 1)
	if !reflect.DeepEqual(strs(res.Prefixes), []string{"10.0.0.0/17"}) {
		t.Fatalf("loose1: %v", strs(res.Prefixes))
	}
	// Coverage invariant: every input stays covered.
	for _, p := range in {
		ok := false
		for _, q := range res.Prefixes {
			if PrefixRange(q).Contains(PrefixRange(p)) {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("%v lost", p)
		}
	}
	// Families are limited independently.
	res = LooseAggregate(pfx(t, "10.0.0.0/24", "10.0.2.0/24", "2001:db8::/48", "2001:db8:2::/48"), 1)
	if !reflect.DeepEqual(strs(res.Prefixes), []string{"10.0.0.0/22", "2001:db8::/46"}) {
		t.Fatalf("families: %v", strs(res.Prefixes))
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"10.20.0.0/16":       "private-use",
		"100.100.0.0/24":     "shared address space (CGNAT)",
		"192.0.2.0/25":       "documentation (TEST-NET-1)",
		"8.8.8.0/24":         "global unicast",
		"2001:db8:1::/48":    "documentation",
		"fd00:1::/64":        "unique local (ULA)",
		"2a01:4f8::/32":      "global unicast",
		"192.0.0.8/32":       "IPv4 dummy address",
		"2001:0:1::/48":      "TEREDO",
		"6000::/3":           "unassigned / reserved by IETF",
		"255.255.255.255/32": "limited broadcast",
	}
	for p, want := range cases {
		got, ok := Classify(netip.MustParsePrefix(p))
		if !ok || got.Name != want {
			t.Errorf("%s: %q %v", p, got.Name, ok)
		}
	}
	if _, ok := Classify(netip.MustParsePrefix("0.0.0.0/0")); ok {
		t.Error("0/0 should be unclassified")
	}
}

func TestReverseZones(t *testing.T) {
	cases := []struct {
		p         string
		zones     string
		classless bool
	}{
		{"10.1.2.0/24", "2.1.10.in-addr.arpa", false},
		{"10.1.0.0/16", "1.10.in-addr.arpa", false},
		{"10.1.4.0/22", "4.1.10.in-addr.arpa 5.1.10.in-addr.arpa 6.1.10.in-addr.arpa 7.1.10.in-addr.arpa", false},
		{"192.0.2.64/26", "2.0.192.in-addr.arpa", true},
		{"2001:db8::/32", "8.b.d.0.1.0.0.2.ip6.arpa", false},
		{"2001:db8:a0::/46", "0.a.0.0.8.b.d.0.1.0.0.2.ip6.arpa 1.a.0.0.8.b.d.0.1.0.0.2.ip6.arpa 2.a.0.0.8.b.d.0.1.0.0.2.ip6.arpa 3.a.0.0.8.b.d.0.1.0.0.2.ip6.arpa", false},
		{"0.0.0.0/0", "in-addr.arpa", false},
	}
	for _, c := range cases {
		rz := ReverseDNSZones(netip.MustParsePrefix(c.p), 16)
		if got := strings.Join(rz.Zones, " "); got != c.zones || rz.Classless != c.classless {
			t.Errorf("%s: %q classless=%v", c.p, got, rz.Classless)
		}
	}
	rz := ReverseDNSZones(netip.MustParsePrefix("10.0.0.0/9"), 3)
	if len(rz.Zones) != 3 || rz.Total.Lo != 128 {
		t.Fatalf("truncation: %v %v", rz.Zones, rz.Total)
	}
}

// TestLooseProperty checks on random inputs that the lossy result covers
// every input, respects the limit, stays canonical and minimal, and that
// the reported extra space is exact.
func TestLooseProperty(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for iter := 0; iter < 300; iter++ {
		var in []netip.Prefix
		for n := 2 + r.Intn(30); n > 0; n-- {
			l := 16 + r.Intn(17)
			a := U128{0, uint64(r.Uint32())}
			in = append(in, PrefixOf(a.And(LowMask(32-l).Not()), l, false))
		}
		max := 1 + r.Intn(6)
		res := LooseAggregate(in, max)
		if len(res.Prefixes) > max {
			t.Fatalf("limit %d exceeded: %v", max, res.Prefixes)
		}
		if again := Aggregate(res.Prefixes); len(again) != len(res.Prefixes) {
			t.Fatalf("output not minimal: %v", res.Prefixes)
		}
		var inSum, outSum uint64
		for _, p := range Aggregate(in) {
			inSum += PrefixRange(p).Count().Lo
		}
		for _, p := range res.Prefixes {
			outSum += PrefixRange(p).Count().Lo
		}
		if outSum-inSum != res.ExtraV4.Lo {
			t.Fatalf("extra %v, want %d", res.ExtraV4, outSum-inSum)
		}
		for _, p := range in {
			ok := false
			for _, q := range res.Prefixes {
				ok = ok || PrefixRange(q).Contains(PrefixRange(p))
			}
			if !ok {
				t.Fatalf("%v not covered by %v", p, res.Prefixes)
			}
		}
	}
}

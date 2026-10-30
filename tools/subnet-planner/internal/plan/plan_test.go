package plan

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
)

func reqs(t *testing.T, ss ...string) []Request {
	t.Helper()
	var out []Request
	for i, s := range ss {
		r, err := ParseRequest(s, i)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func byName(res Result) map[string]Allocation {
	m := map[string]Allocation{}
	for _, a := range res.Allocations {
		m[a.Name] = a
	}
	return m
}

func TestPrefixLenFor(t *testing.T) {
	cases := []struct {
		hosts int64
		v6    bool
		opt   Options
		want  int
	}{
		{1, false, Options{}, 30},
		{2, false, Options{}, 30},
		{2, false, Options{Allow31: true}, 31},
		{1, false, Options{Allow31: true}, 32},
		{3, false, Options{}, 29},
		{6, false, Options{}, 29},
		{7, false, Options{}, 28},
		{254, false, Options{}, 24},
		{255, false, Options{}, 23},
		{100, false, Options{Growth: 30}, 25},  // 130 -> /24? no: 130 > 126 -> /24
		{100, false, Options{Reserve: 27}, 24}, // 127 > 126
		{200, true, Options{V6Len: 64}, 64},
		{200, true, Options{}, 120},
		{256, true, Options{}, 120},
		{257, true, Options{}, 119},
	}
	cases[9].want = 24
	for _, c := range cases {
		got, _, err := PrefixLenFor(c.hosts, c.v6, c.opt)
		if err != nil || got != c.want {
			t.Errorf("hosts=%d v6=%v %+v: got /%d (%v), want /%d", c.hosts, c.v6, c.opt, got, err, c.want)
		}
	}
	if _, _, err := PrefixLenFor(1<<33, false, Options{}); err == nil {
		t.Error("expected IPv4 overflow error")
	}
}

func TestClassicVLSM(t *testing.T) {
	res, err := Plan(netip.MustParsePrefix("192.168.10.0/24"), nil,
		reqs(t, "sales=50", "eng=100", "wan1=2", "mgmt=10", "wan2=/30"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(res)
	want := map[string]string{"eng": "192.168.10.0/25", "sales": "192.168.10.128/26", "mgmt": "192.168.10.192/28",
		"wan1": "192.168.10.208/30", "wan2": "192.168.10.212/30"}
	for n, p := range want {
		if m[n].Prefix.String() != p {
			t.Errorf("%s: got %v want %s", n, m[n].Prefix, p)
		}
	}
	if res.Failed() != 0 || res.MinParentLen != 24 {
		t.Fatalf("failed=%d minparent=%d", res.Failed(), res.MinParentLen)
	}
	e := m["eng"]
	if e.Netmask != "255.255.255.128" || e.FirstUsable != "192.168.10.1" || e.LastUsable != "192.168.10.126" ||
		e.Broadcast != "192.168.10.127" || e.Gateway != "192.168.10.1" || e.Usable.Lo != 126 {
		t.Errorf("details: %+v", e)
	}
	// Output keeps input order.
	if res.Allocations[0].Name != "sales" {
		t.Error("order")
	}
}

func TestUsedAndBestFit(t *testing.T) {
	used := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/25"), netip.MustParsePrefix("10.0.1.0/24"), netip.MustParsePrefix("192.168.0.0/16")}
	res, err := Plan(netip.MustParsePrefix("10.0.0.0/22"), used, reqs(t, "big=/24", "small=/27"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(res)
	// big goes to the first free /24 (10.0.2.0); small fills the hole next
	// to the used /25 instead of breaking 10.0.3.0/24.
	if m["big"].Prefix.String() != "10.0.2.0/24" || m["small"].Prefix.String() != "10.0.0.128/27" {
		t.Fatalf("%v %v", m["big"].Prefix, m["small"].Prefix)
	}
	if len(res.InUse) != 2 {
		t.Errorf("in use outside the parent must be ignored: %v", res.InUse)
	}
	var free []string
	for _, p := range res.Free {
		free = append(free, p.String())
	}
	if strings.Join(free, " ") != "10.0.0.160/27 10.0.0.192/26 10.0.3.0/24" {
		t.Errorf("free: %v", free)
	}
}

func TestDoesNotFit(t *testing.T) {
	res, err := Plan(netip.MustParsePrefix("10.0.0.0/24"), nil, reqs(t, "a=200", "b=100", "c=/16"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(res)
	if m["a"].Prefix.String() != "10.0.0.0/24" || m["b"].OK() || m["c"].OK() || res.Failed() != 2 {
		t.Fatalf("%+v", res.Allocations)
	}
	if !strings.Contains(m["c"].Error, "larger than the parent") {
		t.Error(m["c"].Error)
	}
	if res.MinParentLen != 15 {
		t.Errorf("min parent: /%d", res.MinParentLen)
	}
}

func TestIPv6(t *testing.T) {
	res, err := Plan(netip.MustParsePrefix("2001:db8:42::/48"), nil, reqs(t, "lan=200", "p2p=/127", "odd=/80", "site=/56"), Options{V6Len: 64})
	if err != nil {
		t.Fatal(err)
	}
	m := byName(res)
	if m["site"].Prefix.String() != "2001:db8:42::/56" || m["lan"].Prefix.String() != "2001:db8:42:100::/64" {
		t.Fatalf("%+v", res.Allocations)
	}
	if m["odd"].Warning == "" || m["p2p"].Warning != "" || m["lan"].Warning != "" {
		t.Error("v6 warnings")
	}
	if m["p2p"].Gateway != "" || m["p2p"].FirstUsable != m["p2p"].Prefix.Addr().String() {
		t.Errorf("/127: %+v", m["p2p"])
	}
	if m["lan"].FirstUsable != "2001:db8:42:100::1" {
		t.Errorf("first usable must skip the subnet-router anycast address: %s", m["lan"].FirstUsable)
	}
}

func TestInputOrderAndErrors(t *testing.T) {
	res, _ := Plan(netip.MustParsePrefix("10.0.0.0/24"), nil, reqs(t, "a=/28", "b=/25"), Options{InputOrder: true})
	m := byName(res)
	if m["a"].Prefix.String() != "10.0.0.0/28" || m["b"].Prefix.String() != "10.0.0.128/25" {
		t.Fatalf("%+v", res.Allocations)
	}
	if _, err := Plan(netip.MustParsePrefix("10.0.0.0/24"), nil, reqs(t, "a=/28", "a=/28"), Options{}); err == nil {
		t.Error("duplicate names")
	}
	if _, err := Plan(netip.MustParsePrefix("10.0.0.0/24"), nil, nil, Options{}); err != ErrNoRequests {
		t.Error("no requests")
	}
	res, _ = Plan(netip.MustParsePrefix("10.0.0.0/24"), nil, reqs(t, "x=/40"), Options{})
	if res.Allocations[0].OK() {
		t.Error("/40 in IPv4")
	}
}

// TestPackingProperty: largest-first best-fit packs any set of requests
// whose total is at most the (empty) parent, and never overlaps.
func TestPackingProperty(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	parent := netip.MustParsePrefix("10.0.0.0/20")
	for iter := 0; iter < 200; iter++ {
		var rs []Request
		budget := uint64(4096)
		for i := 0; budget > 0 && i < 40; i++ {
			l := 21 + rnd.Intn(12)
			if uint64(1)<<(32-l) > budget {
				continue
			}
			budget -= uint64(1) << (32 - l)
			rs = append(rs, Request{Name: string(rune('a'+i%26)) + string(rune('0'+i/26)), Len: l, Order: i})
		}
		res, err := Plan(parent, nil, rs, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Failed() != 0 {
			t.Fatalf("packing failed: %+v", res.Allocations)
		}
		var ranges []ipmath.Range
		total := uint64(0)
		for _, a := range res.Allocations {
			ranges = append(ranges, ipmath.PrefixRange(a.Prefix))
			total += uint64(1) << (32 - a.Prefix.Bits())
		}
		merged := ipmath.MergeRanges(ranges)
		sum := uint64(0)
		for _, r := range merged {
			sum += r.Count().Lo
		}
		if sum != total {
			t.Fatal("allocations overlap")
		}
	}
}

func TestReadRequests(t *testing.T) {
	in := "name,size,vlan,note\nusers,500,10,floor 1\n# comment\nvoice; /25 ;20\nmgmt /26 99 out of band\n\n"
	rs, err := ReadRequests(strings.NewReader(in), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 || rs[0].Hosts != 500 || rs[0].VLAN != "10" || rs[0].Note != "floor 1" ||
		rs[1].Len != 25 || rs[1].VLAN != "20" || rs[2].Note != "out of band" || rs[2].Order != 2 {
		t.Fatalf("%+v", rs)
	}
	if _, err := ReadRequests(strings.NewReader("a,10\nb,lots\n"), 0); err == nil {
		t.Error("bad size accepted")
	}
	if _, err := ParseRequest("noequals", 0); err == nil {
		t.Error("bad request accepted")
	}
	if h, _, err := ParseSize("120hosts"); err != nil || h != 120 {
		t.Error("hosts suffix")
	}
}

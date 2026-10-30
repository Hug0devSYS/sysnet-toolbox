package check

import (
	"strings"
	"testing"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/inventory"
)

func analyze(t *testing.T, data string, opt Options) Report {
	t.Helper()
	inv, err := inventory.Load("inv", strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(inv, opt)
}

func codes(r Report) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Code]++
	}
	return m
}

func TestCleanHierarchy(t *testing.T) {
	r := analyze(t, "prefix,status\n10.0.0.0/8,container\n10.1.0.0/16,container\n10.1.1.0/24,active\n10.1.2.0/24,active\n10.2.0.0/24,reserved\n", Options{})
	if len(r.Findings) != 0 || r.Worst() != Info {
		t.Fatalf("unexpected findings: %+v", r.Findings)
	}
}

func TestDuplicatesAndNesting(t *testing.T) {
	data := "prefix,status,vrf\n" +
		"10.0.0.0/16,container,\n" +
		"10.0.1.0/24,active,\n" +
		"10.0.1.0/24,active,\n" + // duplicate
		"10.0.1.64/26,active,\n" + // nested in assigned
		"10.0.1.0/24,active,BLUE\n" // other VRF: not a duplicate
	r := analyze(t, data, Options{})
	c := codes(r)
	if c["duplicate-prefix"] != 1 || c["nested-in-assigned"] != 1 || len(r.Findings) != 2 {
		t.Fatalf("%v", c)
	}
	if r.Worst() != Critical {
		t.Fatal("duplicate must be critical")
	}
	r = analyze(t, data, Options{Nesting: NestingAllow})
	if codes(r)["nested-in-assigned"] != 0 {
		t.Fatal("allow mode")
	}
	r = analyze(t, data, Options{Nesting: NestingDeny})
	n := 0
	for _, f := range r.Findings {
		if f.Code == "overlap" && f.Severity == Critical {
			n++
		}
	}
	if n != 2 { // /24 inside /16 and /26 inside /24 (the duplicate /24 is one node)
		t.Fatalf("deny mode: %+v", r.Findings)
	}
	r = analyze(t, data, Options{IgnoreVRF: true})
	for _, f := range r.Findings {
		if f.Code == "duplicate-prefix" && len(f.Refs) != 3 {
			t.Fatalf("ignore-vrf should merge VRFs: %+v", f)
		}
	}
	r = analyze(t, data, Options{CrossVRF: true})
	if codes(r)["cross-vrf-overlap"] != 3 { // BLUE /24 vs global /16, /24 and the /26 inside it
		t.Fatalf("cross-vrf: %+v", r.Findings)
	}
}

func TestFlatListWithoutStatus(t *testing.T) {
	r := analyze(t, "10.0.0.0/23 a\n10.0.1.0/24 b\n10.0.2.0/24 c\n10.0.2.5/24 d\n", Options{})
	c := codes(r)
	if c["overlap"] != 1 || c["duplicate-prefix"] != 1 || c["host-bits-set"] != 1 {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestParentWithoutStatus(t *testing.T) {
	r := analyze(t, "prefix,status\n10.0.0.0/16,\n10.0.1.0/24,active\n", Options{})
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Message, "no status") {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestAddresses(t *testing.T) {
	data := "address,role\n" +
		"10.0.1.1/24,\n10.0.1.1/24,\n" + // duplicate
		"10.0.1.10/24,vrrp\n10.0.1.10/24,vrrp\n" + // shared role: fine
		"10.0.1.0/24,\n10.0.1.255/24,\n" + // network, broadcast
		"10.0.1.20/16,\n" + // shorter mask
		"10.0.1.30/25,\n" + // longer mask in an active subnet
		"10.0.1.40/32,\n" + // host mask: loopback/VIP convention, fine
		"10.9.0.1/24,\n" + // orphan
		"2001:db8:1::/64,\n" + // subnet-router anycast
		"10.0.2.1,\n" // no mask inside a container: fine
	prefixes := "prefix,status\n10.0.0.0/16,container\n10.0.1.0/24,active\n2001:db8:1::/64,active\n"
	inv1, _ := inventory.Load("p", strings.NewReader(prefixes))
	inv2, _ := inventory.Load("a", strings.NewReader(data))
	inv1.Merge(inv2)
	r := Analyze(inv1, Options{})
	c := codes(r)
	want := map[string]int{"duplicate-address": 1, "reserved-address": 3, "mask-mismatch": 2, "orphan-address": 1}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("%s: got %d want %d (%+v)", k, c[k], v, r.Findings)
		}
	}
	if len(r.Findings) != 7 {
		t.Errorf("total %d: %+v", len(r.Findings), r.Findings)
	}
	// Without any prefix data, no orphan findings and the address's own
	// mask is used for the network/broadcast check.
	r = analyze(t, "address\n10.0.0.0/24\n10.0.0.5/24\n", Options{})
	if c := codes(r); c["orphan-address"] != 0 || c["reserved-address"] != 1 {
		t.Fatalf("%+v", r.Findings)
	}
	// An empty shared-role list makes every duplicate critical.
	r = analyze(t, "address,role\n10.0.0.5/24,anycast\n10.0.0.5/24,anycast\n", Options{SharedRoles: []string{}})
	if codes(r)["duplicate-address"] != 1 {
		t.Fatal("shared roles disabled")
	}
}

func TestMostSpecificLookup(t *testing.T) {
	// Siblings after the containing prefix must not hide it.
	data := "prefix,status\n10.0.0.0/16,container\n10.0.0.0/24,active\n10.0.0.0/26,active\n10.0.0.128/25,active\n10.0.1.0/24,active\n"
	addrs := "address\n10.0.0.70/24\n10.0.0.200/25\n10.0.0.5/26\n"
	inv, _ := inventory.Load("p", strings.NewReader(data))
	a, _ := inventory.Load("a", strings.NewReader(addrs))
	inv.Merge(a)
	r := Analyze(inv, Options{Nesting: NestingAllow})
	if len(r.Findings) != 0 {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestInvalidRows(t *testing.T) {
	r := analyze(t, "10.0.0.0/24\nfoo\n", Options{})
	if codes(r)["invalid-entry"] != 1 || r.Worst() != Warning {
		t.Fatalf("%+v", r.Findings)
	}
}

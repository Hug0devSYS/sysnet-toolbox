package doctor

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnssec"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/fakedns"
)

var testNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

const (
	rootAddr = "192.0.2.1"
	tld1     = "198.51.100.1"
	tld2     = "198.51.100.2"
	ns1Addr  = "203.0.113.1"
	ns2Addr  = "198.51.100.53"
)

type worldCfg struct {
	unsigned     bool // example.test. not signed
	noDS         bool // no DS for example.test. in test.
	badDS        bool // DS for an unrelated key
	childExp     time.Time
	ns2          func(*fakedns.Zone) *fakedns.Zone // variant served by ns2
	ns2Behavior  fakedns.Behavior
	extraChildNS bool
	wrongGlue    bool
	ipv6Unreach  bool
}

type world struct {
	net     *fakedns.Net
	anchors []*dnswire.DS
	zone    *fakedns.Zone
}

func newWorld(t *testing.T, c worldCfg) *world {
	t.Helper()
	inc := testNow.Add(-24 * time.Hour)
	exp := testNow.Add(21 * 24 * time.Hour)
	childExp := exp
	if !c.childExp.IsZero() {
		childExp = c.childExp
	}

	root := fakedns.NewZone(".", 2026100900, true).NS("a.root-servers.test.")
	tld := fakedns.NewZone("test.", 2026100900, true).NS("ns1.nic.test.", "ns2.nic.test.").
		Addr("ns1.nic.test.", tld1).Addr("ns2.nic.test.", tld2)
	zone := fakedns.NewZone("example.test.", 2026100901, !c.unsigned).
		NS("ns1.example.test.", "ns2.example.test.").
		Addr("ns1.example.test.", ns1Addr).Addr("ns2.example.test.", ns2Addr).
		Addr("www.example.test.", "203.0.113.80")
	if c.ipv6Unreach {
		zone.Addr("ns1.example.test.", "2001:db8::1")
	}
	if c.extraChildNS {
		zone.NS("ns3.example.test.").Addr("ns3.example.test.", "203.0.113.3")
	}

	root.Delegate(tld, []string{"ns1.nic.test.", "ns2.nic.test."},
		map[string][]string{"ns1.nic.test.": {tld1}, "ns2.nic.test.": {tld2}}, true)
	glue2 := ns2Addr
	if c.wrongGlue {
		glue2 = "198.51.100.99"
	}
	glue := map[string][]string{"ns1.example.test.": {ns1Addr}, "ns2.example.test.": {glue2}}
	if c.ipv6Unreach {
		glue["ns1.example.test."] = append(glue["ns1.example.test."], "2001:db8::1")
	}
	tld.Delegate(zone, []string{"ns1.example.test.", "ns2.example.test."}, glue, !c.noDS && !c.badDS)
	if c.badDS {
		other := fakedns.NewKey(true)
		ds, _ := dnssec.ComputeDS("example.test.", other.DNSKEY, dnssec.DigestSHA256)
		tld.Add(dnswire.RR{Name: "example.test.", Type: dnswire.TypeDS, TTL: 86400, Data: ds})
	}

	zone.Sign(inc, childExp)
	tld.Sign(inc, exp)
	root.Sign(inc, exp)

	n := fakedns.NewNet()
	n.Host(rootAddr, root)
	n.Host(tld1, tld)
	n.Host(tld2, tld)
	n.Host(ns1Addr, zone)
	z2 := zone
	if c.ns2 != nil {
		z2 = c.ns2(zone)
	}
	n.Host(ns2Addr, z2).Behavior = c.ns2Behavior
	if c.extraChildNS {
		n.Host("203.0.113.3", zone)
	}
	if c.ipv6Unreach {
		n.Host("2001:db8::1", zone).Behavior = fakedns.Unreachable
	}
	ds, err := dnssec.ComputeDS(".", root.KSK.DNSKEY, dnssec.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return &world{net: n, anchors: []*dnswire.DS{ds}, zone: zone}
}

func (w *world) doctor() *Doctor {
	r := NewResolver(w.net)
	r.Roots = []netip.Addr{netip.MustParseAddr(rootAddr)}
	return &Doctor{R: r, Opts: Options{DNSSEC: true, TrustAnchors: w.anchors, SigExpiryWarn: 7 * 24 * time.Hour, Now: func() time.Time { return testNow }}}
}

func diagnose(t *testing.T, c worldCfg, zone string) (*Report, error) {
	t.Helper()
	return newWorld(t, c).doctor().Diagnose(context.Background(), zone)
}

func has(rep *Report, check string, sev Severity, substr string) bool {
	for _, f := range rep.Findings {
		if f.Check == check && f.Severity == sev && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func dump(t *testing.T, rep *Report) {
	t.Helper()
	for _, f := range rep.Findings {
		t.Logf("%s [%s] %s", f.Severity, f.Check, f.Message)
	}
}

func TestHealthySignedZone(t *testing.T) {
	rep, err := diagnose(t, worldCfg{}, "Example.Test")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Errors != 0 || rep.Summary.Warnings != 0 || rep.Summary.Status != "ok" {
		dump(t, rep)
		t.Fatalf("expected clean report, got %+v", rep.Summary)
	}
	if rep.Zone != "example.test." || rep.ParentZone != "test." {
		t.Fatalf("zone/parent = %s/%s", rep.Zone, rep.ParentZone)
	}
	if len(rep.Delegation) != 2 || rep.Delegation[0].Child != "test." || rep.Delegation[1].Child != "example.test." || !rep.Delegation[1].HasDS {
		t.Fatalf("delegation = %+v", rep.Delegation)
	}
	if strings.Join(rep.ParentNS, ",") != "ns1.example.test.,ns2.example.test." || strings.Join(rep.ChildNS, ",") != strings.Join(rep.ParentNS, ",") {
		t.Fatalf("NS parent=%v child=%v", rep.ParentNS, rep.ChildNS)
	}
	if rep.DNSSEC.Status != DNSSECSecure || len(rep.DNSSEC.Chain) != 3 {
		t.Fatalf("dnssec = %+v", rep.DNSSEC)
	}
	for _, h := range rep.Nameservers {
		for _, a := range h.Addresses {
			if a.Status != StatusOK || a.Serial == nil || *a.Serial != 2026100901 {
				t.Fatalf("%s %+v", h.Name, a)
			}
		}
	}
	if !has(rep, CheckDNSSEC, SevInfo, "validates from the root") || !has(rep, CheckSOA, SevInfo, "2026100901") {
		dump(t, rep)
		t.Fatal("missing info findings")
	}
	if rep.Queries == 0 {
		t.Fatal("query counter not updated")
	}
}

func TestLameDelegations(t *testing.T) {
	cases := []struct {
		b    fakedns.Behavior
		want string
	}{
		{fakedns.Refuse, "answered REFUSED"},
		{fakedns.ServFail, "answered SERVFAIL"},
		{fakedns.NonAuth, "non-authoritative"},
		{fakedns.Down, "did not answer"},
	}
	for _, c := range cases {
		rep, err := diagnose(t, worldCfg{ns2Behavior: c.b}, "example.test.")
		if err != nil {
			t.Fatal(err)
		}
		if !has(rep, CheckLame, SevError, c.want) || rep.Summary.Status != "error" {
			dump(t, rep)
			t.Fatalf("behavior %d: missing %q", c.b, c.want)
		}
		// The healthy server keeps the DNSSEC chain valid.
		if rep.DNSSEC.Status != DNSSECSecure {
			t.Fatalf("behavior %d: dnssec %s", c.b, rep.DNSSEC.Status)
		}
	}
}

func TestNSMismatch(t *testing.T) {
	rep, err := diagnose(t, worldCfg{extraChildNS: true}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !has(rep, CheckNS, SevWarning, "only at child [ns3.example.test.]") {
		dump(t, rep)
		t.Fatal("NS mismatch not reported")
	}
	var ns3 *NSHost
	for i := range rep.Nameservers {
		if rep.Nameservers[i].Name == "ns3.example.test." {
			ns3 = &rep.Nameservers[i]
		}
	}
	if ns3 == nil || ns3.InParent || !ns3.InChild || ns3.Addresses[0].Status != StatusOK {
		t.Fatalf("ns3 = %+v", ns3)
	}
}

func TestSOASerialDrift(t *testing.T) {
	stale := func(z *fakedns.Zone) *fakedns.Zone {
		c := z.Clone()
		c.SetSerial(2026100801)
		return c.Sign(testNow.Add(-time.Hour), testNow.Add(20*24*time.Hour))
	}
	rep, err := diagnose(t, worldCfg{ns2: stale}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !has(rep, CheckSOA, SevWarning, "serves 2026100801, newest is 2026100901 (behind by 100)") {
		dump(t, rep)
		t.Fatal("drift not reported")
	}
}

func TestSerialArithmetic(t *testing.T) {
	if !serialNewer(1, 0xffffffff) || serialNewer(0xffffffff, 1) || serialNewer(5, 5) || !serialNewer(10, 5) {
		t.Fatal("RFC 1982 comparison wrong")
	}
}

func TestUnsignedZone(t *testing.T) {
	rep, err := diagnose(t, worldCfg{unsigned: true, noDS: true}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DNSSEC.Status != DNSSECInsecure || rep.Summary.Warnings != 0 || !has(rep, CheckDNSSEC, SevInfo, "not DNSSEC-signed") {
		dump(t, rep)
		t.Fatalf("dnssec = %+v", rep.DNSSEC)
	}
}

func TestIslandOfSecurity(t *testing.T) {
	rep, err := diagnose(t, worldCfg{noDS: true}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DNSSEC.Status != DNSSECInsecure || !has(rep, CheckDNSSEC, SevWarning, "island of security") {
		dump(t, rep)
		t.Fatal("island not reported")
	}
}

func TestBogusDS(t *testing.T) {
	rep, err := diagnose(t, worldCfg{badDS: true}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DNSSEC.Status != DNSSECBogus || !has(rep, CheckDNSSEC, SevError, "matches its DS") {
		dump(t, rep)
		t.Fatalf("dnssec = %+v", rep.DNSSEC)
	}
}

func TestExpiredAndExpiringSignatures(t *testing.T) {
	rep, err := diagnose(t, worldCfg{childExp: testNow.Add(-time.Hour)}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DNSSEC.Status != DNSSECBogus || !has(rep, CheckDNSSEC, SevError, "expired") {
		dump(t, rep)
		t.Fatal("expired signatures not reported as bogus")
	}
	rep, err = diagnose(t, worldCfg{childExp: testNow.Add(48 * time.Hour)}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DNSSEC.Status != DNSSECSecure || !has(rep, CheckDNSSEC, SevWarning, "expires in 48h0m0s") {
		dump(t, rep)
		t.Fatal("near expiry not reported")
	}
}

func TestWrongGlue(t *testing.T) {
	rep, err := diagnose(t, worldCfg{wrongGlue: true}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !has(rep, CheckGlue, SevWarning, "198.51.100.99") || !has(rep, CheckLame, SevError, "198.51.100.99") {
		dump(t, rep)
		t.Fatal("stale glue not reported")
	}
}

func TestIPv6UnreachableIsSkipped(t *testing.T) {
	rep, err := diagnose(t, worldCfg{ipv6Unreach: true}, "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Errors != 0 || !has(rep, CheckLame, SevInfo, "not tested") {
		dump(t, rep)
		t.Fatal("unreachable IPv6 should be skipped, not an error")
	}
}

func TestNXDomainAndNotApex(t *testing.T) {
	rep, err := diagnose(t, worldCfg{}, "missing.test.")
	if !errors.Is(err, ErrNXDomain) || !errors.Is(err, ErrOperational) || rep.Summary.Status != "error" {
		t.Fatalf("err = %v", err)
	}
	rep, err = diagnose(t, worldCfg{}, "www.example.test.")
	if !errors.Is(err, ErrNotZoneApex) || !has(rep, CheckDelegation, SevError, "enclosing zone is example.test.") {
		dump(t, rep)
		t.Fatalf("err = %v", err)
	}
}

func TestAllRootsDown(t *testing.T) {
	w := newWorld(t, worldCfg{})
	w.net.Servers[netip.MustParseAddr(rootAddr)].Behavior = fakedns.Down
	rep, err := w.doctor().Diagnose(context.Background(), "example.test.")
	if !errors.Is(err, ErrOperational) || errors.Is(err, ErrNXDomain) || rep.Error == "" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseTrustAnchors(t *testing.T) {
	in := `; comment
. 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
38696 8 2 683D2D0ACB8C9B712A1948B2 7F741219298D0A450D612C483AF444A4C0FB2B16
`
	ds, err := ParseTrustAnchors(in)
	if err != nil || len(ds) != 2 || ds[0].KeyTag != 20326 || ds[1].KeyTag != 38696 || len(ds[1].Digest) != 32 {
		t.Fatalf("got %v, %v", ds, err)
	}
	for _, bad := range []string{"", "example. IN DS 1 8 2 AA", "1 8 2 ZZ", "1 8"} {
		if _, err := ParseTrustAnchors(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if len(RootAnchors) != 2 || RootAnchors[0].KeyTag != 20326 {
		t.Fatal("built-in anchors wrong")
	}
}

func TestWriteText(t *testing.T) {
	rep, _ := diagnose(t, worldCfg{ns2Behavior: fakedns.Refuse}, "example.test.")
	var b strings.Builder
	WriteText(&b, rep, false)
	out := b.String()
	for _, want := range []string{"Zone: example.test.", "Delegation path", "ns2.example.test.", "DNSSEC: secure", "ERROR [lame-delegation]", "Result: ERROR"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("color codes emitted with color=false")
	}
}

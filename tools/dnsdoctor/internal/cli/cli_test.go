package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnssec"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/fakedns"
)

// world builds root -> test. -> example.test. with real signatures valid
// around the current time, and returns the network plus a trust anchor file.
func world(t *testing.T, ns2 fakedns.Behavior) (*fakedns.Net, string) {
	t.Helper()
	inc, exp := time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)
	root := fakedns.NewZone(".", 1, true).NS("a.root-servers.test.")
	tld := fakedns.NewZone("test.", 1, true).NS("ns1.nic.test.").Addr("ns1.nic.test.", "198.51.100.1")
	zone := fakedns.NewZone("example.test.", 7, true).NS("ns1.example.test.", "ns2.example.test.").
		Addr("ns1.example.test.", "203.0.113.1").Addr("ns2.example.test.", "198.51.100.53")
	root.Delegate(tld, []string{"ns1.nic.test."}, map[string][]string{"ns1.nic.test.": {"198.51.100.1"}}, true)
	tld.Delegate(zone, []string{"ns1.example.test.", "ns2.example.test."},
		map[string][]string{"ns1.example.test.": {"203.0.113.1"}, "ns2.example.test.": {"198.51.100.53"}}, true)
	zone.Sign(inc, exp)
	tld.Sign(inc, exp)
	root.Sign(inc, exp)
	n := fakedns.NewNet()
	n.Host("192.0.2.1", root)
	n.Host("198.51.100.1", tld)
	n.Host("203.0.113.1", zone)
	n.Host("198.51.100.53", zone).Behavior = ns2

	ds, err := dnssec.ComputeDS(".", root.KSK.DNSKEY, dnssec.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "anchors")
	if err := os.WriteFile(f, []byte("; test anchor\n. IN DS "+ds.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return n, f
}

func run(t *testing.T, n *fakedns.Net, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb, n)
	return code, out.String(), errb.String()
}

func TestJSONHealthy(t *testing.T) {
	n, anchors := world(t, fakedns.Normal)
	code, out, stderr := run(t, n, "example.test", "--json", "--roots", "192.0.2.1", "--trust-anchor", anchors)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr=%s\n%s", code, stderr, out)
	}
	var reps []struct {
		Zone    string                  `json:"zone"`
		Summary struct{ Status string } `json:"summary"`
		DNSSEC  struct{ Status string } `json:"dnssec"`
	}
	if err := json.Unmarshal([]byte(out), &reps); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(reps) != 1 || reps[0].Zone != "example.test." || reps[0].DNSSEC.Status != "secure" || reps[0].Summary.Status != "ok" {
		t.Fatalf("unexpected report: %+v", reps)
	}
}

func TestExitCodes(t *testing.T) {
	n, anchors := world(t, fakedns.Refuse)
	code, out, _ := run(t, n, "--roots", "192.0.2.1", "--trust-anchor", anchors, "--color", "never", "example.test.")
	if code != ExitCritical || !strings.Contains(out, "lame delegation") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	code, _, _ = run(t, n, "--roots", "192.0.2.1", "--no-dnssec", "nope.test.")
	if code != ExitCritical {
		t.Fatalf("NXDOMAIN exit %d", code)
	}
	n.Servers[mustAddr("192.0.2.1")].Behavior = fakedns.Down
	code, _, _ = run(t, n, "--roots", "192.0.2.1", "--retries", "0", "example.test.")
	if code != ExitUnknown {
		t.Fatalf("unreachable roots exit %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	n, _ := world(t, fakedns.Normal)
	for _, args := range [][]string{
		{},
		{"-4", "-6", "example.test."},
		{"--sig-warn", "soon", "example.test."},
		{"--roots", "not-an-ip", "example.test."},
		{"--trust-anchor", "/nonexistent/anchors", "example.test."},
		{"--timeout", "0s", "example.test."},
		{"--bogus-flag"},
	} {
		if code, _, _ := run(t, n, args...); code != ExitUnknown {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUnknown)
		}
	}
	if code, out, _ := run(t, n, "--version"); code != ExitOK || !strings.Contains(out, Version) {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, stderr := run(t, n, "--help"); code != ExitOK || !strings.Contains(stderr, "Exit codes") {
		t.Errorf("--help: %d", code)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "1.5d": 36 * time.Hour, "72h": 72 * time.Hour, "0": 0} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1d", "xd", "-5h"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

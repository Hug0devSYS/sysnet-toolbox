package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/pmtu"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/probe"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/simpath"
)

var (
	v4  = netip.MustParseAddr("192.0.2.10")
	v6  = netip.MustParseAddr("2001:db8::10")
	rtr = netip.MustParseAddr("198.51.100.1")
)

type world struct {
	mu        sync.Mutex
	hops      map[netip.Addr][]simpath.Hop
	silent    map[probe.Method]bool
	noICMP    bool
	noRoute6  bool
	resolved  []netip.Addr
	methods   []probe.Method
	tcpCalls  int
	tcpResult probe.TCPInfo
}

func (w *world) deps() *Deps {
	return &Deps{
		Resolve: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if host == "nx.example" {
				return nil, errors.New("no such host")
			}
			var out []netip.Addr
			for _, a := range w.resolved {
				if network == "ip" || (network == "ip4" && a.Is4()) || (network == "ip6" && a.Is6()) {
					out = append(out, a)
				}
			}
			return out, nil
		},
		NewProber: func(a netip.Addr, m probe.Method, _ int) (probe.Prober, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.methods = append(w.methods, m)
			if m == probe.MethodICMP && w.noICMP {
				return nil, probe.ErrPermission
			}
			var hops []*simpath.Hop
			for _, h := range w.hops[a] {
				h := h
				hops = append(hops, &h)
			}
			return &simpath.Path{Dst: a, Meth: m, Hops: hops, Silent: w.silent[m]}, nil
		},
		Route: func(a netip.Addr) (probe.Route, error) {
			if a.Is6() && w.noRoute6 {
				return probe.Route{}, errors.New("network is unreachable")
			}
			return probe.Route{Local: a, Interface: "eth0", IfMTU: 1500, RouteMTU: 1500}, nil
		},
		TCP: func(context.Context, netip.Addr, int, time.Duration) (probe.TCPInfo, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.tcpCalls++
			return w.tcpResult, nil
		},
	}
}

func run(t *testing.T, w *world, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb, w.deps())
	return code, out.String(), errb.String()
}

func reports(t *testing.T, s string) []pmtu.Report {
	t.Helper()
	var r []pmtu.Report
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, s)
	}
	return r
}

func TestUsage(t *testing.T) {
	w := &world{}
	for _, args := range [][]string{
		{}, {"-4", "-6", "x"}, {"--method", "tcp", "x"}, {"--port", "0", "x"}, {"--max", "20", "x"},
		{"--timeout", "0s", "x"}, {"--retries", "-1", "x"}, {"--color", "pink", "x"}, {"--bogus"}, {"--tcp", "70000", "x"},
	} {
		if code, _, _ := run(t, w, args...); code != ExitUnknown {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	code, _, errs := run(t, w, "--help")
	if code != ExitOK || !strings.Contains(errs, "PMTUD black hole") || !strings.Contains(errs, "Exit codes") {
		t.Fatalf("help: %d %q", code, errs)
	}
	code, out, _ := run(t, w, "--version")
	if code != ExitOK || !strings.HasPrefix(out, "pmtud-probe ") {
		t.Fatal(out)
	}
}

func TestDualStackAndExitCodes(t *testing.T) {
	w := &world{
		resolved: []netip.Addr{v4, netip.MustParseAddr("192.0.2.11"), v6},
		hops: map[netip.Addr][]simpath.Hop{
			v4: {{Addr: rtr, MTU: 1400, SendPTB: true}},
			v6: {{Addr: netip.MustParseAddr("2001:db8::1"), MTU: 1400}}, // black hole
		},
	}
	code, out, _ := run(t, w, "--json", "dual.example")
	if code != ExitCritical {
		t.Fatalf("exit %d", code)
	}
	r := reports(t, out)
	if len(r) != 2 || r[0].Family != "ipv4" || r[0].PMTUD != pmtu.PMTUDWorking || r[1].Family != "ipv6" || r[1].PMTUD != pmtu.PMTUDBlackHole {
		t.Fatalf("%+v", r)
	}
	code, out, _ = run(t, w, "--json", "-4", "dual.example")
	if r = reports(t, out); code != ExitOK || len(r) != 1 || r[0].Address != v4.String() {
		t.Fatalf("exit %d %+v", code, r)
	}
}

func TestSkipFamilyWithoutRoute(t *testing.T) {
	w := &world{resolved: []netip.Addr{v4, v6}, noRoute6: true}
	code, out, errs := run(t, w, "--json", "dual.example")
	r := reports(t, out)
	if code != ExitOK || len(r) != 1 || r[0].Family != "ipv4" || !strings.Contains(errs, "skipping ipv6") {
		t.Fatalf("exit %d %+v %q", code, r, errs)
	}
	// An explicit IPv6 address without a route is UNKNOWN, not skipped.
	code, out, _ = run(t, w, "--json", "2001:db8::10")
	if r = reports(t, out); code != ExitUnknown || r[0].Status != pmtu.SevUnknown {
		t.Fatalf("exit %d %+v", code, r)
	}
}

func TestAutoFallsBackToUDP(t *testing.T) {
	w := &world{resolved: []netip.Addr{v4}, noICMP: true}
	code, out, _ := run(t, w, "--json", "h.example")
	if r := reports(t, out); code != ExitOK || r[0].Method != "udp" {
		t.Fatalf("exit %d %+v", code, r)
	}
	w = &world{resolved: []netip.Addr{v4}, silent: map[probe.Method]bool{probe.MethodICMP: true}, tcpResult: probe.TCPInfo{SndMSS: 1460, PMTU: 1500}}
	code, out, _ = run(t, w, "--json", "--tcp", "443", "h.example")
	r := reports(t, out)
	if code != ExitOK || r[0].Method != "udp" || r[0].Findings[0].Code != "method-fallback" || r[0].TCP == nil || r[0].TCP.Verdict != pmtu.MSSFits {
		t.Fatalf("exit %d %+v", code, r)
	}
	if w.tcpCalls != 1 {
		t.Fatalf("TCP handshake repeated %d times", w.tcpCalls)
	}
	// Forced method: no fallback.
	w = &world{resolved: []netip.Addr{v4}, noICMP: true}
	if code, _, _ = run(t, w, "--method", "icmp", "h.example"); code != ExitUnknown {
		t.Fatalf("exit %d", code)
	}
}

func TestResolveErrorsAndFamilies(t *testing.T) {
	w := &world{resolved: []netip.Addr{v4}}
	code, out, _ := run(t, w, "--json", "nx.example")
	if r := reports(t, out); code != ExitUnknown || !strings.Contains(r[0].Findings[0].Message, "cannot resolve") {
		t.Fatalf("exit %d %+v", code, r)
	}
	code, out, _ = run(t, w, "--json", "-6", "v4only.example")
	if r := reports(t, out); code != ExitUnknown || !strings.Contains(r[0].Findings[0].Message, "no IPv6 address") {
		t.Fatalf("exit %d %+v", code, r)
	}
	if code, _, _ = run(t, w, "-4", "[2001:db8::10]"); code != ExitUnknown {
		t.Fatalf("exit %d", code)
	}
}

func TestTargetsFileAndText(t *testing.T) {
	w := &world{hops: map[netip.Addr][]simpath.Hop{v4: {{Addr: rtr, MTU: 1420}}}}
	f := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(f, []byte("# fleet\n192.0.2.10   # edge\n\n192.0.2.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, w, "-f", f, "--timeout", "10ms", "--color", "never")
	if code != ExitCritical {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"192.0.2.10 (IPv4, icmp)  CRITICAL",
		"path MTU   1420 bytes",
		"PMTUD      black-hole",
		"no fragmentation-needed",
		"[CRIT] pmtud-black-hole",
		"192.0.2.20 (IPv4, icmp)  OK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Fatal("colour with --color never")
	}
	code, out, _ = run(t, w, "--color", "always", "192.0.2.20")
	if code != ExitOK || !strings.Contains(out, "\033[32mOK") {
		t.Fatalf("exit %d %q", code, out)
	}
	if code, _, _ := run(t, w, "-f", filepath.Join(t.TempDir(), "missing")); code != ExitUnknown {
		t.Fatal("missing file accepted")
	}
}

func TestStdinTargets(t *testing.T) {
	w := &world{}
	d := w.deps()
	d.Stdin = strings.NewReader("192.0.2.10\n192.0.2.11\n")
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"--json", "-f", "-"}, &out, &errb, d)
	if r := reports(t, out.String()); code != ExitOK || len(r) != 2 {
		t.Fatalf("exit %d %+v", code, r)
	}
}

func TestTextTCPLine(t *testing.T) {
	w := &world{hops: map[netip.Addr][]simpath.Hop{v4: {{Addr: rtr, MTU: 1400}}},
		tcpResult: probe.TCPInfo{SndMSS: 1448, Options: probe.TCPIOptTimestamps, PMTU: 1500}}
	code, out, _ := run(t, w, "--tcp", "443", "--timeout", "10ms", "192.0.2.10")
	if code != ExitCritical || !strings.Contains(out, "TCP/443    peer MSS >= 1460 (1500-byte segments) -> too-large") ||
		!strings.Contains(out, "[CRIT] mss-not-clamped") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

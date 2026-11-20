package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/ntptest"
)

func start(t *testing.T, b ntptest.Behaviour) *ntptest.Server {
	t.Helper()
	s, err := ntptest.Start(b)
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func gps(offset time.Duration) ntptest.Behaviour {
	return ntptest.Behaviour{Offset: offset, Stratum: 1, RefID: [4]byte{'G', 'P', 'S', 0}, RefAge: 16 * time.Second}
}

func testDeps() *Deps {
	return &Deps{
		LocalAddrs: func() []netip.Addr { return nil },
		Open:       func(string) (io.ReadCloser, error) { return nil, fs.ErrNotExist },
		Getenv:     func(string) string { return "" },
		IsTerminal: func(io.Writer) bool { return false },
	}
}

func run(t *testing.T, deps *Deps, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	if deps == nil {
		deps = testDeps()
	}
	code := Run(context.Background(), args, &out, &errb, deps)
	return code, out.String(), errb.String()
}

var fast = []string{"--samples", "2", "--interval", "0", "--timeout", "500ms"}

func TestEndToEndFalseticker(t *testing.T) {
	a := start(t, gps(0))
	b := start(t, gps(time.Millisecond))
	c := start(t, gps(-time.Millisecond))
	liar := start(t, gps(2*time.Second))
	prom := filepath.Join(t.TempDir(), "ntp.prom")
	args := append(append([]string{}, fast...), "--prom-file", prom,
		a.Addr.String(), b.Addr.String(), c.Addr.String(), liar.Addr.String())
	code, out, errs := run(t, nil, args...)
	if code != ExitCritical {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"falseticker", "truechimer", "3 truechimer(s), 1 falseticker(s)", "NTP-SKEW CRITICAL"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	data, err := os.ReadFile(prom)
	if err != nil {
		t.Fatal(err)
	}
	p := string(data)
	for _, want := range []string{
		fmt.Sprintf(`ntp_skew_server_falseticker{server="127.0.0.1",address="%s"} 1`, liar.Addr),
		"ntp_skew_truechimers 3", "ntp_skew_majority 1", "ntp_skew_status 2", "# TYPE ntp_skew_server_offset_seconds gauge",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("prom lacks %q:\n%s", want, p)
		}
	}
	if a.Requests() != 2 {
		t.Errorf("server a got %d requests, want 2", a.Requests())
	}

	// JSON output of the same ensemble.
	args = append(append([]string{"--json"}, fast...), a.Addr.String(), b.Addr.String(), c.Addr.String(), liar.Addr.String())
	code, out, _ = run(t, nil, args...)
	var rep struct {
		Status  string `json:"status"`
		Servers []struct {
			State  string   `json:"state"`
			Offset *float64 `json:"offset_seconds"`
		} `json:"servers"`
		Selection struct {
			Falsetickers int `json:"falsetickers"`
		} `json:"selection"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if code != ExitCritical || rep.Status != "CRITICAL" || rep.Selection.Falsetickers != 1 || rep.Servers[3].State != "falseticker" {
		t.Fatalf("json report: %d %+v", code, rep)
	}
	if off := *rep.Servers[3].Offset; off < 1.9 || off > 2.1 {
		t.Fatalf("liar offset %v", off)
	}
}

func TestHealthyAndMisbehaving(t *testing.T) {
	a := start(t, gps(0))
	b := start(t, gps(0))
	spoof := start(t, ntptest.Behaviour{Stratum: 1, RefID: [4]byte{'P', 'P', 'S', 0}, WrongOriginFirst: true})
	code, out, _ := run(t, nil, append(append([]string{}, fast...), a.Addr.String(), b.Addr.String(), spoof.Addr.String())...)
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "NTP-SKEW OK") || strings.Count(out, "truechimer\n") != 3 {
		t.Fatalf("output:\n%s", out)
	}

	rate := start(t, ntptest.Behaviour{KissCode: "RATE"})
	silent := start(t, ntptest.Behaviour{Silent: true})
	unsync := start(t, ntptest.Behaviour{Stratum: 16, Leap: 3, RefID: [4]byte{'I', 'N', 'I', 'T'}})
	init := start(t, ntptest.Behaviour{Leap: 3}) // stratum 0, empty refid (chrony before sync)
	code, out, _ = run(t, nil, append(append([]string{}, fast...), a.Addr.String(), rate.Addr.String(), silent.Addr.String(), unsync.Addr.String(), init.Addr.String())...)
	if code != ExitWarning || strings.Count(out, "unsynchronised\n") != 2 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"kiss-o-death", "rate limited", "unreachable", "unsynchronised", "no answer (timeout) (x2)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if rate.Requests() != 1 {
		t.Errorf("kept querying after RATE: %d requests", rate.Requests())
	}
}

func TestConfigSources(t *testing.T) {
	a := start(t, gps(0))
	b := start(t, gps(0))
	conf := fmt.Sprintf("# chrony\nserver %s port %d iburst\npool %s port %d\nrefclock PHC /dev/ptp0\n",
		a.Addr.Addr(), a.Addr.Port(), b.Addr.Addr(), b.Addr.Port())
	deps := testDeps()
	deps.Open = func(name string) (io.ReadCloser, error) {
		if name == "/etc/chrony/chrony.conf" || name == "my.conf" {
			return io.NopCloser(strings.NewReader(conf)), nil
		}
		return nil, fs.ErrNotExist
	}
	for _, mode := range [][]string{{"--config", "my.conf"}, {"--system"}} {
		code, out, errs := run(t, deps, append(append([]string{}, fast...), mode...)...)
		if code != ExitOK || strings.Count(out, "truechimer\n") != 2 {
			t.Fatalf("%v: exit %d\n%s\n%s", mode, code, out, errs)
		}
	}
	// --system with nothing installed.
	code, _, errs := run(t, nil, "--system")
	if code != ExitUnknown || !strings.Contains(errs, "no NTP client configuration") {
		t.Fatalf("--system empty: %d %s", code, errs)
	}
	// Missing explicit config file.
	code, _, errs = run(t, nil, "--config", "/nonexistent")
	if code != ExitUnknown || errs == "" {
		t.Fatalf("missing config: %d %s", code, errs)
	}
	// Targets from stdin, with a duplicate.
	deps = testDeps()
	deps.Stdin = strings.NewReader(a.Addr.String() + "\n# c\n" + a.Addr.String() + " " + b.Addr.String() + "\n")
	code, out, _ := run(t, deps, append(append([]string{}, fast...), "-f", "-")...)
	if code != ExitOK || strings.Count(out, "truechimer\n") != 2 {
		t.Fatalf("stdin: %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-4", "-6", "x.example"},
		{"--samples", "0", "x.example"},
		{"--warn", "2s", "--crit", "1s", "x.example"},
		{"--color", "pink", "x.example"},
		{"--max-stratum", "16", "x.example"},
		{"--timeout", "0s", "x.example"},
		{"bad|host"},
		{"--no-such-flag"},
	} {
		code, out, errs := run(t, nil, args...)
		if code != ExitUnknown || out != "" || errs == "" {
			t.Errorf("%v: exit %d out %q err %q", args, code, out, errs)
		}
	}
	if code, out, _ := run(t, nil, "--version"); code != ExitOK || !strings.HasPrefix(out, "ntp-skew ") {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, errs := run(t, nil, "--help"); code != ExitOK || !strings.Contains(errs, "Exit codes") {
		t.Errorf("--help: %d", code)
	}
}

func TestUnresolvedAndColor(t *testing.T) {
	a := start(t, gps(0))
	deps := testDeps()
	deps.Resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("no such host")
	}
	code, out, _ := run(t, deps, append(append([]string{"--color", "always"}, fast...), "missing.example", a.Addr.String())...)
	if code != ExitWarning || !strings.Contains(out, "unresolved") || !strings.Contains(out, "\x1b[") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	deps.Getenv = func(k string) string {
		if k == "NO_COLOR" {
			return "1"
		}
		return ""
	}
	deps.IsTerminal = func(io.Writer) bool { return true }
	_, out, _ = run(t, deps, append(append([]string{}, fast...), a.Addr.String())...)
	if strings.Contains(out, "\x1b[") {
		t.Fatal("NO_COLOR ignored")
	}
}

func TestInterruptKeepsPromFile(t *testing.T) {
	silent := start(t, ntptest.Behaviour{Silent: true})
	dir := t.TempDir()
	prom := filepath.Join(dir, "ntp.prom")
	if err := os.WriteFile(prom, []byte("previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	var out, errb bytes.Buffer
	start := time.Now()
	code := Run(ctx, []string{"--json", "--timeout", "30s", "--prom-file", prom, silent.Addr.String()}, &out, &errb, testDeps())
	if code != ExitUnknown || time.Since(start) > 5*time.Second {
		t.Fatalf("exit %d after %v", code, time.Since(start))
	}
	if !json.Valid(out.Bytes()) || !strings.Contains(errb.String(), "interrupted") {
		t.Fatalf("out %q err %q", out.String(), errb.String())
	}
	if data, _ := os.ReadFile(prom); string(data) != "previous\n" {
		t.Fatalf("prom file touched: %q", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("a\x1b[31mb\u009bc"); got != "a?[31mb?c" {
		t.Fatalf("sanitize %q", got)
	}
	if got := promEscape("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Fatalf("promEscape %q", got)
	}
}

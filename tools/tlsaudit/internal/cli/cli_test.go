package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/testpki"
)

func run(t *testing.T, deps *Deps, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb, deps)
	return code, out.String(), errb.String()
}

// fixture starts a healthy server and an expiring one and writes the test
// root to a PEM file.
func fixture(t *testing.T) (healthy, expiring, caFile string) {
	t.Helper()
	pki := testpki.NewPKI(t, testpki.Options{})
	healthy = testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert)}})
	soon := testpki.NewPKI(t, testpki.Options{NotAfter: time.Now().Add(12 * 24 * time.Hour)})
	expiring = testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{soon.TLSCert(soon.Inter.Cert)}})

	var pemData []byte
	for _, c := range []*testpki.Cert{pki.Root, soon.Root} {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})...)
	}
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

func TestJSONAndExitCodes(t *testing.T) {
	healthy, expiring, ca := fixture(t)
	code, out, stderr := run(t, nil, "--json", "--no-ciphers", "--ca-file", ca, "--ca-only",
		"www.example.test connect="+healthy)
	if code != ExitOK {
		t.Fatalf("exit %d stderr=%s\n%s", code, stderr, out)
	}
	var reps []struct {
		Name    string                  `json:"name"`
		Chain   struct{ Status string } `json:"chain"`
		Summary struct{ Status string } `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 1 {
		t.Fatalf("bad JSON %v\n%s", err, out)
	}
	if reps[0].Chain.Status != "trusted" || reps[0].Summary.Status != "ok" || reps[0].Name != "www.example.test:443" {
		t.Fatalf("%+v", reps[0])
	}

	// Expiring certificate -> WARNING; worst code wins across targets.
	code, out, _ = run(t, nil, "--no-ciphers", "--color", "never", "--ca-file", ca, "--ca-only",
		"www.example.test connect="+healthy, "www.example.test connect="+expiring)
	if code != ExitWarning || !strings.Contains(out, "expires in") || strings.Count(out, "Target:") != 2 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// Same with a stricter threshold -> CRITICAL.
	code, _, _ = run(t, nil, "--no-ciphers", "--crit-days", "14", "--ca-file", ca, "--ca-only", "www.example.test connect="+expiring)
	if code != ExitCritical {
		t.Fatalf("crit-days: exit %d", code)
	}
	// Untrusted without the CA file -> CRITICAL.
	code, _, _ = run(t, nil, "--no-ciphers", "www.example.test connect="+healthy)
	if code != ExitCritical {
		t.Fatalf("untrusted: exit %d", code)
	}
}

func TestTargetsFileSummaryAndProm(t *testing.T) {
	healthy, expiring, ca := fixture(t)
	list := "# fleet\nwww.example.test connect=" + healthy + "\n\nwww.example.test connect=" + expiring + " # expiring\n"
	prom := filepath.Join(t.TempDir(), "tls.prom")
	deps := &Deps{Stdin: strings.NewReader(list)}
	code, out, stderr := run(t, deps, "-f", "-", "--summary", "--no-ciphers", "--ca-file", ca, "--prom-file", prom)
	if code != ExitWarning {
		t.Fatalf("exit %d stderr=%s\n%s", code, stderr, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "OK") || !strings.HasPrefix(lines[2], "WARNING") {
		t.Fatalf("summary:\n%s", out)
	}
	data, err := os.ReadFile(prom)
	if err != nil || !strings.Contains(string(data), "tlsaudit_cert_expiry_seconds{") {
		t.Fatalf("prom file: %v\n%s", err, data)
	}

	// File on disk with a syntax error reports the line number.
	bad := filepath.Join(t.TempDir(), "targets.txt")
	_ = os.WriteFile(bad, []byte("ok.example\nbad host!\n"), 0o600)
	code, _, stderr = run(t, nil, "-f", bad)
	if code != ExitUnknown || !strings.Contains(stderr, "targets.txt:2") {
		t.Fatalf("exit %d %s", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-4", "-6", "example.test"},
		{"--json", "--summary", "example.test"},
		{"--timeout", "0s", "example.test"},
		{"--crit-days", "40", "example.test"},
		{"--ca-only", "example.test"},
		{"--ca-file", "/nonexistent/ca.pem", "example.test"},
		{"--color", "sometimes", "example.test"},
		{"-f", "/nonexistent/targets"},
		{"bad target!"},
		{"--bogus-flag"},
	} {
		if code, _, _ := run(t, nil, args...); code != ExitUnknown {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUnknown)
		}
	}
	if code, out, _ := run(t, nil, "--version"); code != ExitOK || !strings.Contains(out, Version) {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, stderr := run(t, nil, "--help"); code != ExitOK || !strings.Contains(stderr, "Exit codes") {
		t.Errorf("--help: %d", code)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not pem"), 0o600)
	if code, _, stderr := run(t, nil, "--ca-file", empty, "--ca-only", "example.test"); code != ExitUnknown || !strings.Contains(stderr, "no PEM") {
		t.Errorf("empty CA file: %d %s", code, stderr)
	}
}

func TestPromSeriesUniquePerConnectAddress(t *testing.T) {
	healthy, expiring, ca := fixture(t)
	prom := filepath.Join(t.TempDir(), "tls.prom")
	code, _, stderr := run(t, nil, "--no-ciphers", "--ca-file", ca, "--prom-file", prom,
		"www.example.test connect="+healthy, "www.example.test connect="+expiring)
	if code != ExitWarning {
		t.Fatalf("exit %d %s", code, stderr)
	}
	data, err := os.ReadFile(prom)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		series := l[:strings.LastIndexByte(l, ' ')]
		if seen[series] {
			t.Fatalf("duplicate series %q (node_exporter would reject the file)", series)
		}
		seen[series] = true
	}
	for _, addr := range []string{healthy, expiring} {
		if !strings.Contains(string(data), `connect="`+addr+`"`) {
			t.Fatalf("missing connect label for %s:\n%s", addr, data)
		}
	}
}

func TestDuplicateTargetsAuditedOnce(t *testing.T) {
	healthy, _, ca := fixture(t)
	spec := "www.example.test connect=" + healthy
	code, out, stderr := run(t, nil, "--summary", "--no-ciphers", "--ca-file", ca, spec, spec, "  "+spec+"  ")
	if code != ExitOK || strings.Count(strings.TrimSpace(out), "\n") != 1 || strings.Count(stderr, "ignoring duplicate target") != 2 {
		t.Fatalf("exit %d\nout=%s\nstderr=%s", code, out, stderr)
	}
}

func TestInterruptedRunIsUnknownAndKeepsPromFile(t *testing.T) {
	healthy, _, ca := fixture(t)
	prom := filepath.Join(t.TempDir(), "tls.prom")
	if err := os.WriteFile(prom, []byte("previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := Run(ctx, []string{"--no-ciphers", "--ca-file", ca, "--prom-file", prom, "www.example.test connect=" + healthy}, &out, &errb, nil)
	if code != ExitUnknown || !strings.Contains(errb.String(), "interrupted") {
		t.Fatalf("exit %d stderr=%s", code, errb.String())
	}
	if data, _ := os.ReadFile(prom); string(data) != "previous\n" {
		t.Fatalf("prom file overwritten after interruption: %q", data)
	}
}

func TestExpiryColourFollowsThresholds(t *testing.T) {
	_, expiring, ca := fixture(t) // expires in 12 days
	spec := "www.example.test connect=" + expiring
	_, out, _ := run(t, nil, "--no-ciphers", "--color", "always", "--ca-file", ca, spec)
	if !strings.Contains(out, "\033[33m11 days left") && !strings.Contains(out, "\033[33m12 days left") {
		t.Fatalf("default thresholds: expected yellow expiry\n%q", out)
	}
	_, out, _ = run(t, nil, "--no-ciphers", "--color", "always", "--crit-days", "14", "--warn-days", "20", "--ca-file", ca, spec)
	if !strings.Contains(out, "\033[31m1") {
		t.Fatalf("--crit-days 14: expected red expiry\n%q", out)
	}
	_, out, _ = run(t, nil, "--no-ciphers", "--color", "always", "--warn-days", "5", "--crit-days", "2", "--ca-file", ca, spec)
	if strings.Contains(out, "\033[33m1") || strings.Contains(out, "\033[31m1") {
		t.Fatalf("--warn-days 5: expiry must not be highlighted\n%q", out)
	}
}

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 13, 17, 0, 0, 0, time.UTC)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(stdin), Now: func() time.Time { return now }}
	code := Run(args, env)
	return code, out.String(), errb.String()
}

// sample writes a syslog file: 6h of traffic, an auth burst at 13:00 and,
// optionally, a new kernel error during the last 20 minutes.
func sample(t *testing.T, withNew bool) string {
	t.Helper()
	var b strings.Builder
	start := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	for m := 0; m < 360; m++ {
		ts := start.Add(time.Duration(m) * time.Minute).Format(time.Stamp)
		for i := 0; i < 4; i++ {
			fmt.Fprintf(&b, "<86>%s web%d sshd[%d]: Accepted publickey for u%d from 192.0.2.%d port %d ssh2\n", ts, i, 1000+m, i, m%250, 30000+m)
		}
		fmt.Fprintf(&b, "<78>%s web1 CRON[%d]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)\n", ts, 2000+m)
		if m >= 180 && m < 190 {
			for i := 0; i < 20; i++ {
				fmt.Fprintf(&b, "<36>%s web3 sshd[%d]: Failed password for invalid user u%d from 198.51.100.%d port %d ssh2\n", ts, 5000+i, i, i, 40000+i)
			}
		}
		if withNew && m >= 340 {
			fmt.Fprintf(&b, "<10>%s db1 kernel: EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0\n", ts)
		}
	}
	p := filepath.Join(t.TempDir(), "syslog")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(p, now, now)
	return p
}

func TestTextReport(t *testing.T) {
	code, out, errs := run(t, "", "--tz", "UTC", "--examples", sample(t, false))
	if code != ExitWarning {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	for _, want := range []string{
		"syslog-triage WARNING: 2,000 messages, 3 patterns, 4 hosts, 2 programs",
		"range    2026-11-13 10:00:00 .. 2026-11-13 15:59:00 (UTC), bucket 5m",
		"13:00-13:10  #3    warning  sshd",
		"Failed password for invalid user <*> from <IP> port <NUM> ssh2",
		"not evaluated: use --model FILE or --recent DURATION",
		"Accepted publickey for <*> from <IP> port <NUM> ssh2",
		"e.g. Accepted publickey for u0 from 192.0.2.0 port 30000 ssh2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestJSONAndRecent(t *testing.T) {
	code, out, _ := run(t, "", "--json", "--recent", "30m", sample(t, true))
	if code != ExitCritical {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var res struct {
		Version string
		Status  string
		Summary struct {
			Messages    int64
			NewPatterns int64 `json:"new_patterns"`
		}
		Spikes []struct {
			PatternID int `json:"pattern_id"`
			Alert     bool
		}
		NewPatterns []struct {
			App, Severity, Template string
			Count                   int64
		} `json:"new_patterns"`
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err, out)
	}
	if res.Version != Version || res.Status != "CRITICAL" || res.ExitCode != 2 || len(res.NewPatterns) != 1 ||
		res.NewPatterns[0].App != "kernel" || res.NewPatterns[0].Severity != "crit" || res.NewPatterns[0].Count != 20 || res.Summary.NewPatterns != 1 ||
		res.NewPatterns[0].Template != "EXT4-fs error (device sda1): ext4_find_entry:<NUM>: inode #<NUM>: comm ls: reading directory lblock <NUM>" {
		t.Fatalf("%+v", res)
	}
	for _, s := range res.Spikes {
		if s.PatternID == 3 {
			t.Fatal("old auth burst reported despite --recent")
		}
	}
}

func TestModelWorkflow(t *testing.T) {
	dir := t.TempDir()
	model := filepath.Join(dir, "model.json")
	code, _, errs := run(t, "", "--model", model, sample(t, false))
	if code != ExitUnknown || !strings.Contains(errs, "does not exist") {
		t.Fatalf("missing model without --update-model: %d %s", code, errs)
	}
	code, out, errs := run(t, "", "--model", model, "--update-model", "--quiet", sample(t, false))
	if code != ExitWarning || !strings.Contains(errs, "will be created") || !strings.Contains(out, "NEW PATTERNS (0)\n  none") {
		t.Fatalf("first run: %d\n%s%s", code, out, errs)
	}
	if st, err := os.Stat(model); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("model not written: %v", err)
	}
	before, _ := os.ReadFile(model)
	// Read-only use: the model is not modified, the new pattern is reported.
	code, out, _ = run(t, "", "--model", model, "--sim", "0.9", "--quiet", sample(t, true))
	if code != ExitCritical || !strings.Contains(out, "NEW PATTERNS (1)") || !strings.Contains(out, "3 patterns in model") {
		t.Fatalf("second run: %d\n%s", code, out)
	}
	after, _ := os.ReadFile(model)
	if !bytes.Equal(before, after) {
		t.Fatal("model modified without --update-model")
	}
	// Learn it, then it is known.
	run(t, "", "--model", model, "--update-model", sample(t, true))
	code, out, _ = run(t, "", "--model", model, "--quiet", "--recent", "30m", sample(t, true))
	if code != ExitOK || !strings.Contains(out, "NEW PATTERNS (0)") {
		t.Fatalf("third run: %d\n%s", code, out)
	}
	os.WriteFile(model, []byte("garbage"), 0o600)
	if code, _, errs := run(t, "", "--model", model, sample(t, false)); code != ExitUnknown || !strings.Contains(errs, "invalid model") {
		t.Fatalf("corrupt model: %d %s", code, errs)
	}
}

func TestStdinFormats(t *testing.T) {
	in := `{"__REALTIME_TIMESTAMP":"1794564001000000","_HOSTNAME":"h1","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"Connection closed by 192.0.2.1 port 22"}
<165>1 2026-11-13T10:00:00Z h2 app 12 ID1 - message from 5424 number 7
2026-11-13T10:00:01+01:00 h3 nginx[1]: high precision line 8
plain line without header
`
	code, out, _ := run(t, in, "--json", "--top", "0", "-")
	if code != ExitOK {
		t.Fatalf("exit %d %s", code, out)
	}
	var res struct {
		Summary  struct{ Messages, Unparsed, Hosts int64 }
		Patterns []struct{ App string }
	}
	json.Unmarshal([]byte(out), &res)
	if res.Summary.Messages != 4 || res.Summary.Unparsed != 1 || res.Summary.Hosts != 3 || len(res.Patterns) != 4 {
		t.Fatalf("%+v", res)
	}
}

func TestJournalMode(t *testing.T) {
	var gotArgs []string
	var out, errb bytes.Buffer
	line := fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","MESSAGE":"hello","SYSLOG_IDENTIFIER":"x","PRIORITY":"6"}`, now.Add(-time.Hour).UnixMicro())
	env := Env{Stdout: &out, Stderr: &errb, Now: func() time.Time { return now },
		Journal: func(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
			gotArgs = args
			return io.NopCloser(strings.NewReader(line + "\n")), func() error { return nil }, nil
		}}
	code := Run([]string{"--journal", "--since", "-2h", "--unit", "ssh.service", "--journal-dir", "/var/log/journal/remote", "--quiet"}, env)
	if code != ExitOK || !strings.Contains(out.String(), "1 messages, 1 pattern, 0 hosts, 1 program") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	want := fmt.Sprintf("-o json --no-pager -q --since=@%d --unit=ssh.service --directory=/var/log/journal/remote", now.Add(-2*time.Hour).Unix())
	if strings.Join(gotArgs, " ") != want {
		t.Fatalf("args %q", gotArgs)
	}
	// journalctl failure.
	env.Journal = func(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
		return io.NopCloser(strings.NewReader("")), func() error { return errors.New("exit status 1") }, nil
	}
	errb.Reset()
	if code := Run([]string{"--journal"}, env); code != ExitUnknown || !strings.Contains(errb.String(), "journalctl: exit status 1") {
		t.Fatalf("failure: %d %s", code, errb.String())
	}
	env.Journal = func(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
		return nil, nil, errors.New("executable file not found")
	}
	if code := Run([]string{"--journal"}, env); code != ExitUnknown {
		t.Fatalf("missing journalctl: %d", code)
	}
}

func TestJournalTimeout(t *testing.T) {
	var out, errb bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errb, Now: func() time.Time { return now },
		Journal: func(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
			<-ctx.Done()
			return io.NopCloser(strings.NewReader("")), func() error { return ctx.Err() }, nil
		}}
	if code := Run([]string{"--journal", "--timeout", "10ms"}, env); code != ExitUnknown || !strings.Contains(errb.String(), "timed out") {
		t.Fatalf("%d %s", code, errb.String())
	}
}

func TestUsageErrors(t *testing.T) {
	f := sample(t, false)
	for _, args := range [][]string{
		{"--bucket", "0s", f}, {"--sim", "2", f}, {"--depth", "2", f}, {"--sort", "x", f},
		{"--min-severity", "loud", f}, {"--app", "(", f}, {"--since", "yesterday-ish", f},
		{"--since", "2026-11-13", "--until", "2026-11-12", f}, {"--update-model", f}, {"--recent", "-5m", f},
		{"--unit", "x", f}, {"--journal", f}, {"--journal", "--raw"}, {"--min-baseline", "50", f},
		{"--max-tokens", "1", f}, {"-", "-"}, {"--tz", "Mars/Olympus", f}, {"--no-such-flag"},
		{filepath.Join(t.TempDir(), "missing.log")},
	} {
		if code, _, errs := run(t, "", args...); code != ExitUnknown || errs == "" {
			t.Errorf("%q: exit %d stderr %q", args, code, errs)
		}
	}
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "syslog-triage ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, errs := run(t, "", "--help"); code != 0 || !strings.Contains(errs, "Exit codes:") {
		t.Errorf("help: %d", code)
	}
	// Interactive stdin without files prints the usage.
	var out, errb bytes.Buffer
	if code := Run(nil, Env{Stdout: &out, Stderr: &errb, StdinIsTTY: true}); code != ExitUnknown || !strings.Contains(errb.String(), "Usage:") {
		t.Errorf("tty: %d", code)
	}
}

func TestSanitizeAndFilters(t *testing.T) {
	in := "<11>Nov 13 10:00:00 evil app: \x1b[31mred\x1b]0;title\x07 text\n<14>Nov 13 10:00:00 good other: fine\n"
	code, out, _ := run(t, in, "--tz", "UTC", "--min-severity", "err", "--host", "^evil$")
	if code != ExitOK || strings.ContainsAny(out, "\x1b\x07") || !strings.Contains(out, "?[31mred") || strings.Contains(out, "fine") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestParseTimeAndDuration(t *testing.T) {
	cases := map[string]time.Time{
		"-2h":                       now.Add(-2 * time.Hour),
		"90m":                       now.Add(-90 * time.Minute),
		"1d ago":                    now.Add(-24 * time.Hour),
		"now":                       now,
		"2026-11-13 08:30":          time.Date(2026, 11, 13, 8, 30, 0, 0, time.UTC),
		"2026-11-13T08:30:15":       time.Date(2026, 11, 13, 8, 30, 15, 0, time.UTC),
		"2026-11-12":                time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC),
		"2026-11-13T08:30:00+01:00": time.Date(2026, 11, 13, 7, 30, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got, err := ParseTime(in, now, time.UTC)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if d, err := ParseDuration("1.5d"); err != nil || d != 36*time.Hour {
		t.Errorf("1.5d: %v %v", d, err)
	}
	if _, err := ParseDuration("xd"); err == nil {
		t.Error("xd accepted")
	}
	if group(1234567) != "1,234,567" || group(-1000) != "-1,000" || group(12) != "12" {
		t.Error("group")
	}
}

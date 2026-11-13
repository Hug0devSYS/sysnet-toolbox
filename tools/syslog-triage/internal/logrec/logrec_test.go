package logrec

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ref = time.Date(2026, 11, 13, 17, 0, 0, 0, time.UTC)

func newParser() *Parser { return &Parser{Location: time.UTC, Ref: ref} }

func TestParseFormats(t *testing.T) {
	cases := []struct {
		name, line string
		want       Record
	}{
		{"rfc3164 with pri", "<38>Nov 13 10:00:01 web03 sshd[4242]: Failed password for root from 192.0.2.1 port 22 ssh2",
			Record{Time: time.Date(2026, 11, 13, 10, 0, 1, 0, time.UTC), Host: "web03", App: "sshd", PID: "4242",
				Severity: 6, Facility: 4, Message: "Failed password for root from 192.0.2.1 port 22 ssh2", Format: FormatRFC3164}},
		{"rfc3164 file, space-padded day", "Nov  3 07:05:09 db1 kernel: Out of memory: Killed process 123",
			Record{Time: time.Date(2026, 11, 3, 7, 5, 9, 0, time.UTC), Host: "db1", App: "kernel",
				Severity: -1, Facility: -1, Message: "Out of memory: Killed process 123", Format: FormatRFC3164}},
		{"rfc3164 without hostname", "<34>Oct 11 22:14:15 su: 'su root' failed for lonvick on /dev/pts/8",
			Record{Time: time.Date(2026, 10, 11, 22, 14, 15, 0, time.UTC), App: "su",
				Severity: 2, Facility: 4, Message: "'su root' failed for lonvick on /dev/pts/8", Format: FormatRFC3164}},
		{"rfc3164 without tag", "Nov 13 10:00:01 fw1 some message without a tag",
			Record{Time: time.Date(2026, 11, 13, 10, 0, 1, 0, time.UTC), Host: "fw1", App: "-",
				Severity: -1, Facility: -1, Message: "some message without a tag", Format: FormatRFC3164}},
		{"rsyslog high precision", "2026-11-13T10:00:01.123456+01:00 web1 nginx[77]: upstream timed out",
			Record{Time: time.Date(2026, 11, 13, 9, 0, 1, 123456000, time.UTC), Host: "web1", App: "nginx", PID: "77",
				Severity: -1, Facility: -1, Message: "upstream timed out", Format: FormatRFC3339}},
		{"journalctl short-iso", "2026-11-13T10:00:01+0100 web1 systemd[1]: Started foo.service.",
			Record{Time: time.Date(2026, 11, 13, 9, 0, 1, 0, time.UTC), Host: "web1", App: "systemd", PID: "1",
				Severity: -1, Facility: -1, Message: "Started foo.service.", Format: FormatRFC3339}},
		{"rfc5424 with SD", `<165>1 2026-11-13T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Appl\]ication"] ` + "\uFEFF" + `An application event`,
			Record{Time: time.Date(2026, 11, 13, 22, 14, 15, 3000000, time.UTC), Host: "mymachine.example.com", App: "evntslog",
				Severity: 5, Facility: 20, Message: "An application event", Format: FormatRFC5424}},
		{"rfc5424 nil values", "<11>1 - - - - - - disk failure",
			Record{App: "-", Severity: 3, Facility: 1, Message: "disk failure", Format: FormatRFC5424}},
		{"cisco via rsyslog", "<187>Nov 13 10:00:01 10.1.1.1 1234: Nov 13 10:00:00.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down",
			Record{Time: time.Date(2026, 11, 13, 10, 0, 1, 0, time.UTC), Host: "10.1.1.1", App: "%LINK-UPDOWN",
				Severity: 3, Facility: 23, Message: "Interface GigabitEthernet1/0/1, changed state to down", Format: FormatCisco}},
		{"cisco tag as program", "Nov 13 10:00:01 sw1 %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan10, changed state to up",
			Record{Time: time.Date(2026, 11, 13, 10, 0, 1, 0, time.UTC), Host: "sw1", App: "%LINEPROTO-UPDOWN",
				Severity: 5, Facility: -1, Message: "Line protocol on Interface Vlan10, changed state to up", Format: FormatCisco}},
		{"cisco direct", "<189>123: *Mar  1 00:01:02.345: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.5)",
			Record{Time: time.Date(2026, 3, 1, 0, 1, 2, 0, time.UTC), App: "%SYS-CONFIG_I",
				Severity: 5, Facility: 23, Message: "Configured from console by admin on vty0 (10.0.0.5)", Format: FormatCisco}},
		{"cisco asa", "<166>Nov 13 2026 10:00:01: %ASA-6-302013: Built inbound TCP connection 1 for outside:192.0.2.1/1234",
			Record{Time: time.Date(2026, 11, 13, 10, 0, 1, 0, time.UTC), App: "%ASA-302013",
				Severity: 6, Facility: 20, Message: "Built inbound TCP connection 1 for outside:192.0.2.1/1234", Format: FormatCisco}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := newParser().Parse(c.line)
			if !ok {
				t.Fatalf("not parsed: %+v", got)
			}
			if !got.Time.Equal(c.want.Time) {
				t.Errorf("time %v, want %v", got.Time, c.want.Time)
			}
			got.Time, c.want.Time = time.Time{}, time.Time{}
			if got != c.want {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestParseRawAndInvalid(t *testing.T) {
	p := newParser()
	for _, l := range []string{"plain application line", "<999>Nov 13 10:00:01 x y: z", "{not json", `{"foo":"bar"}`, "Foo 13 10:00:01 h a: b"} {
		r, ok := p.Parse(l)
		if ok || r.Format != FormatRaw || r.Message != l || r.Severity != SeverityUnknown || r.App != "-" {
			t.Errorf("%q: got %+v ok=%v", l, r, ok)
		}
	}
	p.Raw = true
	if r, ok := p.Parse("<38>Nov 13 10:00:01 web03 sshd[1]: x"); ok || r.Format != FormatRaw {
		t.Errorf("raw mode parsed a header: %+v", r)
	}
	// Invalid UTF-8 is repaired.
	r, _ := newParser().Parse("Nov 13 10:00:01 h app: caf\xe9")
	if r.Message != "caf\uFFFD" {
		t.Errorf("invalid UTF-8: %q", r.Message)
	}
}

func TestYearInference(t *testing.T) {
	p := &Parser{Location: time.UTC, Ref: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)}
	r, _ := p.Parse("Dec 31 23:59:59 h a: x")
	if r.Time.Year() != 2026 {
		t.Errorf("December line read in January: year %d", r.Time.Year())
	}
	r, _ = p.Parse("Jan  1 00:00:01 h a: x")
	if r.Time.Year() != 2027 {
		t.Errorf("year %d", r.Time.Year())
	}
	p.Year = 2020
	r, _ = p.Parse("Feb 29 12:00:00 h a: x")
	if !r.Time.Equal(time.Date(2020, 2, 29, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("forced year: %v", r.Time)
	}
	// Feb 29 seen from a non-leap year after it: the previous leap year
	// does not exist one year back (2027 -> 2026 has no Feb 29).
	p = &Parser{Location: time.UTC, Ref: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)}
	if r, ok := p.Parse("Feb 29 12:00:00 h a: x"); ok && r.Time.Month() != time.February {
		t.Errorf("Feb 29 normalised to %v", r.Time)
	}
	// Fractional seconds after a BSD timestamp.
	r, _ = newParser().Parse("Nov 13 10:00:01.250 h a: x")
	if r.Time.Nanosecond() != 250000000 {
		t.Errorf("fraction: %v", r.Time)
	}
	// Location applies to zone-less timestamps.
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("no tzdata")
	}
	r, _ = (&Parser{Location: paris, Ref: ref}).Parse("Nov 13 10:00:01 h a: x")
	if r.Time.UTC().Hour() != 9 {
		t.Errorf("location: %v", r.Time.UTC())
	}
}

func TestJournal(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1794564001123456","_HOSTNAME":"web1","SYSLOG_IDENTIFIER":"sshd","_PID":"99","PRIORITY":"3","SYSLOG_FACILITY":"10","MESSAGE":"error: kex_exchange_identification: Connection closed"}`
	r, ok := newParser().Parse(line)
	if !ok || r.Format != FormatJournal || r.Host != "web1" || r.App != "sshd" || r.PID != "99" || r.Severity != 3 || r.Facility != 10 ||
		r.Message != "error: kex_exchange_identification: Connection closed" || r.Time.UnixMicro() != 1794564001123456 {
		t.Fatalf("got %+v", r)
	}
	// Binary MESSAGE (array of bytes), _COMM fallback, no priority.
	r, ok = newParser().Parse(`{"__REALTIME_TIMESTAMP":"1","_COMM":"app","MESSAGE":[104,105,255]}`)
	if !ok || r.Message != "hi\uFFFD" || r.App != "app" || r.Severity != SeverityUnknown {
		t.Fatalf("binary: %+v", r)
	}
	// Null message, unit fallback.
	r, ok = newParser().Parse(`{"MESSAGE":null,"_SYSTEMD_UNIT":"foo.service"}`)
	if !ok || r.Message != "" || r.App != "foo.service" || !r.Time.IsZero() {
		t.Fatalf("null: %+v", r)
	}
}

func TestSeverity(t *testing.T) {
	for in, want := range map[string]int{"err": 3, "ERROR": 3, "warn": 4, "0": 0, "debug": 7, "crit": 2} {
		if got, ok := ParseSeverity(in); !ok || got != want {
			t.Errorf("%s: %d %v", in, got, ok)
		}
	}
	if _, ok := ParseSeverity("8"); ok {
		t.Error("8 accepted")
	}
	if SeverityName(-1) != "-" || SeverityName(4) != "warning" {
		t.Error("SeverityName")
	}
}

func TestOpenAndReadLines(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "syslog")
	os.WriteFile(plain, []byte("a\r\nb\n\nc"), 0o644)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("x\ny\n"))
	zw.Close()
	gz := filepath.Join(dir, "syslog.1") // no .gz suffix: detected by magic
	os.WriteFile(gz, buf.Bytes(), 0o644)
	read := func(p string) []string {
		r, c, err := Open(p, strings.NewReader("s1\ns2\n"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		var out []string
		if _, err := ReadLines(r, func(l string) error { out = append(out, l); return nil }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := strings.Join(read(plain), "|"); got != "a|b||c" {
		t.Errorf("plain: %q", got)
	}
	if got := strings.Join(read(gz), "|"); got != "x|y" {
		t.Errorf("gzip: %q", got)
	}
	if got := strings.Join(read("-"), "|"); got != "s1|s2" {
		t.Errorf("stdin: %q", got)
	}
	if _, _, err := Open(dir, nil); err == nil {
		t.Error("directory accepted")
	}
	if _, _, err := Open(filepath.Join(dir, "missing"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	bad := filepath.Join(dir, "bad.gz")
	os.WriteFile(bad, []byte{0x1f, 0x8b, 0, 0}, 0o644)
	if _, _, err := Open(bad, nil); err == nil {
		t.Error("corrupt gzip accepted")
	}
}

func TestReadLinesLong(t *testing.T) {
	long := strings.Repeat("x", MaxLineBytes*5)
	in := "short\n" + long + "\nafter\n" + strings.Repeat("y", 300<<10)
	var lines []string
	n, err := ReadLines(strings.NewReader(in), func(l string) error { lines = append(lines, l); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(lines) != 4 || lines[0] != "short" || len(lines[1]) != MaxLineBytes || lines[2] != "after" || len(lines[3]) != MaxLineBytes {
		t.Fatalf("truncated=%d lines=%d lens=%d,%d", n, len(lines), len(lines[1]), len(lines[len(lines)-1]))
	}
	stop := errors.New("stop")
	if _, err := ReadLines(strings.NewReader("a\nb\n"), func(string) error { return stop }); err != stop {
		t.Errorf("callback error not returned: %v", err)
	}
}

package triage

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/drain"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/logrec"
)

var t0 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

func rec(min int, host, app string, sev int, msg string) logrec.Record {
	return logrec.Record{Time: t0.Add(time.Duration(min) * time.Minute), Host: host, App: app, Severity: sev, Facility: 1, Message: msg}
}

// feed generates 6 hours of background traffic, a burst of auth failures
// at 03:00-03:10 and a new error pattern during the last 20 minutes.
func feed(a *Analyzer, withNew bool) {
	for m := 0; m < 360; m++ {
		for i := 0; i < 5; i++ {
			a.Add(rec(m, fmt.Sprintf("web%d", i), "sshd", 6, fmt.Sprintf("Accepted publickey for u%d from 192.0.2.%d port %d ssh2", i, m%200, 1000+m)), true)
		}
		a.Add(rec(m, "web1", "CRON", 6, fmt.Sprintf("(root) CMD (run-parts /etc/cron.hourly %d)", m)), true)
		if m >= 180 && m < 190 {
			for i := 0; i < 20; i++ {
				a.Add(rec(m, "web3", "sshd", 4, fmt.Sprintf("Failed password for invalid user x%d from 198.51.100.%d port %d ssh2", i, i, 2000+i)), true)
			}
		}
		if withNew && m >= 340 {
			a.Add(rec(m, "db1", "kernel", 2, "EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0"), true)
			a.Add(rec(m, "db1", "kernel", 2, "EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0"), true)
		}
	}
}

func TestSpikesAndRecent(t *testing.T) {
	a := New(DefaultOptions(), drain.New(drain.DefaultParams()))
	feed(a, false)
	res, err := a.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Messages != 360*6+200 || res.Summary.Patterns != 3 || res.Summary.Hosts != 5 || res.Summary.Buckets != 72 {
		t.Fatalf("summary %+v", res.Summary)
	}
	var auth *Spike
	for i := range res.Spikes {
		if res.Spikes[i].PatternID != 0 {
			if auth != nil {
				t.Fatalf("several pattern spikes: %+v", res.Spikes)
			}
			auth = &res.Spikes[i]
		}
	}
	if auth == nil || auth.App != "sshd" || !auth.Start.Equal(t0.Add(180*time.Minute)) || !auth.End.Equal(t0.Add(190*time.Minute)) ||
		auth.Total != 200 || auth.Severity != "warning" || !auth.Alert {
		t.Fatalf("auth spike %+v", auth)
	}
	if res.Status != "WARNING" || res.ExitCode != 1 {
		t.Fatalf("status %s", res.Status)
	}
	// Recent window after the burst: nothing to report.
	o := DefaultOptions()
	o.Recent = time.Hour
	a = New(o, drain.New(drain.DefaultParams()))
	feed(a, false)
	res, _ = a.Finish()
	if len(res.Spikes) != 0 || res.Status != "OK" || len(res.New) != 0 {
		t.Fatalf("recent: %+v status %s", res.Spikes, res.Status)
	}
}

func TestNewPatternsRecent(t *testing.T) {
	o := DefaultOptions()
	o.Recent = 30 * time.Minute
	a := New(o, drain.New(drain.DefaultParams()))
	feed(a, true)
	res, _ := a.Finish()
	if len(res.New) != 1 || res.New[0].App != "kernel" || res.New[0].Severity != "crit" || res.New[0].Count != 40 {
		t.Fatalf("new: %+v", res.New)
	}
	if res.Status != "CRITICAL" || res.ExitCode != 2 {
		t.Fatalf("status %s", res.Status)
	}
	// A crit pattern does not page when --crit-severity is emerg.
	o.CritSeverity = 0
	a = New(o, drain.New(drain.DefaultParams()))
	feed(a, true)
	if res, _ = a.Finish(); res.Status != "WARNING" {
		t.Fatalf("crit-severity: %s", res.Status)
	}
	// Alert severity: new patterns less severe than alert are listed but quiet.
	o = DefaultOptions()
	o.Recent = 30 * time.Minute
	o.AlertSeverity = 1
	a = New(o, drain.New(drain.DefaultParams()))
	feed(a, true)
	if res, _ = a.Finish(); len(res.New) != 1 || res.Status != "OK" {
		t.Fatalf("alert-severity: %d %s", len(res.New), res.Status)
	}
}

func TestNewPatternsWithModel(t *testing.T) {
	m := drain.New(drain.DefaultParams())
	a := New(DefaultOptions(), m)
	feed(a, false)
	if _, err := a.Finish(); err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Clusters() {
		c.Known, c.Count = true, 0 // as after a model reload
	}
	o := DefaultOptions()
	o.ModelLoaded = true
	a = New(o, m)
	feed(a, true)
	res, _ := a.Finish()
	if res.Summary.KnownBefore != 3 || len(res.New) != 1 || res.New[0].App != "kernel" || !res.New[0].New {
		t.Fatalf("known %d new %+v", res.Summary.KnownBefore, res.New)
	}
	for _, p := range res.Patterns {
		if p.App == "sshd" && !p.Known {
			t.Fatalf("sshd pattern not known: %+v", p)
		}
	}
}

func TestFilters(t *testing.T) {
	o := DefaultOptions()
	o.MinSeverity = 4
	o.NoApp = regexp.MustCompile("^CRON$")
	o.Host = regexp.MustCompile("^web")
	o.Since = t0.Add(60 * time.Minute)
	o.Until = t0.Add(300 * time.Minute)
	a := New(o, drain.New(drain.DefaultParams()))
	feed(a, true)
	a.Add(logrec.Record{App: "x", Host: "web9", Severity: logrec.SeverityUnknown, Message: "no time, unknown severity"}, false)
	res, _ := a.Finish()
	// Only the 200 auth failures (warning) and the timeless record remain.
	if res.Summary.Clustered != 201 || res.Summary.Unparsed != 1 || res.Summary.WithoutTime != 1 || res.Summary.Patterns != 2 {
		t.Fatalf("summary %+v", res.Summary)
	}
}

func TestNoTimestamps(t *testing.T) {
	a := New(DefaultOptions(), drain.New(drain.DefaultParams()))
	for i := 0; i < 50; i++ {
		a.Add(logrec.Record{App: "-", Severity: -1, Message: fmt.Sprintf("job %d done", i)}, false)
	}
	res, err := a.Finish()
	if err != nil || res.Summary.First != nil || len(res.Spikes) != 0 || res.Patterns[0].Count != 50 ||
		res.Patterns[0].SeverityCounts["unknown"] != 50 || res.Patterns[0].Severity != "-" || res.Status != "OK" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestTooManyBuckets(t *testing.T) {
	o := DefaultOptions()
	o.Bucket = time.Second
	a := New(o, drain.New(drain.DefaultParams()))
	a.Add(rec(0, "h", "a", 6, "x"), true)
	a.Add(rec(60*24*30, "h", "a", 6, "x"), true)
	if _, err := a.Finish(); err == nil {
		t.Fatal("expected TooManyBucketsError")
	}
}

func TestNoAppSplitAndSorting(t *testing.T) {
	o := DefaultOptions()
	o.AppSplit = false
	a := New(o, drain.New(drain.DefaultParams()))
	for i := 0; i < 10; i++ {
		a.Add(rec(i, "h1", "app1", 6, "same message text"), true)
	}
	for i := 0; i < 3; i++ {
		a.Add(rec(i, "h2", "app2", 6, "same message text"), true)
		a.Add(rec(20+i, "h2", "app2", 3, fmt.Sprintf("disk %d failed badly now", i)), true)
	}
	res, _ := a.Finish()
	if len(res.Patterns) != 2 || res.Patterns[0].Count != 13 || res.Patterns[0].App != "app1" {
		t.Fatalf("%+v", res.Patterns)
	}
	SortPatterns(res.Patterns, "severity")
	if res.Patterns[0].Severity != "err" {
		t.Fatal("severity sort")
	}
	SortPatterns(res.Patterns, "first")
	if res.Patterns[0].Severity != "err" {
		t.Fatal("first sort")
	}
	SortPatterns(res.Patterns, "hosts")
	if res.Patterns[0].Hosts != 2 {
		t.Fatal("hosts sort")
	}
	SortPatterns(res.Patterns, "count")
	if res.Patterns[0].Count != 13 || len(res.Patterns[0].TopHosts) != 2 || res.Patterns[0].TopHosts[0].Host != "h1" {
		t.Fatalf("count sort / top hosts %+v", res.Patterns[0].TopHosts)
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{5 * time.Minute: "5m", 90 * time.Minute: "1h30m", time.Hour: "1h", 48 * time.Hour: "2d", 30 * time.Second: "30s"} {
		if got := FormatDuration(d); got != want {
			t.Errorf("%v: %s", d, got)
		}
	}
	if truncate("héllo", 2) != "h…" {
		t.Errorf("truncate: %q", truncate("héllo", 2))
	}
}

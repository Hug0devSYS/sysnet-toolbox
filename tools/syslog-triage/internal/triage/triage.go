// Package triage feeds parsed records into the Drain miner, keeps
// per-pattern statistics and time series, and produces the report: pattern
// table, volume spikes per pattern and overall, and new patterns.
package triage

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/drain"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/logrec"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/mask"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/spike"
)

// Options configure an analysis.
type Options struct {
	Bucket    time.Duration
	Spike     spike.Params
	AppSplit  bool // one Drain partition per program
	MaxTokens int  // tokens kept per message (0 = all)

	// Filters applied before clustering.
	Since, Until time.Time
	MinSeverity  int // drop messages less severe (higher value); -1 = keep all
	App, NoApp   *regexp.Regexp
	Host         *regexp.Regexp

	// Recent limits alerts to spikes and new patterns within this duration
	// of the latest message (0 = whole input).
	Recent time.Duration
	// ModelLoaded tells that the miner was restored from an existing model:
	// patterns it does not know are new.
	ModelLoaded bool
	// AlertSeverity: spikes and new patterns of patterns whose worst
	// severity is less severe than this do not raise the status (unknown
	// severity always does).
	AlertSeverity int
	// CritSeverity: alerts on patterns at least this severe are CRITICAL.
	CritSeverity int
	TopHosts     int
}

// DefaultOptions returns the CLI defaults.
func DefaultOptions() Options {
	return Options{Bucket: 5 * time.Minute, Spike: spike.DefaultParams(), AppSplit: true, MaxTokens: 0,
		MinSeverity: -1, AlertSeverity: 7, CritSeverity: 3, TopHosts: 3}
}

const maxHostsTracked = 10000
const maxExample = 400

type stats struct {
	series     map[int64]int64
	sev        [8]int64
	sevUnknown int64
	hosts      map[string]int64
	hostsMore  bool
	apps       map[string]int64
	example    string
	firstRun   time.Time // first/last seen in this run
	lastRun    time.Time
}

// Analyzer accumulates records.
type Analyzer struct {
	opt   Options
	miner *drain.Miner
	st    map[*drain.Cluster]*stats

	global      map[int64]int64
	total       int64 // records read
	clustered   int64
	unparsed    int64
	filtered    int64
	noTime      int64
	first, last time.Time
	hosts       map[string]struct{}
	apps        map[string]struct{}
}

// New returns an analyzer using miner (from drain.New or a loaded model).
func New(opt Options, miner *drain.Miner) *Analyzer {
	if opt.Bucket <= 0 {
		opt.Bucket = 5 * time.Minute
	}
	return &Analyzer{opt: opt, miner: miner, st: map[*drain.Cluster]*stats{}, global: map[int64]int64{},
		hosts: map[string]struct{}{}, apps: map[string]struct{}{}}
}

func (a *Analyzer) bucketOf(t time.Time) int64 {
	n := t.UnixNano()
	b := int64(a.opt.Bucket)
	q := n / b
	if n%b < 0 {
		q--
	}
	return q
}

func (a *Analyzer) keep(r *logrec.Record) bool {
	o := &a.opt
	if !r.Time.IsZero() {
		if !o.Since.IsZero() && r.Time.Before(o.Since) {
			return false
		}
		if !o.Until.IsZero() && !r.Time.Before(o.Until) {
			return false
		}
	}
	if o.MinSeverity >= 0 && r.Severity != logrec.SeverityUnknown && r.Severity > o.MinSeverity {
		return false
	}
	if o.App != nil && !o.App.MatchString(r.App) {
		return false
	}
	if o.NoApp != nil && o.NoApp.MatchString(r.App) {
		return false
	}
	if o.Host != nil && !o.Host.MatchString(r.Host) {
		return false
	}
	return true
}

// Add processes one record. parsed tells whether a header was recognised.
func (a *Analyzer) Add(r logrec.Record, parsed bool) {
	a.total++
	if !parsed {
		a.unparsed++
	}
	if !a.keep(&r) {
		a.filtered++
		return
	}
	a.clustered++
	key := ""
	if a.opt.AppSplit {
		key = r.App
	}
	tokens := mask.Tokens(r.Message, a.opt.MaxTokens)
	c, _ := a.miner.Add(key, tokens, r.Time)
	s := a.st[c]
	if s == nil {
		s = &stats{series: map[int64]int64{}, hosts: map[string]int64{}, apps: map[string]int64{}}
		s.example = truncate(r.Message, maxExample)
		a.st[c] = s
	}
	if r.Severity >= 0 && r.Severity <= 7 {
		s.sev[r.Severity]++
	} else {
		s.sevUnknown++
	}
	if r.Host != "" {
		if _, ok := s.hosts[r.Host]; ok || len(s.hosts) < maxHostsTracked {
			s.hosts[r.Host]++
		} else {
			s.hostsMore = true
		}
		if len(a.hosts) < 1_000_000 {
			a.hosts[r.Host] = struct{}{}
		}
	}
	if !a.opt.AppSplit {
		if _, ok := s.apps[r.App]; ok || len(s.apps) < 100 {
			s.apps[r.App]++
		}
	}
	if len(a.apps) < 1_000_000 {
		a.apps[r.App] = struct{}{}
	}
	if r.Time.IsZero() {
		a.noTime++
		return
	}
	b := a.bucketOf(r.Time)
	s.series[b]++
	a.global[b]++
	if s.firstRun.IsZero() || r.Time.Before(s.firstRun) {
		s.firstRun = r.Time
	}
	if r.Time.After(s.lastRun) {
		s.lastRun = r.Time
	}
	if a.first.IsZero() || r.Time.Before(a.first) {
		a.first = r.Time
	}
	if r.Time.After(a.last) {
		a.last = r.Time
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// HostCount is one entry of a pattern's top hosts.
type HostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// Pattern is one template in the report.
type Pattern struct {
	ID             int              `json:"id"`
	App            string           `json:"app"`
	Template       string           `json:"template"`
	Count          int64            `json:"count"`
	Percent        float64          `json:"percent"`
	Severity       string           `json:"severity"`
	SeverityValue  int              `json:"-"`
	SeverityCounts map[string]int64 `json:"severity_counts"`
	Hosts          int              `json:"hosts"`
	HostsTruncated bool             `json:"hosts_truncated,omitempty"`
	TopHosts       []HostCount      `json:"top_hosts"`
	FirstSeen      *time.Time       `json:"first_seen,omitempty"`
	LastSeen       *time.Time       `json:"last_seen,omitempty"`
	Example        string           `json:"example"`
	Known          bool             `json:"known"`
	New            bool             `json:"new"`
	// TotalCount includes the counts stored in the model.
	TotalCount int64 `json:"total_count"`
}

// Spike is a burst of one pattern (PatternID 0: all messages).
type Spike struct {
	PatternID     int       `json:"pattern_id"`
	App           string    `json:"app"`
	Template      string    `json:"template"`
	Severity      string    `json:"severity"`
	SeverityValue int       `json:"-"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	PeakAt        time.Time `json:"peak_at"`
	Peak          int64     `json:"peak"`
	Total         int64     `json:"total"`
	Baseline      float64   `json:"baseline"`
	Ratio         float64   `json:"ratio"`
	Sustained     bool      `json:"sustained"`
	Alert         bool      `json:"alert"`
}

// Summary describes the input.
type Summary struct {
	Messages    int64      `json:"messages"`
	Unparsed    int64      `json:"unparsed"`
	Filtered    int64      `json:"filtered"`
	Clustered   int64      `json:"clustered"`
	WithoutTime int64      `json:"without_time"`
	Hosts       int        `json:"hosts"`
	Apps        int        `json:"apps"`
	Patterns    int        `json:"patterns"`
	KnownBefore int        `json:"known_patterns"`
	NewPatterns int        `json:"new_patterns"`
	Spikes      int        `json:"spikes"`
	First       *time.Time `json:"first,omitempty"`
	Last        *time.Time `json:"last,omitempty"`
	Bucket      string     `json:"bucket"`
	RecentFrom  *time.Time `json:"recent_from,omitempty"`
	Buckets     int        `json:"buckets"`
}

// Result is the complete analysis.
type Result struct {
	Summary  Summary   `json:"summary"`
	Spikes   []Spike   `json:"spikes"`
	New      []Pattern `json:"new_patterns"`
	Patterns []Pattern `json:"patterns"`
	Status   string    `json:"status"`
	ExitCode int       `json:"exit_code"`
}

// MaxBuckets bounds the dense time series built for spike detection.
const MaxBuckets = 500_000

// worst returns the most severe level seen (or -1).
func (s *stats) worst() int {
	for i, n := range s.sev {
		if n > 0 {
			return i
		}
	}
	return logrec.SeverityUnknown
}

func (a *Analyzer) alerting(sev int) bool {
	return sev == logrec.SeverityUnknown || sev <= a.opt.AlertSeverity
}

// Finish computes the report. The miner keeps its state (for SaveModel).
func (a *Analyzer) Finish() (*Result, error) {
	res := &Result{Spikes: []Spike{}, New: []Pattern{}, Patterns: []Pattern{}}
	sum := &res.Summary
	sum.Messages, sum.Unparsed, sum.Filtered, sum.Clustered, sum.WithoutTime =
		a.total, a.unparsed, a.filtered, a.clustered, a.noTime
	sum.Hosts, sum.Apps = len(a.hosts), len(a.apps)
	sum.Bucket = FormatDuration(a.opt.Bucket)
	if !a.first.IsZero() {
		f, l := a.first, a.last
		sum.First, sum.Last = &f, &l
	}
	var recentFrom time.Time
	if a.opt.Recent > 0 && !a.last.IsZero() {
		recentFrom = a.last.Add(-a.opt.Recent)
		sum.RecentFrom = &recentFrom
	}

	byCluster := map[*drain.Cluster]int{} // index in res.Patterns
	for _, c := range a.miner.Clusters() {
		if c.Known {
			sum.KnownBefore++
		}
		s := a.st[c]
		if s == nil {
			continue
		}
		p := Pattern{ID: c.ID, App: c.Key, Template: c.Template(), Count: c.Count, TotalCount: c.TotalCount,
			SeverityCounts: map[string]int64{}, Example: s.example, Known: c.Known, Hosts: len(s.hosts),
			HostsTruncated: s.hostsMore, TopHosts: []HostCount{}}
		if a.clustered > 0 {
			p.Percent = math.Round(float64(c.Count)/float64(a.clustered)*10000) / 100
		}
		p.SeverityValue = s.worst()
		p.Severity = logrec.SeverityName(p.SeverityValue)
		for i, n := range s.sev {
			if n > 0 {
				p.SeverityCounts[logrec.SeverityNames[i]] = n
			}
		}
		if s.sevUnknown > 0 {
			p.SeverityCounts["unknown"] = s.sevUnknown
		}
		if !a.opt.AppSplit {
			p.App = topKey(s.apps)
		}
		p.TopHosts = topHosts(s.hosts, a.opt.TopHosts)
		if !s.firstRun.IsZero() {
			f, l := s.firstRun, s.lastRun
			p.FirstSeen, p.LastSeen = &f, &l
		}
		// New patterns.
		switch {
		case a.opt.ModelLoaded:
			p.New = !c.Known && (recentFrom.IsZero() || !s.firstRun.Before(recentFrom))
		case !recentFrom.IsZero():
			p.New = !s.firstRun.IsZero() && !s.firstRun.Before(recentFrom) && a.first.Before(recentFrom)
		}
		res.Patterns = append(res.Patterns, p)
		byCluster[c] = len(res.Patterns) - 1
	}
	sum.Patterns = len(res.Patterns)

	// Spike detection on dense series.
	if len(a.global) > 0 {
		lo, hi := a.bucketOf(a.first), a.bucketOf(a.last)
		n := hi - lo + 1
		if n > MaxBuckets {
			return nil, &TooManyBucketsError{Buckets: n, Bucket: a.opt.Bucket}
		}
		sum.Buckets = int(n)
		dense := make([]int64, n)
		toTime := func(i int) time.Time { return time.Unix(0, (lo+int64(i))*int64(a.opt.Bucket)) }
		emit := func(id int, app, tmpl string, sev int, sp []spike.Spike) {
			for _, s := range sp {
				out := Spike{PatternID: id, App: app, Template: tmpl, SeverityValue: sev,
					Severity: logrec.SeverityName(sev), Start: toTime(s.Start), End: toTime(s.End + 1),
					PeakAt: toTime(s.PeakIndex), Peak: s.Peak, Total: s.Total,
					Baseline: math.Round(s.Baseline*100) / 100, Ratio: math.Round(s.Ratio()*10) / 10,
					Sustained: s.Sustained}
				inWindow := recentFrom.IsZero() || out.End.After(recentFrom)
				out.Alert = inWindow && (id == 0 || a.alerting(sev))
				if inWindow {
					res.Spikes = append(res.Spikes, out)
				}
			}
		}
		fill := func(m map[int64]int64) []int64 {
			for i := range dense {
				dense[i] = 0
			}
			for b, v := range m {
				dense[b-lo] = v
			}
			return dense
		}
		emit(0, "*", "all messages", logrec.SeverityUnknown, spike.Detect(fill(a.global), a.opt.Spike))
		for _, c := range a.miner.Clusters() {
			s := a.st[c]
			if s == nil || c.Count < a.opt.Spike.MinCount || len(s.series) == 0 {
				continue
			}
			p := &res.Patterns[byCluster[c]]
			emit(p.ID, p.App, p.Template, p.SeverityValue, spike.Detect(fill(s.series), a.opt.Spike))
		}
	}
	sort.SliceStable(res.Spikes, func(i, j int) bool {
		if !res.Spikes[i].Start.Equal(res.Spikes[j].Start) {
			return res.Spikes[i].Start.After(res.Spikes[j].Start)
		}
		return res.Spikes[i].Ratio > res.Spikes[j].Ratio
	})
	sum.Spikes = len(res.Spikes)

	for _, p := range res.Patterns {
		if p.New {
			res.New = append(res.New, p)
		}
	}
	sort.SliceStable(res.New, func(i, j int) bool { return lessSeverity(res.New[i], res.New[j]) })
	sum.NewPatterns = len(res.New)

	// Status.
	status := 0
	raise := func(sev int) {
		lvl := 1
		if sev >= 0 && sev <= a.opt.CritSeverity {
			lvl = 2
		}
		status = max(status, lvl)
	}
	for _, s := range res.Spikes {
		if s.Alert {
			raise(s.SeverityValue)
		}
	}
	for _, p := range res.New {
		if a.alerting(p.SeverityValue) {
			raise(p.SeverityValue)
		}
	}
	res.ExitCode = status
	res.Status = []string{"OK", "WARNING", "CRITICAL"}[status]
	return res, nil
}

func lessSeverity(a, b Pattern) bool {
	sa, sb := a.SeverityValue, b.SeverityValue
	if sa < 0 {
		sa = 8
	}
	if sb < 0 {
		sb = 8
	}
	if sa != sb {
		return sa < sb
	}
	return a.Count > b.Count
}

// SortPatterns orders patterns: "count" (default), "severity", "first"
// (most recently appeared first), "last" (most recently seen first),
// "hosts".
func SortPatterns(ps []Pattern, by string) {
	t := func(p *time.Time) time.Time {
		if p == nil {
			return time.Time{}
		}
		return *p
	}
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		switch by {
		case "severity":
			return lessSeverity(a, b)
		case "first":
			if !t(a.FirstSeen).Equal(t(b.FirstSeen)) {
				return t(a.FirstSeen).After(t(b.FirstSeen))
			}
		case "last":
			if !t(a.LastSeen).Equal(t(b.LastSeen)) {
				return t(a.LastSeen).After(t(b.LastSeen))
			}
		case "hosts":
			if a.Hosts != b.Hosts {
				return a.Hosts > b.Hosts
			}
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
}

// TooManyBucketsError is returned when the time range is too long for the
// bucket size.
type TooManyBucketsError struct {
	Buckets int64
	Bucket  time.Duration
}

func (e *TooManyBucketsError) Error() string {
	return "time range spans " + itoa(e.Buckets) + " buckets of " + e.Bucket.String() +
		" (max " + itoa(MaxBuckets) + "): use a larger --bucket or --since/--until"
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func topKey(m map[string]int64) string {
	best, bn := "-", int64(-1)
	for k, v := range m {
		if v > bn || v == bn && k < best {
			best, bn = k, v
		}
	}
	return best
}

func topHosts(m map[string]int64, n int) []HostCount {
	out := make([]HostCount, 0, len(m))
	for h, c := range m {
		out = append(out, HostCount{h, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	if n >= 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// FormatDuration prints d without zero trailing units ("5m", "1h30m", "2d").
func FormatDuration(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

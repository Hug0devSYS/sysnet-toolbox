// Package cli implements the syslog-triage command line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/drain"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/logrec"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/triage"
)

// Version is overridden at build time with -ldflags "-X .../cli.Version=x.y.z".
var Version = "0.1.0"

// Exit codes (Nagios/Icinga compatible).
const (
	ExitOK       = 0
	ExitWarning  = 1
	ExitCritical = 2
	ExitUnknown  = 3
)

const usageHead = `syslog-triage - cluster syslog/journald messages into patterns (Drain) and detect spikes

Usage:
  syslog-triage [flags] [FILE...]          files may be gzip-compressed; "-" is stdin
  journalctl -o json --since -2h | syslog-triage [flags]
  syslog-triage --journal --since -2h [--unit UNIT]...

Input formats are detected per line: RFC 3164 (with or without <PRI>),
RFC 3339 timestamps (rsyslog high precision, journalctl -o short-iso),
RFC 5424, Cisco IOS/NX-OS/ASA %FAC-SEV-MNEMONIC messages and journalctl
-o json. The tool only reads logs; it writes nothing unless --update-model
is given.

Flags:
`

const usageTail = `
Durations accept Go syntax plus days: 90s, 15m, 2h, 7d.
Times (--since/--until) accept RFC 3339, "2006-01-02 15:04[:05]",
"2006-01-02", or a duration relative to now ("-2h" or "2h").

Exit codes:
  0  OK        no spike and no new pattern
  1  WARNING   spikes or new patterns
  2  CRITICAL  spikes or new patterns of severity --crit-severity or worse
  3  UNKNOWN   usage error, unreadable input or model
`

// JournalFunc starts journalctl with args and returns its standard output.
// wait must be called after the output has been consumed.
type JournalFunc func(ctx context.Context, args []string) (out io.ReadCloser, wait func() error, err error)

// Env carries the process environment so tests can replace it.
type Env struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	StdinIsTTY     bool
	Now            func() time.Time
	Journal        JournalFunc
}

// DefaultEnv returns the environment of the running process.
func DefaultEnv() Env {
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, StdinIsTTY: isTerminal(os.Stdin),
		Now: time.Now, Journal: execJournal}
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func execJournal(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, cmd.Wait, nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// ParseDuration is time.ParseDuration with a "d" (24h) unit.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// ParseTime parses an absolute time or a duration relative to now.
func ParseTime(s string, now time.Time, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if s == "now" {
		return now, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
	}
	rel := strings.TrimSuffix(strings.TrimPrefix(s, "-"), " ago")
	if d, err := ParseDuration(rel); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q", s)
}

type config struct {
	journal                          bool
	units                            stringList
	journalDir                       string
	raw                              bool
	year                             int
	tz                               string
	since, until                     string
	minSev, alertSev, critSev        string
	app, noApp, host                 string
	sim                              float64
	depth, maxChildren, maxTokens    int
	noAppSplit                       bool
	model                            string
	updateModel                      bool
	modelMaxAge                      string
	bucket, recent                   string
	window, minBaseline              int
	threshold, minRatio              float64
	minCount                         int64
	jsonOut, examples, wide, quiet   bool
	top                              int
	sortBy                           string
	timeout                          string
	version                          bool
	explicit                         map[string]bool
	parsedLoc                        *time.Location
	sinceT, untilT                   time.Time
	bucketD, recentD, maxAgeD, toutD time.Duration
}

func newFlagSet(cfg *config, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet("syslog-triage", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		io.WriteString(env.Stderr, usageHead)
		fs.PrintDefaults()
		io.WriteString(env.Stderr, usageTail)
	}
	d := triage.DefaultOptions()
	dp := drain.DefaultParams()
	// Input
	fs.BoolVar(&cfg.journal, "journal", false, "read the local journal with `journalctl -o json` (use --since)")
	fs.Var(&cfg.units, "unit", "with --journal: only this systemd unit (repeatable)")
	fs.StringVar(&cfg.journalDir, "journal-dir", "", "with --journal: read journal files from this directory (journalctl -D)")
	fs.BoolVar(&cfg.raw, "raw", false, "do not parse syslog headers: every line is a message (application logs)")
	fs.IntVar(&cfg.year, "year", 0, "year of RFC 3164 timestamps (default: inferred from the file time)")
	fs.StringVar(&cfg.tz, "tz", "Local", "time zone of timestamps without offset, and of the text output")
	// Filters
	fs.StringVar(&cfg.since, "since", "", "ignore messages before this time")
	fs.StringVar(&cfg.until, "until", "", "ignore messages at or after this time")
	fs.StringVar(&cfg.minSev, "min-severity", "", "ignore messages less severe than this level (messages without severity are kept)")
	fs.StringVar(&cfg.app, "app", "", "only programs matching this regular expression")
	fs.StringVar(&cfg.noApp, "exclude-app", "", "skip programs matching this regular expression")
	fs.StringVar(&cfg.host, "host", "", "only hosts matching this regular expression")
	// Clustering
	fs.Float64Var(&cfg.sim, "sim", dp.Sim, "Drain similarity threshold (0-1): higher gives more, finer patterns")
	fs.IntVar(&cfg.depth, "depth", dp.Depth, "Drain tree depth (>= 3)")
	fs.IntVar(&cfg.maxChildren, "max-children", dp.MaxChildren, "Drain max children per tree node")
	fs.IntVar(&cfg.maxTokens, "max-tokens", 80, "tokens per message considered (rest folded into <*>), 0 = all")
	fs.BoolVar(&cfg.noAppSplit, "no-app-split", false, "cluster all programs together (default: one partition per program)")
	fs.StringVar(&cfg.model, "model", "", "pattern model file: patterns it does not contain are reported as new")
	fs.BoolVar(&cfg.updateModel, "update-model", false, "write the updated model back to --model (created if missing)")
	fs.StringVar(&cfg.modelMaxAge, "model-max-age", "90d", "drop patterns not seen for this long when saving the model (0 = never)")
	// Spikes
	fs.StringVar(&cfg.bucket, "bucket", triage.FormatDuration(d.Bucket), "time bucket for spike detection")
	fs.IntVar(&cfg.window, "window", d.Spike.Window, "baseline: number of preceding buckets")
	fs.IntVar(&cfg.minBaseline, "min-baseline", d.Spike.MinBaseline, "buckets of history needed before a bucket is evaluated")
	fs.Float64Var(&cfg.threshold, "threshold", d.Spike.K, "spike when count > median + threshold x robust sigma")
	fs.Float64Var(&cfg.minRatio, "min-ratio", d.Spike.MinRatio, "spike only when count >= min-ratio x median")
	fs.Int64Var(&cfg.minCount, "min-count", d.Spike.MinCount, "minimum messages in a bucket for a spike")
	fs.StringVar(&cfg.recent, "recent", "", "alert only on spikes and new patterns within this duration of the last message")
	fs.StringVar(&cfg.alertSev, "alert-severity", "debug", "spikes/new patterns less severe than this level do not raise the status")
	fs.StringVar(&cfg.critSev, "crit-severity", "err", "spikes/new patterns at this level or worse are CRITICAL")
	// Output
	fs.BoolVar(&cfg.jsonOut, "json", false, "JSON output")
	fs.IntVar(&cfg.top, "top", 20, "patterns listed (0 = all)")
	fs.StringVar(&cfg.sortBy, "sort", "count", "pattern order: count, severity, first, last, hosts")
	fs.BoolVar(&cfg.examples, "examples", false, "text: show an example message under each pattern")
	fs.BoolVar(&cfg.wide, "wide", false, "text: do not truncate templates")
	fs.BoolVar(&cfg.quiet, "quiet", false, "text: only print the status line, spikes and new patterns")
	fs.StringVar(&cfg.timeout, "timeout", "5m", "with --journal: maximum run time of journalctl")
	fs.BoolVar(&cfg.version, "version", false, "print the version and exit")
	return fs
}

// parseInterleaved accepts flags before, between and after positionals.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func usageErr(env Env, format string, a ...any) int {
	fmt.Fprintf(env.Stderr, "syslog-triage: %s\n", fmt.Sprintf(format, a...))
	return ExitUnknown
}

func compileRe(s string) (*regexp.Regexp, error) {
	if s == "" {
		return nil, nil
	}
	return regexp.Compile(s)
}

func (c *config) validate(env Env, now time.Time) error {
	var err error
	if c.parsedLoc, err = time.LoadLocation(c.tz); err != nil {
		return fmt.Errorf("--tz: %v", err)
	}
	if c.sinceT, err = ParseTime(c.since, now, c.parsedLoc); err != nil {
		return fmt.Errorf("--since: %v", err)
	}
	if c.untilT, err = ParseTime(c.until, now, c.parsedLoc); err != nil {
		return fmt.Errorf("--until: %v", err)
	}
	if !c.sinceT.IsZero() && !c.untilT.IsZero() && !c.untilT.After(c.sinceT) {
		return errors.New("--until must be after --since")
	}
	if c.bucketD, err = ParseDuration(c.bucket); err != nil || c.bucketD < time.Second {
		return fmt.Errorf("--bucket: invalid or below 1s: %q", c.bucket)
	}
	if c.recent != "" {
		if c.recentD, err = ParseDuration(c.recent); err != nil || c.recentD <= 0 {
			return fmt.Errorf("--recent: invalid duration %q", c.recent)
		}
	}
	if c.maxAgeD, err = ParseDuration(c.modelMaxAge); err != nil || c.maxAgeD < 0 {
		return fmt.Errorf("--model-max-age: invalid duration %q", c.modelMaxAge)
	}
	if c.toutD, err = ParseDuration(c.timeout); err != nil || c.toutD <= 0 {
		return fmt.Errorf("--timeout: invalid duration %q", c.timeout)
	}
	if c.sim < 0 || c.sim > 1 {
		return errors.New("--sim must be between 0 and 1")
	}
	if c.depth < 3 || c.depth > 32 {
		return errors.New("--depth must be between 3 and 32")
	}
	if c.maxChildren < 2 {
		return errors.New("--max-children must be at least 2")
	}
	if c.maxTokens < 0 || c.maxTokens == 1 {
		return errors.New("--max-tokens must be 0 or at least 2")
	}
	if c.window < 1 || c.minBaseline < 1 || c.minBaseline > c.window {
		return errors.New("--window and --min-baseline must be >= 1 and min-baseline <= window")
	}
	if c.threshold < 0 || c.minRatio < 0 || c.minCount < 1 {
		return errors.New("--threshold and --min-ratio must be >= 0, --min-count >= 1")
	}
	if c.top < 0 {
		return errors.New("--top must be >= 0")
	}
	switch c.sortBy {
	case "count", "severity", "first", "last", "hosts":
	default:
		return fmt.Errorf("--sort: unknown order %q", c.sortBy)
	}
	if c.updateModel && c.model == "" {
		return errors.New("--update-model needs --model FILE")
	}
	if c.year != 0 && (c.year < 1970 || c.year > 9999) {
		return errors.New("--year out of range")
	}
	if c.journal && c.raw {
		return errors.New("--raw cannot be used with --journal")
	}
	if !c.journal && (len(c.units) > 0 || c.journalDir != "") {
		return errors.New("--unit and --journal-dir need --journal")
	}
	return nil
}

func severityFlag(name, v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	s, ok := logrec.ParseSeverity(v)
	if !ok {
		return 0, fmt.Errorf("%s: unknown severity %q (emerg, alert, crit, err, warning, notice, info, debug or 0-7)", name, v)
	}
	return s, nil
}

// Run executes the CLI and returns the process exit code.
func Run(args []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	cfg := &config{explicit: map[string]bool{}}
	fs := newFlagSet(cfg, env)
	files, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUnknown
	}
	fs.Visit(func(f *flag.Flag) { cfg.explicit[f.Name] = true })
	if cfg.version {
		fmt.Fprintf(env.Stdout, "syslog-triage %s\n", Version)
		return ExitOK
	}
	now := env.Now()
	if err := cfg.validate(env, now); err != nil {
		return usageErr(env, "%v", err)
	}
	opt := triage.DefaultOptions()
	if opt.MinSeverity, err = severityFlag("--min-severity", cfg.minSev, -1); err != nil {
		return usageErr(env, "%v", err)
	}
	if opt.AlertSeverity, err = severityFlag("--alert-severity", cfg.alertSev, 7); err != nil {
		return usageErr(env, "%v", err)
	}
	if opt.CritSeverity, err = severityFlag("--crit-severity", cfg.critSev, 3); err != nil {
		return usageErr(env, "%v", err)
	}
	for _, r := range []struct {
		flag, v string
		dst     **regexp.Regexp
	}{{"--app", cfg.app, &opt.App}, {"--exclude-app", cfg.noApp, &opt.NoApp}, {"--host", cfg.host, &opt.Host}} {
		if *r.dst, err = compileRe(r.v); err != nil {
			return usageErr(env, "%s: %v", r.flag, err)
		}
	}
	if cfg.journal && len(files) > 0 {
		return usageErr(env, "--journal reads the local journal: do not give files")
	}
	if !cfg.journal && len(files) == 0 {
		if env.StdinIsTTY {
			fs.Usage()
			return ExitUnknown
		}
		files = []string{"-"}
	}
	nStdin := 0
	for _, f := range files {
		if f == "-" {
			nStdin++
		}
	}
	if nStdin > 1 {
		return usageErr(env, "stdin (-) given more than once")
	}

	// Miner: from the model file when it exists.
	params := drain.Params{Depth: cfg.depth, Sim: cfg.sim, MaxChildren: cfg.maxChildren}
	appSplit := !cfg.noAppSplit
	miner := drain.New(params)
	modelLoaded := false
	if cfg.model != "" {
		m, split, err := drain.LoadModelFile(cfg.model)
		switch {
		case err == nil:
			if (cfg.explicit["sim"] && m.P.Sim != params.Sim) || (cfg.explicit["depth"] && m.P.Depth != params.Depth) ||
				(cfg.explicit["max-children"] && m.P.MaxChildren != params.MaxChildren) || (cfg.explicit["no-app-split"] && split == appSplit) {
				fmt.Fprintf(env.Stderr, "syslog-triage: note: using the clustering parameters stored in %s\n", cfg.model)
			}
			miner, appSplit, modelLoaded = m, split, true
		case errors.Is(err, os.ErrNotExist):
			if !cfg.updateModel {
				return usageErr(env, "model %s does not exist (create it with --update-model)", cfg.model)
			}
			if !cfg.jsonOut {
				fmt.Fprintf(env.Stderr, "syslog-triage: model %s does not exist yet: it will be created, no pattern is reported as new on this run\n", cfg.model)
			}
		default:
			return usageErr(env, "%v", err)
		}
	}

	opt.Bucket = cfg.bucketD
	opt.Spike.Window, opt.Spike.MinBaseline, opt.Spike.K = cfg.window, cfg.minBaseline, cfg.threshold
	opt.Spike.MinCount, opt.Spike.MinRatio = cfg.minCount, cfg.minRatio
	opt.AppSplit = appSplit
	opt.MaxTokens = cfg.maxTokens
	opt.Since, opt.Until = cfg.sinceT, cfg.untilT
	opt.Recent = cfg.recentD
	opt.ModelLoaded = modelLoaded
	an := triage.New(opt, miner)

	truncated := 0
	if cfg.journal {
		n, err := readJournal(cfg, env, an)
		truncated += n
		if err != nil {
			return usageErr(env, "%v", err)
		}
	} else {
		for _, f := range files {
			n, err := readFile(f, cfg, env, an, now)
			truncated += n
			if err != nil {
				return usageErr(env, "%v", err)
			}
		}
	}
	res, err := an.Finish()
	if err != nil {
		return usageErr(env, "%v", err)
	}
	SortPatternsAndTrim(res, cfg.sortBy, cfg.top)

	code := res.ExitCode
	if cfg.updateModel {
		if err := miner.SaveModelFile(cfg.model, appSplit, now, cfg.maxAgeD); err != nil {
			fmt.Fprintf(env.Stderr, "syslog-triage: saving model: %v\n", err)
			code = ExitUnknown
		}
	}
	if cfg.jsonOut {
		out := jsonResult{Result: res, Version: Version, TruncatedLines: truncated}
		if err := writeJSON(env.Stdout, out); err != nil {
			return ExitUnknown
		}
	} else {
		writeText(env.Stdout, res, cfg, truncated)
	}
	return code
}

// SortPatternsAndTrim orders the pattern list and keeps the first top.
func SortPatternsAndTrim(res *triage.Result, by string, top int) {
	triage.SortPatterns(res.Patterns, by)
	if top > 0 && len(res.Patterns) > top {
		res.Patterns = res.Patterns[:top]
	}
}

func readFile(path string, cfg *config, env Env, an *triage.Analyzer, now time.Time) (int, error) {
	r, closer, err := logrec.Open(path, env.Stdin)
	if err != nil {
		return 0, err
	}
	defer closer.Close()
	ref := now
	if path != "-" {
		if st, err := os.Stat(path); err == nil {
			ref = st.ModTime()
		}
	}
	p := &logrec.Parser{Location: cfg.parsedLoc, Ref: ref, Year: cfg.year, Raw: cfg.raw}
	n, err := logrec.ReadLines(r, func(line string) error {
		if line == "" {
			return nil
		}
		rec, ok := p.Parse(line)
		an.Add(rec, ok)
		return nil
	})
	if err != nil {
		name := path
		if path == "-" {
			name = "stdin"
		}
		return n, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

func journalArgs(cfg *config) []string {
	args := []string{"-o", "json", "--no-pager", "-q"}
	if !cfg.sinceT.IsZero() {
		args = append(args, "--since=@"+strconv.FormatInt(cfg.sinceT.Unix(), 10))
	}
	if !cfg.untilT.IsZero() {
		args = append(args, "--until=@"+strconv.FormatInt(cfg.untilT.Unix(), 10))
	}
	for _, u := range cfg.units {
		args = append(args, "--unit="+u)
	}
	if cfg.journalDir != "" {
		args = append(args, "--directory="+cfg.journalDir)
	}
	return args
}

func readJournal(cfg *config, env Env, an *triage.Analyzer) (int, error) {
	if env.Journal == nil {
		return 0, errors.New("journal access is not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.toutD)
	defer cancel()
	out, wait, err := env.Journal(ctx, journalArgs(cfg))
	if err != nil {
		return 0, fmt.Errorf("journalctl: %w", err)
	}
	p := &logrec.Parser{Location: cfg.parsedLoc}
	n, rerr := logrec.ReadLines(out, func(line string) error {
		if line == "" {
			return nil
		}
		rec, ok := p.Parse(line)
		an.Add(rec, ok)
		return nil
	})
	out.Close()
	werr := wait()
	if ctx.Err() != nil {
		return n, fmt.Errorf("journalctl: timed out after %s", cfg.toutD)
	}
	if rerr != nil {
		return n, fmt.Errorf("journalctl: reading output: %w", rerr)
	}
	if werr != nil {
		return n, fmt.Errorf("journalctl: %w", werr)
	}
	return n, nil
}

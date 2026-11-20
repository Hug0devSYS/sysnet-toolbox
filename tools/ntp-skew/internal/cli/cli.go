// Package cli implements ntp-skew's command line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/check"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/ntp"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/sources"
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

const usage = `ntp-skew - compare NTP sources, find falsetickers, check the local clock

Usage:
  ntp-skew [flags] <server> [<server>...]
  ntp-skew [flags] -f servers.txt
  ntp-skew [flags] --config /etc/chrony.conf
  ntp-skew [flags] --system

Every server is queried a few times (client mode, NTPv4, random transmit
timestamp, nothing else about this host is sent). The best exchange of each
server (lowest delay) gives its offset, delay, jitter and root distance;
the RFC 5905 intersection algorithm then separates truechimers from
falsetickers, and the weighted consensus of the truechimers gives the
offset of the local clock. Also reported: unreachable, rate-limiting
(kiss-o'-death) and unsynchronised servers, stale references, servers
synchronised to each other or to this host, no upstream diversity and
leap second disagreement.

Read-only, no privileges needed (unprivileged UDP socket). The local clock
is never adjusted.

Targets: "host", "host:port", "[v6addr]:port", w32time entries
("time.example,0x9"). "pool" lines of a configuration file contribute every
address of the name; other names one address (one server, one vote) unless
--all-addresses is given.

Flags:
`

const exitHelp = `
Exit codes:
  0  OK        sources agree, local clock within --warn
  1  WARNING   unreachable/unsynchronised/rate-limited source, stale reference,
               sync loop, no upstream diversity, local offset above --warn
  2  CRITICAL  falseticker, no majority agreement, local offset above --crit,
               fewer usable sources than --min-sources
  3  UNKNOWN   no usable source, usage error, interrupted
`

// systemConfigs are tried by --system, in order; every existing file is read.
var systemConfigs = []string{
	"/etc/chrony.conf",
	"/etc/chrony/chrony.conf",
	"/etc/ntp.conf",
	"/etc/ntpsec/ntp.conf",
	"/etc/openntpd/ntpd.conf",
	"/etc/systemd/timesyncd.conf",
}

type config struct {
	json        bool
	targetsFile string
	configFiles multiFlag
	system      bool
	ipv4, ipv6  bool
	allAddrs    bool
	samples     int
	interval    time.Duration
	timeout     time.Duration
	concurrency int
	warn, crit  time.Duration
	maxSkew     time.Duration
	maxDist     time.Duration
	maxStratum  int
	maxRefAge   time.Duration
	minSources  int
	allowCommon bool
	promFile    string
	verbose     bool
	color       string
	version     bool
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// Deps lets tests replace the network, the clock and the file system.
type Deps struct {
	Resolve    sources.Resolver
	Dial       ntp.Dialer
	Now        func() time.Time
	Sleep      func(ctx context.Context, d time.Duration) error
	LocalAddrs func() []netip.Addr
	Open       func(name string) (io.ReadCloser, error)
	Stdin      io.Reader
	Getenv     func(string) string
	IsTerminal func(w io.Writer) bool
}

func (d *Deps) fill() {
	if d.Resolve == nil {
		d.Resolve = net.DefaultResolver.LookupNetIP
	}
	if d.Dial == nil {
		d.Dial = ntp.DialUDP
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.LocalAddrs == nil {
		d.LocalAddrs = interfaceAddrs
	}
	if d.Open == nil {
		d.Open = func(name string) (io.ReadCloser, error) { return os.Open(name) }
	}
	if d.Stdin == nil {
		d.Stdin = os.Stdin
	}
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
	if d.IsTerminal == nil {
		d.IsTerminal = isTerminal
	}
}

func interfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, deps *Deps) int {
	if deps == nil {
		deps = &Deps{}
	}
	deps.fill()
	var cfg config
	fs := flag.NewFlagSet("ntp-skew", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cfg.json, "json", false, "emit the report as JSON on stdout")
	fs.StringVar(&cfg.targetsFile, "f", "", "read servers from file, one or more per line ('-' for stdin; '#' comments)")
	fs.Var(&cfg.configFiles, "config", "read servers from an NTP client configuration (chrony, ntpd, timesyncd, w32time peer list); repeatable")
	fs.BoolVar(&cfg.system, "system", false, "read the servers of this host's NTP client configuration ("+strings.Join(systemConfigs, ", ")+")")
	fs.BoolVar(&cfg.ipv4, "4", false, "IPv4 only")
	fs.BoolVar(&cfg.ipv6, "6", false, "IPv6 only")
	fs.BoolVar(&cfg.allAddrs, "all-addresses", false, "measure every address of every name, not only of pools")
	fs.IntVar(&cfg.samples, "samples", 4, "exchanges per server (the lowest-delay one is used)")
	fs.DurationVar(&cfg.interval, "interval", 2*time.Second, "spacing between exchanges with one server (servers rate-limit below ~2s)")
	fs.DurationVar(&cfg.timeout, "timeout", 2*time.Second, "wait time for each answer")
	fs.IntVar(&cfg.concurrency, "concurrency", 16, "servers measured in parallel")
	fs.DurationVar(&cfg.warn, "warn", 100*time.Millisecond, "WARNING when the local clock is further than this from the consensus (0: off)")
	fs.DurationVar(&cfg.crit, "crit", time.Second, "CRITICAL when the local clock is further than this from the consensus (0: off)")
	fs.DurationVar(&cfg.maxSkew, "max-skew", 0, "WARNING for a truechimer further than this from the consensus (0: off)")
	fs.DurationVar(&cfg.maxDist, "max-distance", 1500*time.Millisecond, "root distance above which a source is not selectable (RFC 5905 MAXDIST)")
	fs.IntVar(&cfg.maxStratum, "max-stratum", 0, "WARNING for sources above this stratum (0: off)")
	fs.DurationVar(&cfg.maxRefAge, "max-ref-age", 24*time.Hour, "WARNING when a source last updated from its own upstream longer ago (0: off)")
	fs.IntVar(&cfg.minSources, "min-sources", 1, "CRITICAL when fewer sources are usable")
	fs.BoolVar(&cfg.allowCommon, "allow-common-upstream", false, "report sources sharing one upstream as a note instead of a WARNING")
	fs.StringVar(&cfg.promFile, "prom-file", "", "write Prometheus textfile-collector metrics to this file (atomically)")
	fs.BoolVar(&cfg.verbose, "v", false, "log every exchange to stderr")
	fs.StringVar(&cfg.color, "color", "auto", "colorize text output: auto, always, never")
	fs.BoolVar(&cfg.version, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
		fmt.Fprint(stderr, exitHelp)
	}
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUnknown
	}
	if cfg.version {
		fmt.Fprintf(stdout, "ntp-skew %s\n", Version)
		return ExitOK
	}
	if msg := validate(&cfg); msg != "" {
		fmt.Fprintf(stderr, "ntp-skew: %s\n", msg)
		return ExitUnknown
	}

	specs, err := gatherSpecs(&cfg, pos, deps, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "ntp-skew: %v\n", err)
		return ExitUnknown
	}
	if len(specs) == 0 {
		fmt.Fprintln(stderr, "ntp-skew: no server given (arguments, -f, --config or --system); see --help")
		return ExitUnknown
	}

	fam := sources.Any
	if cfg.ipv4 {
		fam = sources.IPv4
	} else if cfg.ipv6 {
		fam = sources.IPv6
	}
	srcs, rerrs := sources.Expand(ctx, specs, fam, cfg.allAddrs, deps.Resolve)
	var unresolved []check.Unresolved
	for _, s := range specs {
		if e, ok := rerrs[s.String()]; ok {
			unresolved = append(unresolved, check.Unresolved{Spec: s, Err: e})
			delete(rerrs, s.String())
		}
	}

	inputs := measureAll(ctx, srcs, &cfg, deps, stderr)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "ntp-skew: interrupted; no report written")
		if cfg.json {
			_ = json.NewEncoder(stdout).Encode(map[string]any{"status": "UNKNOWN", "error": "interrupted"})
		}
		return ExitUnknown
	}

	rep := check.Analyse(inputs, unresolved, check.Config{
		WarnOffset: cfg.warn, CritOffset: cfg.crit, MaxSkew: cfg.maxSkew, MaxDistance: cfg.maxDist,
		MaxStratum: cfg.maxStratum, MaxRefAge: cfg.maxRefAge, MinSources: cfg.minSources,
		AllowCommonUpstream: cfg.allowCommon, LocalAddrs: deps.LocalAddrs(), Now: deps.Now(),
	})

	if cfg.promFile != "" {
		if err := writeProm(cfg.promFile, rep); err != nil {
			fmt.Fprintf(stderr, "ntp-skew: --prom-file: %v\n", err)
			rep.Status = check.Worse(rep.Status, check.Unknown)
		}
	}
	if cfg.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "ntp-skew: %v\n", err)
			return ExitUnknown
		}
	} else {
		color := cfg.color == "always" || cfg.color == "auto" && deps.Getenv("NO_COLOR") == "" && deps.IsTerminal(stdout)
		renderText(stdout, rep, color)
	}
	return int(rep.Status)
}

func validate(cfg *config) string {
	switch {
	case cfg.ipv4 && cfg.ipv6:
		return "-4 and -6 are mutually exclusive"
	case cfg.samples < 1 || cfg.samples > 64:
		return "--samples must be between 1 and 64"
	case cfg.interval < 0:
		return "--interval must not be negative"
	case cfg.timeout <= 0:
		return "--timeout must be positive"
	case cfg.concurrency < 1:
		return "--concurrency must be at least 1"
	case cfg.warn < 0 || cfg.crit < 0 || cfg.maxSkew < 0 || cfg.maxRefAge < 0:
		return "thresholds must not be negative"
	case cfg.warn > 0 && cfg.crit > 0 && cfg.warn > cfg.crit:
		return "--warn must not exceed --crit"
	case cfg.maxDist <= 0:
		return "--max-distance must be positive"
	case cfg.maxStratum < 0 || cfg.maxStratum > 15:
		return "--max-stratum must be between 0 and 15"
	case cfg.minSources < 0:
		return "--min-sources must not be negative"
	case cfg.color != "auto" && cfg.color != "always" && cfg.color != "never":
		return fmt.Sprintf("invalid --color %q (auto, always, never)", cfg.color)
	}
	return ""
}

func gatherSpecs(cfg *config, pos []string, deps *Deps, stderr io.Writer) ([]sources.Spec, error) {
	var specs []sources.Spec
	for _, p := range pos {
		s, err := sources.ParseTarget(p, "args")
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	if cfg.targetsFile != "" {
		var r io.Reader
		name := cfg.targetsFile
		if name == "-" {
			r, name = deps.Stdin, "stdin"
		} else {
			f, err := deps.Open(name)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			r = f
		}
		list, err := sources.ParseList(r, name)
		if err != nil {
			return nil, err
		}
		specs = append(specs, list...)
	}
	files := append([]string(nil), cfg.configFiles...)
	optional := map[string]bool{}
	if cfg.system {
		for _, f := range systemConfigs {
			files = append(files, f)
			optional[f] = true
		}
	}
	found := false
	for _, name := range files {
		f, err := deps.Open(name)
		if err != nil {
			if optional[name] && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		list, err := sources.ParseConfig(f, name)
		f.Close()
		if err != nil {
			if optional[name] {
				fmt.Fprintf(stderr, "ntp-skew: %v (skipped)\n", err)
				continue
			}
			return nil, err
		}
		found = true
		specs = append(specs, list...)
	}
	if cfg.system && !found {
		return nil, fmt.Errorf("--system: no NTP client configuration with servers found")
	}
	return dedupeSpecs(specs), nil
}

func dedupeSpecs(in []sources.Spec) []sources.Spec {
	seen := map[string]bool{}
	var out []sources.Spec
	for _, s := range in {
		k := strings.ToLower(strings.TrimSuffix(s.Host, ".")) + "|" + fmt.Sprint(s.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

func measureAll(ctx context.Context, srcs []sources.Source, cfg *config, deps *Deps, stderr io.Writer) []check.Input {
	inputs := make([]check.Input, len(srcs))
	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup
	var logMu sync.Mutex
	for i, s := range srcs {
		wg.Add(1)
		go func(i int, s sources.Source) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				inputs[i] = check.Input{Source: s, M: &ntp.Measurement{Addr: s.Addr, LastError: ctx.Err()}}
				return
			}
			defer func() { <-sem }()
			m := ntp.Measure(ctx, s.Addr, ntp.Options{
				Samples: cfg.samples, Interval: cfg.interval, Timeout: cfg.timeout,
				Dial: deps.Dial, Now: deps.Now, Sleep: deps.Sleep,
			})
			if cfg.verbose {
				logMu.Lock()
				for _, smp := range m.Samples {
					fmt.Fprintf(stderr, "%s %s: stratum %d offset %s delay %s\n", s.Spec.Host, s.Addr,
						smp.Packet.Stratum, check.FormatSigned(smp.Offset), check.FormatDuration(smp.Delay))
				}
				for _, e := range m.Errors {
					fmt.Fprintf(stderr, "%s %s: %s\n", s.Spec.Host, s.Addr, e)
				}
				logMu.Unlock()
			}
			inputs[i] = check.Input{Source: s, M: m}
		}(i, s)
	}
	wg.Wait()
	return inputs
}

// parseInterleaved accepts flags after positional arguments
// ("ntp-skew a b --json").
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

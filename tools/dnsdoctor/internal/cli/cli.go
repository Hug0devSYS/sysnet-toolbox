// Package cli implements dnsdoctor's command line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/doctor"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/transport"
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

const usage = `dnsdoctor - end-to-end DNS zone diagnostics

Usage:
  dnsdoctor [flags] <zone> [<zone>...]

Checks performed (read-only, standard DNS queries only):
  delegation      iterative walk from the root servers to the zone
  ns-consistency  parent vs child NS RRsets, per-server NS RRset
  glue            missing or stale glue for in-bailiwick name servers
  lame-delegation unreachable, refusing or non-authoritative servers
  soa-serial      SOA serial drift between every server address
  diversity       all servers in one /24 (IPv4) or /48 (IPv6)
  dnssec          DS/DNSKEY chain of trust from the root, signature
                  expiry, deprecated algorithms and digests

Flags:
`

const exitHelp = `
Exit codes:
  0  OK        no warnings or errors
  1  WARNING   at least one warning
  2  CRITICAL  at least one error (lame server, bogus DNSSEC, NXDOMAIN, ...)
  3  UNKNOWN   usage error or the diagnosis could not be completed
`

type config struct {
	json        bool
	timeout     time.Duration
	retries     int
	ipv4, ipv6  bool
	noDNSSEC    bool
	anchorFile  string
	sigWarn     string
	maxTime     time.Duration
	roots       string
	port        uint
	concurrency int
	verbose     bool
	color       string
	version     bool
}

// Run executes the CLI and returns the process exit code. x overrides the
// network transport (used by tests); nil means the real network.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, x transport.Exchanger) int {
	var cfg config
	fs := flag.NewFlagSet("dnsdoctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cfg.json, "json", false, "emit a JSON array of reports on stdout")
	fs.DurationVar(&cfg.timeout, "timeout", 3*time.Second, "per-query timeout")
	fs.IntVar(&cfg.retries, "retries", 1, "UDP retries after a timeout")
	fs.BoolVar(&cfg.ipv4, "4", false, "use IPv4 transport only")
	fs.BoolVar(&cfg.ipv6, "6", false, "use IPv6 transport only")
	fs.BoolVar(&cfg.noDNSSEC, "no-dnssec", false, "skip DNSSEC chain-of-trust validation")
	fs.StringVar(&cfg.anchorFile, "trust-anchor", "", "file with root DS trust anchors (replaces the built-in IANA anchors)")
	fs.StringVar(&cfg.sigWarn, "sig-warn", "7d", "warn when a zone RRSIG expires within this duration (e.g. 72h, 7d; 0 disables)")
	fs.DurationVar(&cfg.maxTime, "max-time", 90*time.Second, "overall time budget per zone")
	fs.StringVar(&cfg.roots, "roots", "", "comma-separated root server addresses (lab/private roots)")
	fs.UintVar(&cfg.port, "port", 53, "DNS server port")
	fs.IntVar(&cfg.concurrency, "concurrency", 8, "parallel name server probes")
	fs.BoolVar(&cfg.verbose, "v", false, "log every query to stderr")
	fs.StringVar(&cfg.color, "color", "auto", "colorize text output: auto, always, never")
	fs.BoolVar(&cfg.version, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
		fmt.Fprint(stderr, exitHelp)
	}

	zones, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUnknown
	}
	if cfg.version {
		fmt.Fprintf(stdout, "dnsdoctor %s\n", Version)
		return ExitOK
	}
	if len(zones) == 0 {
		fmt.Fprintln(stderr, "dnsdoctor: missing <zone> argument (see --help)")
		return ExitUnknown
	}
	if cfg.ipv4 && cfg.ipv6 {
		fmt.Fprintln(stderr, "dnsdoctor: -4 and -6 are mutually exclusive")
		return ExitUnknown
	}
	if cfg.timeout <= 0 || cfg.maxTime <= 0 || cfg.retries < 0 || cfg.concurrency <= 0 || cfg.port == 0 || cfg.port > 65535 {
		fmt.Fprintln(stderr, "dnsdoctor: --timeout, --max-time, --concurrency and --port must be positive, --retries >= 0")
		return ExitUnknown
	}
	sigWarn, err := ParseDuration(cfg.sigWarn)
	if err != nil {
		fmt.Fprintf(stderr, "dnsdoctor: --sig-warn: %v\n", err)
		return ExitUnknown
	}

	if x == nil {
		x = &transport.Net{Timeout: cfg.timeout, Retries: cfg.retries}
	}
	opts := doctor.Options{
		DNSSEC:        !cfg.noDNSSEC,
		SigExpiryWarn: sigWarn,
		Concurrency:   cfg.concurrency,
	}
	if cfg.anchorFile != "" {
		data, err := os.ReadFile(cfg.anchorFile)
		if err != nil {
			fmt.Fprintf(stderr, "dnsdoctor: %v\n", err)
			return ExitUnknown
		}
		if opts.TrustAnchors, err = doctor.ParseTrustAnchors(string(data)); err != nil {
			fmt.Fprintf(stderr, "dnsdoctor: %s: %v\n", cfg.anchorFile, err)
			return ExitUnknown
		}
	}
	var roots []netip.Addr
	if cfg.roots != "" {
		for _, s := range strings.Split(cfg.roots, ",") {
			a, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				fmt.Fprintf(stderr, "dnsdoctor: --roots: invalid address %q\n", s)
				return ExitUnknown
			}
			roots = append(roots, a)
		}
	}

	color := cfg.color == "always" || (cfg.color == "auto" && isTerminal(stdout) && os.Getenv("NO_COLOR") == "")
	exit := ExitOK
	var reports []*doctor.Report
	for _, z := range zones {
		r := doctor.NewResolver(x)
		r.Port = uint16(cfg.port)
		if roots != nil {
			r.Roots = roots
		}
		if cfg.ipv4 {
			r.UseIPv6 = false
		}
		if cfg.ipv6 {
			r.UseIPv4 = false
		}
		if cfg.verbose {
			r.Logf = func(f string, a ...any) { fmt.Fprintf(stderr, f+"\n", a...) }
		}
		d := &doctor.Doctor{R: r, Opts: opts}
		zctx, cancel := context.WithTimeout(ctx, cfg.maxTime)
		rep, err := d.Diagnose(zctx, z)
		cancel()
		code := exitFor(rep, err)
		if code > exit {
			exit = code
		}
		reports = append(reports, rep)
		if !cfg.json {
			if len(reports) > 1 {
				fmt.Fprintln(stdout, strings.Repeat("-", 72))
			}
			doctor.WriteText(stdout, rep, color)
		}
	}
	if cfg.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintf(stderr, "dnsdoctor: %v\n", err)
			return ExitUnknown
		}
	}
	return exit
}

func exitFor(rep *doctor.Report, err error) int {
	if err != nil && !errors.Is(err, doctor.ErrNXDomain) && !errors.Is(err, doctor.ErrNotZoneApex) {
		return ExitUnknown
	}
	switch {
	case rep.Summary.Errors > 0 || err != nil:
		return ExitCritical
	case rep.Summary.Warnings > 0:
		return ExitWarning
	}
	return ExitOK
}

// parseInterleaved allows flags after positional arguments.
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

// ParseDuration accepts Go durations plus a "d" (day) suffix.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

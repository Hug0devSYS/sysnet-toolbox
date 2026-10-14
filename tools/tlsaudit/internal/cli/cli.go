// Package cli implements tlsaudit's command line interface.
package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/audit"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/target"
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

const usage = `tlsaudit - TLS endpoint fleet audit

Usage:
  tlsaudit [flags] <target> [<target>...]
  tlsaudit [flags] -f targets.txt

Target syntax (quote targets that carry options):
  host | host:port | [v6addr]:port | scheme://host[:port]   (default port 443)
  schemes: https tls smtps imaps pop3s ftps ldaps (implicit TLS),
           smtp submission imap pop3 ftp ldap postgres (STARTTLS)
  options: sni=NAME|none  connect=IP[:PORT]  starttls=PROTO|none
  e.g.     'www.example.com connect=10.0.0.5'  smtp://mx.example.com

Checks (read-only: handshakes only, no application data, no credentials):
  expiry        leaf and chain expiry (--warn-days, --crit-days)
  hostname      SAN match against the SNI / target name
  chain         trust, incomplete chain, untrusted root, order, extra certs
  certificate   key size, SHA-1 signatures, missing SAN, validity period
  protocol      SSLv3, TLS 1.0/1.1 enabled, TLS 1.2/1.3 missing
  cipher        insecure/weak/legacy suites (full enumeration, TLS <= 1.2)
  key-exchange  DHE group size (Logjam)
  ocsp          stapling, Must-Staple, revoked/unknown/stale staple
  renegotiation, fallback-scsv

Flags:
`

const exitHelp = `
Exit codes:
  0  OK        no warnings or errors on any target
  1  WARNING   at least one warning
  2  CRITICAL  at least one error (expired, untrusted, unreachable, ...)
  3  UNKNOWN   usage error, unreadable input, or output could not be written
`

type config struct {
	json        bool
	summary     bool
	promFile    string
	targetsFile string
	timeout     time.Duration
	maxTime     time.Duration
	concurrency int
	warnDays    int
	critDays    int
	caFile      string
	caOnly      bool
	noCiphers   bool
	fetchAIA    bool
	ipv4, ipv6  bool
	verbose     bool
	color       string
	version     bool
}

// Deps lets tests replace the network and the clock.
type Deps struct {
	Dialer   audit.Dialer
	Resolver audit.Resolver
	Now      func() time.Time
	Stdin    io.Reader
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, deps *Deps) int {
	var cfg config
	fs := flag.NewFlagSet("tlsaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cfg.json, "json", false, "emit a JSON array of reports on stdout")
	fs.BoolVar(&cfg.summary, "summary", false, "one line per target instead of full reports")
	fs.StringVar(&cfg.promFile, "prom-file", "", "also write Prometheus metrics to this file (atomic; node_exporter textfile collector)")
	fs.StringVar(&cfg.targetsFile, "f", "", "read targets from file, one per line ('-' for stdin; '#' comments)")
	fs.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-connection timeout (dial + STARTTLS + handshake)")
	fs.DurationVar(&cfg.maxTime, "max-time", 2*time.Minute, "overall time budget per target")
	fs.IntVar(&cfg.concurrency, "concurrency", 8, "targets audited in parallel")
	fs.IntVar(&cfg.warnDays, "warn-days", 30, "WARNING when a certificate expires within this many days")
	fs.IntVar(&cfg.critDays, "crit-days", 7, "CRITICAL when a certificate expires within this many days")
	fs.StringVar(&cfg.caFile, "ca-file", "", "PEM bundle of extra trusted roots (private PKI)")
	fs.BoolVar(&cfg.caOnly, "ca-only", false, "trust only --ca-file, not the system roots")
	fs.BoolVar(&cfg.noCiphers, "no-ciphers", false, "skip cipher suite enumeration (about 6 connections per target instead of up to ~150)")
	fs.BoolVar(&cfg.fetchAIA, "fetch-aia", false, "download missing intermediates from AIA URLs to confirm incomplete chains")
	fs.BoolVar(&cfg.ipv4, "4", false, "connect over IPv4 only")
	fs.BoolVar(&cfg.ipv6, "6", false, "connect over IPv6 only")
	fs.BoolVar(&cfg.verbose, "v", false, "log every connection to stderr")
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
		fmt.Fprintf(stdout, "tlsaudit %s\n", Version)
		return ExitOK
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "tlsaudit: "+format+"\n", a...)
		return ExitUnknown
	}
	switch {
	case cfg.ipv4 && cfg.ipv6:
		return fail("-4 and -6 are mutually exclusive")
	case cfg.json && cfg.summary:
		return fail("--json and --summary are mutually exclusive")
	case cfg.timeout <= 0 || cfg.maxTime <= 0 || cfg.concurrency <= 0:
		return fail("--timeout, --max-time and --concurrency must be positive")
	case cfg.warnDays < 0 || cfg.critDays < 0 || cfg.critDays > cfg.warnDays:
		return fail("need 0 <= --crit-days <= --warn-days")
	case cfg.caOnly && cfg.caFile == "":
		return fail("--ca-only requires --ca-file")
	case cfg.color != "auto" && cfg.color != "always" && cfg.color != "never":
		return fail("--color must be auto, always or never")
	}
	if deps == nil {
		deps = &Deps{}
	}

	var targets []target.Target
	for _, p := range pos {
		t, err := target.Parse(p)
		if err != nil {
			return fail("%s: %v", p, err)
		}
		targets = append(targets, t)
	}
	if cfg.targetsFile != "" {
		var r io.Reader
		name := cfg.targetsFile
		if name == "-" {
			r, name = deps.Stdin, "stdin"
			if r == nil {
				r = os.Stdin
			}
		} else {
			f, err := os.Open(name)
			if err != nil {
				return fail("%v", err)
			}
			defer f.Close()
			r = f
		}
		ts, err := target.ParseList(r, name)
		if err != nil {
			return fail("%v", err)
		}
		targets = append(targets, ts...)
	}
	if len(targets) == 0 {
		return fail("no target given (see --help)")
	}

	opts := audit.Options{
		Timeout:  cfg.timeout,
		WarnDays: cfg.warnDays,
		CritDays: cfg.critDays,
		Ciphers:  !cfg.noCiphers,
		FetchAIA: cfg.fetchAIA,
		Now:      deps.Now,
	}
	switch {
	case cfg.ipv4:
		opts.Network = "tcp4"
	case cfg.ipv6:
		opts.Network = "tcp6"
	}
	if cfg.caFile != "" {
		pool, err := loadRoots(cfg.caFile, cfg.caOnly)
		if err != nil {
			return fail("%v", err)
		}
		opts.Roots = pool
	}
	var logMu sync.Mutex
	if cfg.verbose {
		opts.Logf = func(f string, a ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			fmt.Fprintf(stderr, f+"\n", a...)
		}
	}
	a := audit.New(opts)
	if deps.Dialer != nil {
		a.Dialer = deps.Dialer
	}
	if deps.Resolver != nil {
		a.Resolver = deps.Resolver
	}

	reports := make([]*audit.Report, len(targets))
	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t target.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			tctx, cancel := context.WithTimeout(ctx, cfg.maxTime)
			defer cancel()
			reports[i] = a.Audit(tctx, t)
		}(i, t)
	}
	wg.Wait()

	exit := ExitOK
	for _, r := range reports {
		code := ExitOK
		switch r.Summary.Status {
		case "error":
			code = ExitCritical
		case "warning":
			code = ExitWarning
		}
		exit = max(exit, code)
	}

	color := cfg.color == "always" || (cfg.color == "auto" && isTerminal(stdout) && os.Getenv("NO_COLOR") == "")
	switch {
	case cfg.json:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return fail("%v", err)
		}
	case cfg.summary:
		audit.WriteSummary(stdout, reports)
	default:
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(stdout, strings.Repeat("-", 72))
			}
			audit.WriteText(stdout, r, color)
		}
	}
	if cfg.promFile != "" {
		now := time.Now()
		if deps.Now != nil {
			now = deps.Now()
		}
		if err := audit.WritePromFile(cfg.promFile, reports, now); err != nil {
			return fail("writing %s: %v", cfg.promFile, err)
		}
	}
	return exit
}

func loadRoots(path string, only bool) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !only {
		sys, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system roots: %w (use --ca-only)", err)
		}
		pool = sys
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: no PEM certificate found", path)
	}
	return pool, nil
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

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

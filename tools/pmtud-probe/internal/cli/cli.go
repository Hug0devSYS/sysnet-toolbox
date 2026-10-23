// Package cli implements pmtud-probe's command line interface.
package cli

import (
	"bufio"
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

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/pmtu"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/probe"
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

const usage = `pmtud-probe - path MTU discovery and PMTUD black-hole detection

Usage:
  pmtud-probe [flags] <host|address> [<host|address>...]
  pmtud-probe [flags] -f targets.txt

For every target (both IPv4 and IPv6 unless -4/-6 is given) pmtud-probe
finds the largest packet that reaches it unfragmented, tells whether routers
signal the constriction with ICMP "fragmentation needed" / ICMPv6 "packet
too big" (PMTUD works) or drop oversized packets silently (PMTUD black
hole), and with --tcp checks that the target's TCP MSS fits the path (MSS
clamping).

Probes: --method icmp sends ICMP echo requests (unprivileged ping sockets,
sysctl net.ipv4.ping_group_range); --method udp sends UDP datagrams to a
closed port and expects ICMP port unreachable; auto (default) uses ICMP
when allowed and falls back to UDP. No root privileges are needed. The tool
only sends probes and TCP handshakes; it never changes the system.

Flags:
`

const exitHelp = `
Exit codes:
  0  OK        full MTU, or a constriction correctly signalled by ICMP
  1  WARNING   e.g. MSS not clamped, unexpected MTU, oversize packets rejected
  2  CRITICAL  PMTUD black hole, IPv6 path below 1280, unclamped MSS on a black hole
  3  UNKNOWN   target not answering, usage error, unsupported platform
`

type config struct {
	json        bool
	targetsFile string
	ipv4, ipv6  bool
	method      string
	port        int
	tcpPort     int
	max         int
	expect      int
	timeout     time.Duration
	retries     int
	maxTime     time.Duration
	concurrency int
	verbose     bool
	color       string
	version     bool
}

// Deps lets tests replace the network and the kernel.
type Deps struct {
	Resolve   func(ctx context.Context, network, host string) ([]netip.Addr, error)
	NewProber func(addr netip.Addr, method probe.Method, udpPort int) (probe.Prober, error)
	Route     func(addr netip.Addr) (probe.Route, error)
	TCP       func(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (probe.TCPInfo, error)
	Stdin     io.Reader
}

func (d *Deps) fill() {
	if d.Resolve == nil {
		d.Resolve = net.DefaultResolver.LookupNetIP
	}
	if d.NewProber == nil {
		d.NewProber = probe.New
	}
	if d.Route == nil {
		d.Route = probe.LookupRoute
	}
	if d.TCP == nil {
		d.TCP = probe.TCPCheck
	}
	if d.Stdin == nil {
		d.Stdin = os.Stdin
	}
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, deps *Deps) int {
	var cfg config
	fs := flag.NewFlagSet("pmtud-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cfg.json, "json", false, "emit a JSON array of reports on stdout")
	fs.StringVar(&cfg.targetsFile, "f", "", "read targets from file, one per line ('-' for stdin; '#' comments)")
	fs.BoolVar(&cfg.ipv4, "4", false, "IPv4 only")
	fs.BoolVar(&cfg.ipv6, "6", false, "IPv6 only")
	fs.StringVar(&cfg.method, "method", "auto", "probe method: auto, icmp or udp")
	fs.IntVar(&cfg.port, "port", 33434, "destination port of UDP probes (should be closed on the target)")
	fs.IntVar(&cfg.tcpPort, "tcp", 0, "also check the TCP MSS against this port (handshake only, e.g. 443)")
	fs.IntVar(&cfg.max, "max", 0, "largest packet size to try (default: outgoing interface MTU)")
	fs.IntVar(&cfg.expect, "expect-mtu", 0, "WARNING when the path MTU differs from this value")
	fs.DurationVar(&cfg.timeout, "timeout", time.Second, "wait time for each probe's answer")
	fs.IntVar(&cfg.retries, "retries", 1, "extra attempts before a size counts as unanswered")
	fs.DurationVar(&cfg.maxTime, "max-time", 2*time.Minute, "overall time budget per target and family")
	fs.IntVar(&cfg.concurrency, "concurrency", 4, "targets probed in parallel")
	fs.BoolVar(&cfg.verbose, "v", false, "log every probe to stderr")
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
		fmt.Fprintf(stdout, "pmtud-probe %s\n", Version)
		return ExitOK
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "pmtud-probe: "+format+"\n", a...)
		return ExitUnknown
	}
	switch {
	case cfg.ipv4 && cfg.ipv6:
		return fail("-4 and -6 are mutually exclusive")
	case cfg.method != "auto" && cfg.method != "icmp" && cfg.method != "udp":
		return fail("--method must be auto, icmp or udp")
	case cfg.port < 1 || cfg.port > 65535:
		return fail("--port must be in 1-65535")
	case cfg.tcpPort < 0 || cfg.tcpPort > 65535:
		return fail("--tcp must be a port in 1-65535")
	case cfg.max != 0 && (cfg.max < 68 || cfg.max > 65535):
		return fail("--max must be in 68-65535")
	case cfg.expect != 0 && (cfg.expect < 68 || cfg.expect > 65535):
		return fail("--expect-mtu must be in 68-65535")
	case cfg.timeout <= 0 || cfg.maxTime <= 0 || cfg.concurrency <= 0:
		return fail("--timeout, --max-time and --concurrency must be positive")
	case cfg.retries < 0 || cfg.retries > 10:
		return fail("--retries must be in 0-10")
	case cfg.color != "auto" && cfg.color != "always" && cfg.color != "never":
		return fail("--color must be auto, always or never")
	}
	if deps == nil {
		deps = &Deps{}
	}
	deps.fill()

	targets := pos
	if cfg.targetsFile != "" {
		var r io.Reader = deps.Stdin
		if cfg.targetsFile != "-" {
			f, err := os.Open(cfg.targetsFile)
			if err != nil {
				return fail("%v", err)
			}
			defer f.Close()
			r = f
		}
		ts, err := readTargets(r)
		if err != nil {
			return fail("%s: %v", cfg.targetsFile, err)
		}
		targets = append(targets, ts...)
	}
	if len(targets) == 0 {
		return fail("no target given (see --help)")
	}

	var logMu sync.Mutex
	logf := func(string, ...any) {}
	if cfg.verbose {
		logf = func(f string, a ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			fmt.Fprintf(stderr, f+"\n", a...)
		}
	}

	results := make([][]*pmtu.Report, len(targets))
	notes := make([][]string, len(targets))
	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], notes[i] = runTarget(ctx, t, &cfg, deps, logf)
		}(i, t)
	}
	wg.Wait()

	var reports []*pmtu.Report
	for i := range results {
		reports = append(reports, results[i]...)
		for _, n := range notes[i] {
			fmt.Fprintf(stderr, "pmtud-probe: %s\n", n)
		}
	}
	exit := ExitOK
	for _, r := range reports {
		exit = max(exit, exitCode(r.Status))
	}
	if cfg.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return fail("%v", err)
		}
		return exit
	}
	color := cfg.color == "always" || (cfg.color == "auto" && isTerminal(stdout) && os.Getenv("NO_COLOR") == "")
	for i, r := range reports {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		WriteText(stdout, r, color)
	}
	return exit
}

func exitCode(s pmtu.Severity) int {
	switch s {
	case pmtu.SevWarning:
		return ExitWarning
	case pmtu.SevCritical:
		return ExitCritical
	case pmtu.SevUnknown:
		return ExitUnknown
	}
	return ExitOK
}

// runTarget resolves one target and probes one address per family.
func runTarget(ctx context.Context, target string, cfg *config, deps *Deps, logf func(string, ...any)) ([]*pmtu.Report, []string) {
	unknown := func(fam, msg string) []*pmtu.Report {
		return []*pmtu.Report{{Target: target, Family: fam, PMTUD: pmtu.PMTUDUnknown, Status: pmtu.SevUnknown,
			Findings: []pmtu.Finding{{Code: "resolve", Severity: pmtu.SevUnknown, Message: msg}}, Probes: []pmtu.ProbeLog{}}}
	}
	network := "ip"
	switch {
	case cfg.ipv4:
		network = "ip4"
	case cfg.ipv6:
		network = "ip6"
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		a = a.Unmap()
		if (cfg.ipv4 && !a.Is4()) || (cfg.ipv6 && !a.Is6()) {
			return unknown("", fmt.Sprintf("%s does not match the requested address family", target)), nil
		}
		addrs = []netip.Addr{a}
	} else {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		res, err := deps.Resolve(rctx, network, target)
		cancel()
		if err != nil {
			return unknown("", fmt.Sprintf("cannot resolve %s: %v", target, err)), nil
		}
		var v4, v6 netip.Addr
		for _, a := range res {
			a = a.Unmap()
			if a.Is4() && !v4.IsValid() {
				v4 = a
			} else if a.Is6() && !v6.IsValid() {
				v6 = a
			}
		}
		for _, a := range []netip.Addr{v4, v6} {
			if a.IsValid() {
				addrs = append(addrs, a)
			}
		}
		if len(addrs) == 0 {
			return unknown("", fmt.Sprintf("%s has no %s address", target, map[string]string{"ip": "IP", "ip4": "IPv4", "ip6": "IPv6"}[network])), nil
		}
	}
	explicit := len(addrs) == 1
	var reps []*pmtu.Report
	var notes []string
	for _, a := range addrs {
		fam := "ipv4"
		if a.Is6() {
			fam = "ipv6"
		}
		rt, err := deps.Route(a)
		if err != nil {
			if !explicit {
				notes = append(notes, fmt.Sprintf("%s: skipping %s (%s): %v", target, fam, a, err))
				continue
			}
			reps = append(reps, unknown(fam, fmt.Sprintf("%s: %v", a, err))...)
			continue
		}
		reps = append(reps, probeAddr(ctx, target, a, rt, cfg, deps, logf))
	}
	if len(reps) == 0 {
		return unknown("", fmt.Sprintf("no local route to any address of %s", target)), notes
	}
	return reps, notes
}

func probeAddr(ctx context.Context, target string, a netip.Addr, rt probe.Route, cfg *config, deps *Deps, logf func(string, ...any)) *pmtu.Report {
	ctx, cancel := context.WithTimeout(ctx, cfg.maxTime)
	defer cancel()
	// The MSS check runs once per address even when the method falls back:
	// the second run reuses the first handshake's TCP_INFO.
	var (
		tcpOnce sync.Once
		tcpInfo probe.TCPInfo
		tcpErr  error
	)
	opt := pmtu.Options{
		Max: cfg.max, Timeout: cfg.timeout, Retries: cfg.retries, ExpectMTU: cfg.expect,
		TCPPort: cfg.tcpPort, Logf: logf,
		TCP: func(ctx context.Context, a netip.Addr, port int, d time.Duration) (probe.TCPInfo, error) {
			tcpOnce.Do(func() { tcpInfo, tcpErr = deps.TCP(ctx, a, port, d) })
			return tcpInfo, tcpErr
		},
	}
	fam := "ipv4"
	if a.Is6() {
		fam = "ipv6"
	}
	methods := []probe.Method{probe.Method(cfg.method)}
	if cfg.method == "auto" {
		methods = []probe.Method{probe.MethodICMP, probe.MethodUDP}
	}
	var rep *pmtu.Report
	var notes []pmtu.Finding
	for i, m := range methods {
		p, err := deps.NewProber(a, m, cfg.port)
		if err != nil {
			if cfg.method == "auto" && errors.Is(err, probe.ErrPermission) {
				logf("%s: ICMP sockets not permitted, using UDP probes", target)
				continue
			}
			return &pmtu.Report{Target: target, Address: a.String(), Family: fam, Method: string(m), Route: rt,
				PMTUD: pmtu.PMTUDUnknown, Status: pmtu.SevUnknown, Probes: []pmtu.ProbeLog{},
				Findings: []pmtu.Finding{{Code: "probe-error", Severity: pmtu.SevUnknown, Message: err.Error()}}}
		}
		r := pmtu.Run(ctx, target, p, rt, opt)
		rep = r
		if i+1 < len(methods) && isUnreachable(r) {
			notes = append(notes, pmtu.Finding{Code: "method-fallback", Severity: pmtu.SevInfo,
				Message: fmt.Sprintf("%s does not answer ICMP echo; fell back to UDP probes to port %d", a, cfg.port)})
			continue
		}
		break
	}
	if rep == nil {
		return &pmtu.Report{Target: target, Address: a.String(), Family: fam, Route: rt, PMTUD: pmtu.PMTUDUnknown,
			Status: pmtu.SevUnknown, Probes: []pmtu.ProbeLog{},
			Findings: []pmtu.Finding{{Code: "probe-error", Severity: pmtu.SevUnknown, Message: "no usable probe method"}}}
	}
	if len(notes) > 0 {
		rep.Findings = append(notes, rep.Findings...)
		for _, f := range notes {
			if f.Severity.Rank() > rep.Status.Rank() {
				rep.Status = f.Severity
			}
		}
	}
	return rep
}

func isUnreachable(r *pmtu.Report) bool {
	for _, f := range r.Findings {
		if f.Code == "unreachable" {
			return true
		}
	}
	return false
}

func readTargets(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		out = append(out, strings.Fields(line)...)
	}
	return out, sc.Err()
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

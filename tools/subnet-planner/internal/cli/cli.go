// Package cli implements subnet-planner's command line interface.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/netip"
	"os"
	"strings"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/inventory"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
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

const mainUsage = `subnet-planner - IPv4/IPv6 subnet planning, IPAM overlap checks and route aggregation

Usage:
  subnet-planner plan      --parent PREFIX [flags] NAME=SIZE... | -f requests.csv
  subnet-planner check     [flags] FILE...
  subnet-planner aggregate [flags] [PREFIX...] [-f FILE]
  subnet-planner free      --parent PREFIX [--used FILE] [--exclude PREFIX] [--split N]
  subnet-planner info      [--split N] PREFIX|ADDRESS...
  subnet-planner version

Commands:
  plan       VLSM allocation inside a parent prefix (largest first, best fit),
             avoiding prefixes already in use (NetBox/CSV export or --exclude)
  check      duplicate and overlapping prefixes, duplicate addresses, orphan
             addresses, mask mismatches in NetBox exports, CSV, JSON or lists
  aggregate  minimal exact prefix list, or at most N prefixes with the fewest
             extra addresses (--max); plain, Cisco or Junos prefix-list output
  free       unallocated space of a parent prefix
  info       subnet calculator: mask, ranges, sizes, address type, reverse zones

Run "subnet-planner COMMAND --help" for the flags of a command. Every
command is offline and read-only: it reads files and prints results.

Exit codes:
  0  OK
  1  WARNING   findings of warning severity, invalid input lines
  2  CRITICAL  requests that do not fit, duplicates, forbidden overlaps
  3  UNKNOWN   usage error, unreadable input
`

// Env carries the process environment so tests can replace it.
type Env struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	// StdinIsTTY tells whether stdin is interactive (no implicit read).
	StdinIsTTY bool
	// ColorOK tells whether stdout supports ANSI colours.
	ColorOK bool
}

// DefaultEnv returns the environment of the running process.
func DefaultEnv() Env {
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin,
		StdinIsTTY: isTerminal(os.Stdin), ColorOK: isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"}
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Run executes the CLI and returns the process exit code.
func Run(args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, mainUsage)
		return ExitUnknown
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "plan":
		return runPlan(rest, env)
	case "check":
		return runCheck(rest, env)
	case "aggregate", "agg":
		return runAggregate(rest, env)
	case "free":
		return runFree(rest, env)
	case "info", "calc":
		return runInfo(rest, env)
	case "version", "--version", "-version":
		fmt.Fprintf(env.Stdout, "subnet-planner %s\n", Version)
		return ExitOK
	case "help", "-h", "--help", "-help":
		fmt.Fprint(env.Stdout, mainUsage)
		return ExitOK
	}
	fmt.Fprintf(env.Stderr, "subnet-planner: unknown command %q\n\n%s", cmd, mainUsage)
	return ExitUnknown
}

// --- shared helpers ---------------------------------------------------------

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// newFlagSet builds a flag set whose usage prints head, the flags and tail.
func newFlagSet(name, head, tail string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprint(env.Stderr, head)
		fs.PrintDefaults()
		fmt.Fprint(env.Stderr, tail)
	}
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

// parseFlags handles --help and reports usage errors with exit codes.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, int, bool) {
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, ExitOK, false
		}
		return nil, ExitUnknown, false
	}
	return pos, 0, true
}

func usageErr(env Env, cmd, format string, a ...any) int {
	fmt.Fprintf(env.Stderr, "subnet-planner %s: %s\n", cmd, fmt.Sprintf(format, a...))
	return ExitUnknown
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// loadFiles loads every inventory file ("-" is stdin).
func loadFiles(paths []string, env Env) (inventory.Result, error) {
	var res inventory.Result
	stdinUsed := false
	for _, p := range paths {
		if p == "-" {
			if stdinUsed {
				return res, fmt.Errorf("stdin given more than once")
			}
			stdinUsed = true
		}
		r, err := inventory.LoadFile(p, env.Stdin)
		if err != nil {
			return res, err
		}
		res.Merge(r)
	}
	return res, nil
}

func parsePrefixArg(s string) (netip.Prefix, error) {
	p, _, err := inventory.ParsePrefix(s)
	return p, err
}

type colorizer struct{ on bool }

func newColorizer(mode string, env Env) (colorizer, error) {
	switch mode {
	case "auto":
		return colorizer{env.ColorOK}, nil
	case "always":
		return colorizer{true}, nil
	case "never":
		return colorizer{false}, nil
	}
	return colorizer{}, fmt.Errorf("--color must be auto, always or never")
}

func (c colorizer) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c colorizer) red(s string) string    { return c.wrap("31;1", s) }
func (c colorizer) yellow(s string) string { return c.wrap("33", s) }
func (c colorizer) green(s string) string  { return c.wrap("32", s) }
func (c colorizer) dim(s string) string    { return c.wrap("2", s) }
func (c colorizer) bold(s string) string   { return c.wrap("1", s) }

// human formats an address count: exact below 2^40, otherwise as a power
// of two (exact when possible, approximate otherwise).
func human(u ipmath.U128) string {
	if u.Hi == 0 && u.Lo < 1<<40 {
		return u.String()
	}
	if u == ipmath.MaxU128 {
		return "2^128"
	}
	if tz := u.TrailingZeros(); u == ipmath.Pow2(tz) {
		return fmt.Sprintf("2^%d", tz)
	}
	if n, _ := u.Inc(); n == ipmath.Pow2(n.TrailingZeros()) {
		return fmt.Sprintf("2^%d-1", n.TrailingZeros())
	}
	f, _ := new(big.Float).SetInt(u.Big()).Float64()
	return fmt.Sprintf("~2^%.2f", math.Log2(f))
}

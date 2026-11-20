package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/check"
)

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiDim    = "\x1b[2m"
)

func paint(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + ansiReset
}

func sevColor(s check.Severity) string {
	switch s {
	case check.OK:
		return ansiGreen
	case check.Warning:
		return ansiYellow
	default:
		return ansiRed
	}
}

// sanitize keeps hostile names and server-provided strings from injecting
// terminal escape sequences.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}

func optDur(v *float64, signed bool) string {
	if v == nil {
		return "-"
	}
	d := check.Seconds(*v)
	if signed {
		return check.FormatSigned(d)
	}
	return check.FormatDuration(d)
}

func renderText(w io.Writer, r *check.Report, color bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tADDRESS\tST\tREFID\tOFFSET\tVS CONSENSUS\tDELAY\tJITTER\tROOT DIST\tSTATE")
	for _, s := range r.Servers {
		st := "-"
		if s.Stratum > 0 {
			st = fmt.Sprint(s.Stratum)
		}
		ref := s.RefID
		if ref == "" {
			ref = "-"
		} else if s.RefIDServer != "" && s.RefIDServer != s.RefID {
			ref += " <" + s.RefIDServer + ">"
		}
		addr := s.Address
		if addr == "" {
			addr = "-"
		}
		state := s.State
		switch s.State {
		case check.StateTruechimer:
			state = paint(color, ansiGreen, state)
		case check.StateFalseticker:
			state = paint(color, ansiRed, state)
		case check.StateCandidate:
		default:
			state = paint(color, ansiYellow, state)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sanitize(s.Name), addr, st, sanitize(ref), optDur(s.Offset, true), optDur(s.OffsetConsensus, true),
			optDur(s.Delay, false), optDur(s.Jitter, false), optDur(s.RootDistance, false), state)
	}
	tw.Flush()
	fmt.Fprintln(w)

	sel := r.Selection
	switch {
	case sel.Candidates == 0:
		fmt.Fprintln(w, "Selection: no usable source")
	case !sel.Majority:
		fmt.Fprintf(w, "Selection: %d candidate(s), %s\n", sel.Candidates, paint(color, ansiRed, "no majority agreement"))
	default:
		fmt.Fprintf(w, "Selection: %d candidate(s), %d truechimer(s), %d falseticker(s); intersection [%s, %s]\n",
			sel.Candidates, sel.Truechimers, sel.Falsetickers, optDur(sel.Low, true), optDur(sel.High, true))
		local := -*sel.Offset
		fmt.Fprintf(w, "Local clock: %s from the consensus (truechimer spread %s)\n",
			check.FormatSigned(check.Seconds(local)), optDur(sel.Spread, false))
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
		for _, f := range r.Findings {
			prefix := ""
			if f.Server != "" {
				prefix = sanitize(f.Server) + ": "
			}
			fmt.Fprintf(w, "%s %s%s\n", paint(color, sevColor(f.Severity), fmt.Sprintf("%-8s", f.Severity)), prefix, sanitize(f.Message))
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "%s %s\n", paint(color, ansiDim, "note    "), sanitize(n))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "NTP-SKEW %s - %s\n", paint(color, sevColor(r.Status), r.Status.String()), summary(r))
}

func summary(r *check.Report) string {
	var parts []string
	if n := r.Selection.Falsetickers; n > 0 {
		parts = append(parts, fmt.Sprintf("%d falseticker(s)", n))
	}
	counts := map[string]int{}
	for _, s := range r.Servers {
		counts[s.State]++
	}
	for _, st := range []string{check.StateUnreachable, check.StateUnresolved, check.StateUnsynchronised, check.StateKoD, check.StateTooFar, check.StateBogus} {
		if counts[st] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[st], st))
		}
	}
	if r.Selection.Majority && r.Selection.Offset != nil {
		parts = append(parts, fmt.Sprintf("local clock %s from consensus of %d", check.FormatSigned(check.Seconds(-*r.Selection.Offset)), r.Selection.Truechimers))
	} else if r.Selection.Candidates > 0 {
		parts = append(parts, "no majority")
	}
	if len(parts) == 0 {
		return "no usable source"
	}
	return strings.Join(parts, ", ")
}

// writeProm writes Prometheus textfile-collector metrics atomically
// (temporary file in the same directory, then rename).
func writeProm(path string, r *check.Report) error {
	var b strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	lbl := func(s *check.Server) string {
		return fmt.Sprintf(`server="%s",address="%s"`, promEscape(s.Name), promEscape(s.Address))
	}
	bool01 := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	gauge("ntp_skew_server_up", "1 when the server returned at least one valid answer.")
	for _, s := range r.Servers {
		fmt.Fprintf(&b, "ntp_skew_server_up{%s} %d\n", lbl(s), bool01(s.Offset != nil))
	}
	gauge("ntp_skew_server_falseticker", "1 when the server was classified as a falseticker.")
	for _, s := range r.Servers {
		fmt.Fprintf(&b, "ntp_skew_server_falseticker{%s} %d\n", lbl(s), bool01(s.State == check.StateFalseticker))
	}
	series := []struct {
		name, help string
		get        func(*check.Server) *float64
	}{
		{"ntp_skew_server_offset_seconds", "Server clock minus local clock.", func(s *check.Server) *float64 { return s.Offset }},
		{"ntp_skew_server_consensus_offset_seconds", "Server offset minus the consensus offset.", func(s *check.Server) *float64 { return s.OffsetConsensus }},
		{"ntp_skew_server_delay_seconds", "Round-trip delay of the best exchange.", func(s *check.Server) *float64 { return s.Delay }},
		{"ntp_skew_server_jitter_seconds", "RMS offset difference between exchanges.", func(s *check.Server) *float64 { return s.Jitter }},
		{"ntp_skew_server_root_distance_seconds", "Root distance (correctness interval half-width).", func(s *check.Server) *float64 { return s.RootDistance }},
		{"ntp_skew_server_reference_age_seconds", "Time since the server last updated from its own source.", func(s *check.Server) *float64 { return s.RefAge }},
	}
	for _, m := range series {
		gauge(m.name, m.help)
		for _, s := range r.Servers {
			if v := m.get(s); v != nil {
				fmt.Fprintf(&b, "%s{%s} %g\n", m.name, lbl(s), *v)
			}
		}
	}
	gauge("ntp_skew_server_stratum", "Stratum announced by the server.")
	for _, s := range r.Servers {
		if s.Stratum > 0 {
			fmt.Fprintf(&b, "ntp_skew_server_stratum{%s} %d\n", lbl(s), s.Stratum)
		}
	}
	gauge("ntp_skew_truechimers", "Number of truechimers.")
	fmt.Fprintf(&b, "ntp_skew_truechimers %d\n", r.Selection.Truechimers)
	gauge("ntp_skew_majority", "1 when a majority of sources agrees.")
	fmt.Fprintf(&b, "ntp_skew_majority %d\n", bool01(r.Selection.Majority))
	if r.Selection.Offset != nil {
		gauge("ntp_skew_local_offset_seconds", "Local clock minus the consensus of the truechimers.")
		fmt.Fprintf(&b, "ntp_skew_local_offset_seconds %g\n", -*r.Selection.Offset)
	}
	gauge("ntp_skew_status", "Overall status (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN).")
	fmt.Fprintf(&b, "ntp_skew_status %d\n", int(r.Status))
	gauge("ntp_skew_last_run_timestamp_seconds", "Unix time of the run.")
	fmt.Fprintf(&b, "ntp_skew_last_run_timestamp_seconds %d\n", r.Time.Unix())

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func promEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

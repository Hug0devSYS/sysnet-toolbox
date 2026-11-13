package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/triage"
)

type jsonResult struct {
	Version string `json:"version"`
	*triage.Result
	TruncatedLines int `json:"truncated_lines"`
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// group formats n with thousands separators.
func group(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func cut(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// sanitize removes control characters (terminal escapes from hostile log
// lines must not reach the operator's terminal).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}

func writeText(w io.Writer, res *triage.Result, cfg *config, truncated int) {
	loc := cfg.parsedLoc
	s := res.Summary
	tmplWidth := 110
	if cfg.wide {
		tmplWidth = 0
	}
	ts := func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04:05") }
	short := func(t time.Time, ref time.Time) string {
		if t.In(loc).Format("2006-01-02") == ref.In(loc).Format("2006-01-02") {
			return t.In(loc).Format("15:04")
		}
		return t.In(loc).Format("2006-01-02 15:04")
	}

	fmt.Fprintf(w, "syslog-triage %s: %s messages, %s, %s, %s\n", res.Status, group(s.Messages),
		plural(s.Patterns, "pattern", "patterns"), plural(s.Hosts, "host", "hosts"), plural(s.Apps, "program", "programs"))
	if s.First != nil {
		fmt.Fprintf(w, "  range    %s .. %s (%s), bucket %s\n", ts(*s.First), ts(*s.Last), loc, s.Bucket)
	} else {
		fmt.Fprintf(w, "  range    no timestamps: spike detection disabled\n")
	}
	var notes []string
	if s.Unparsed > 0 {
		notes = append(notes, group(s.Unparsed)+" without syslog header")
	}
	if s.Filtered > 0 {
		notes = append(notes, group(s.Filtered)+" filtered out")
	}
	if s.WithoutTime > 0 && s.First != nil {
		notes = append(notes, group(s.WithoutTime)+" without timestamp")
	}
	if truncated > 0 {
		notes = append(notes, group(int64(truncated))+" truncated long lines")
	}
	if s.KnownBefore > 0 {
		notes = append(notes, group(int64(s.KnownBefore))+" patterns in model")
	}
	if len(notes) > 0 {
		fmt.Fprintf(w, "  input    %s\n", strings.Join(notes, ", "))
	}
	if s.RecentFrom != nil {
		fmt.Fprintf(w, "  alerts   since %s (--recent)\n", ts(*s.RecentFrom))
	}

	fmt.Fprintf(w, "\nSPIKES (%d)\n", len(res.Spikes))
	if len(res.Spikes) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, sp := range res.Spikes {
		id := "#" + strconv.Itoa(sp.PatternID)
		if sp.PatternID == 0 {
			id = "ALL"
		}
		mark := ""
		if !sp.Alert {
			mark = " (below --alert-severity)"
		}
		if sp.Sustained {
			mark += " (sustained: level shift)"
		}
		fmt.Fprintf(w, "  %s-%s  %-5s %-8s %-16s peak %s/%s at %s, x%.1f over baseline %.1f, %s msgs%s\n",
			short(sp.Start, *s.Last), short(sp.End, sp.Start), id, sp.Severity, cut(sanitize(sp.App), 16),
			group(sp.Peak), s.Bucket, short(sp.PeakAt, sp.Start), sp.Ratio, sp.Baseline, group(sp.Total), mark)
		if sp.PatternID != 0 {
			fmt.Fprintf(w, "      %s\n", cut(sanitize(sp.Template), tmplWidth))
		}
	}

	fmt.Fprintf(w, "\nNEW PATTERNS (%d)\n", len(res.New))
	if len(res.New) == 0 {
		switch {
		case cfg.model == "" && cfg.recent == "":
			fmt.Fprintln(w, "  not evaluated: use --model FILE or --recent DURATION")
		default:
			fmt.Fprintln(w, "  none")
		}
	}
	for _, p := range res.New {
		first := "-"
		if p.FirstSeen != nil {
			first = ts(*p.FirstSeen)
		}
		fmt.Fprintf(w, "  #%-5d %-8s %-16s %s msgs, %s, first %s\n", p.ID, p.Severity, cut(sanitize(p.App), 16),
			group(p.Count), plural(p.Hosts, "host", "hosts"), first)
		fmt.Fprintf(w, "      %s\n", cut(sanitize(p.Template), tmplWidth))
		if cfg.examples {
			fmt.Fprintf(w, "      e.g. %s\n", cut(sanitize(p.Example), tmplWidth))
		}
	}
	if cfg.quiet {
		return
	}

	fmt.Fprintf(w, "\nPATTERNS (%d of %d, by %s)\n", len(res.Patterns), s.Patterns, cfg.sortBy)
	if len(res.Patterns) == 0 {
		fmt.Fprintln(w, "  none")
		return
	}
	fmt.Fprintf(w, "  %6s %10s %6s  %-8s %5s  %-16s %s\n", "ID", "COUNT", "%", "SEV", "HOSTS", "PROGRAM", "TEMPLATE")
	for _, p := range res.Patterns {
		flag := " "
		if p.New {
			flag = "*"
		}
		fmt.Fprintf(w, "%s %6d %10s %5.1f%%  %-8s %5d  %-16s %s\n", flag, p.ID, group(p.Count), p.Percent,
			p.Severity, p.Hosts, cut(sanitize(p.App), 16), cut(sanitize(p.Template), tmplWidth))
		if cfg.examples {
			fmt.Fprintf(w, "  %6s e.g. %s\n", "", cut(sanitize(p.Example), tmplWidth))
		}
	}
	if len(res.New) > 0 {
		fmt.Fprintln(w, "  (* new pattern)")
	}
}

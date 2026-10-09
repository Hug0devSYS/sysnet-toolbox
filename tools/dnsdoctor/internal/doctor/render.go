package doctor

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// WriteText renders a human-readable report.
func WriteText(w io.Writer, r *Report, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	sev := func(s Severity) string {
		switch s {
		case SevError:
			return c("31;1", "ERROR")
		case SevWarning:
			return c("33;1", "WARN ")
		default:
			return c("36", "INFO ")
		}
	}

	fmt.Fprintf(w, "%s %s\n", c("1", "Zone:"), r.Zone)
	fmt.Fprintf(w, "Checked at %s in %.0f ms (%d queries)\n\n", r.CheckedAt.Format(time.RFC3339), r.DurationMS, r.Queries)

	if len(r.Delegation) > 0 {
		fmt.Fprintln(w, c("1", "Delegation path"))
		for _, ref := range r.Delegation {
			ds := "no DS"
			if ref.HasDS {
				ds = "DS"
			}
			fmt.Fprintf(w, "  %-24s -> %-28s via %-16s %6.1f ms  [%s]  %s\n",
				ref.Parent, ref.Child, ref.Server, ref.RTTMillis, ds, strings.Join(ref.NS, " "))
		}
		fmt.Fprintln(w)
	}

	if len(r.Nameservers) > 0 {
		fmt.Fprintln(w, c("1", "Name servers"))
		for _, h := range r.Nameservers {
			where := []string{}
			if h.InParent {
				where = append(where, "parent")
			}
			if h.InChild {
				where = append(where, "child")
			}
			fmt.Fprintf(w, "  %s  (%s)\n", h.Name, strings.Join(where, "+"))
			if h.ResolveError != "" && len(h.Addresses) == 0 {
				fmt.Fprintf(w, "      %s\n", h.ResolveError)
			}
			for _, a := range h.Addresses {
				serial := "-"
				if a.Serial != nil {
					serial = fmt.Sprint(*a.Serial)
				}
				status := a.Status
				switch a.Status {
				case StatusOK:
					status = c("32", "ok")
				case StatusLame, StatusUnreachable:
					status = c("31", a.Status)
				}
				line := fmt.Sprintf("      %-40s %-12s serial=%-12s", a.Address, status, serial)
				if a.RTTMillis > 0 {
					line += fmt.Sprintf(" %6.1f ms", a.RTTMillis)
				}
				if a.Error != "" && a.Status != StatusOK {
					line += "  " + a.Error
				}
				fmt.Fprintln(w, line)
			}
		}
		fmt.Fprintln(w)
	}

	if r.DNSSEC != nil && r.DNSSEC.Status != DNSSECSkipped {
		fmt.Fprintf(w, "%s %s\n", c("1", "DNSSEC:"), r.DNSSEC.Status)
		for _, l := range r.DNSSEC.Chain {
			keys := make([]string, 0, len(l.DNSKEYs))
			for _, k := range l.DNSKEYs {
				keys = append(keys, fmt.Sprintf("%s %d/%s", k.Role, k.KeyTag, k.Algorithm))
			}
			exp := ""
			if l.SigExpires != nil {
				exp = " sigs until " + l.SigExpires.Format("2006-01-02")
			}
			fmt.Fprintf(w, "  %-28s %-13s %s%s\n", l.Zone, l.Status, strings.Join(keys, ", "), exp)
			if l.Detail != "" && l.Status != DNSSECSecure {
				fmt.Fprintf(w, "  %-28s %s\n", "", l.Detail)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, c("1", "Findings"))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  %s [%s] %s\n", sev(f.Severity), f.Check, f.Message)
	}
	if r.Error != "" {
		fmt.Fprintf(w, "  %s diagnosis incomplete: %s\n", sev(SevError), r.Error)
	}
	fmt.Fprintf(w, "\nResult: %s (%d error(s), %d warning(s))\n", strings.ToUpper(r.Summary.Status), r.Summary.Errors, r.Summary.Warnings)
}

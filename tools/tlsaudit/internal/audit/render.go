package audit

import (
	"fmt"
	"io"
	"sort"
	"strconv"
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

	head := r.Name
	if r.StartTLS != "" {
		head += " (STARTTLS " + r.StartTLS + ")"
	}
	fmt.Fprintf(w, "%s %s\n", c("1", "Target:"), head)
	sni := r.ServerName
	if sni == "" {
		sni = "(none)"
	}
	fmt.Fprintf(w, "Address %s, SNI %s, checked at %s in %.0f ms (%d connections)\n",
		orDash(r.Address), sni, r.CheckedAt.Format(time.RFC3339), r.DurationMS, r.Connections)
	if r.Negotiated != nil {
		fmt.Fprintf(w, "Negotiated %s with %s\n", r.Negotiated.Protocol, r.Negotiated.Cipher)
	}
	fmt.Fprintln(w)

	if ci := r.Certificate; ci != nil {
		fmt.Fprintln(w, c("1", "Certificate"))
		fmt.Fprintf(w, "  Subject     %s\n", ci.Subject)
		fmt.Fprintf(w, "  Issuer      %s\n", ci.Issuer)
		sans := append(append([]string{}, ci.DNSNames...), ci.IPAddresses...)
		if len(sans) > 6 {
			sans = append(sans[:6], fmt.Sprintf("+%d more", len(sans)-6))
		}
		match := ""
		if r.HostnameMatch != nil {
			match = c("32", "  [matches]")
			if !*r.HostnameMatch {
				match = c("31", "  [MISMATCH]")
			}
		}
		fmt.Fprintf(w, "  SANs        %s%s\n", orDash(strings.Join(sans, ", ")), match)
		fmt.Fprintf(w, "  Key         %s %d bits, signed with %s\n", ci.Key, ci.KeyBits, ci.SignatureAlgorithm)
		days := strconv.Itoa(ci.DaysLeft) + " days left"
		switch {
		case ci.DaysLeft < 0:
			days = c("31;1", "EXPIRED")
		case ci.ExpiryStatus == SevError:
			days = c("31", days)
		case ci.ExpiryStatus == SevWarning:
			days = c("33", days)
		}
		fmt.Fprintf(w, "  Validity    %s -> %s (%s)\n", ci.NotBefore.Format("2006-01-02"), ci.NotAfter.Format("2006-01-02"), days)
		fmt.Fprintf(w, "  Serial      %s\n", ci.Serial)
		fmt.Fprintf(w, "  SHA-256     %s\n", ci.SHA256)
		fmt.Fprintln(w)
	}

	if ch := r.Chain; ch != nil {
		st := ch.Status
		if st == ChainTrusted {
			st = c("32", st)
		} else {
			st = c("31", st)
		}
		fmt.Fprintf(w, "%s %s (%d served)\n", c("1", "Chain:"), st, len(ch.Served))
		for i, ci := range ch.Served {
			fmt.Fprintf(w, "  #%d %-48s expires %s\n", i, trunc(subjectLabel(ci), 48), ci.NotAfter.Format("2006-01-02"))
		}
		if len(ch.Verified) > 0 {
			fmt.Fprintf(w, "  path: %s\n", strings.Join(ch.Verified, " -> "))
		}
		fmt.Fprintln(w)
	}

	if o := r.OCSP; o != nil {
		switch {
		case !o.Stapled:
			fmt.Fprintf(w, "%s not stapled\n\n", c("1", "OCSP:"))
		default:
			next := ""
			if o.NextUpdate != nil {
				next = ", next update " + o.NextUpdate.Format(time.RFC3339)
			}
			status := orDash(o.Status)
			if o.Error != "" {
				status += " (" + o.Error + ")"
			}
			fmt.Fprintf(w, "%s stapled, %s%s\n\n", c("1", "OCSP:"), status, next)
		}
	}

	if len(r.Protocols) > 0 {
		fmt.Fprint(w, c("1", "Protocols:"))
		for _, p := range r.Protocols {
			v := c("2", "no")
			switch {
			case p.Error != "":
				v = "?"
			case p.Supported && (p.Protocol == "SSLv3"):
				v = c("31;1", "YES")
			case p.Supported && (p.Protocol == "TLS1.0" || p.Protocol == "TLS1.1"):
				v = c("33", "yes")
			case p.Supported:
				v = c("32", "yes")
			}
			fmt.Fprintf(w, "  %s %s", p.Protocol, v)
		}
		fmt.Fprintln(w)
		extra := []string{}
		if r.SecureRenegotiation != nil {
			extra = append(extra, "secure renegotiation "+yesNo(*r.SecureRenegotiation))
		}
		if r.FallbackSCSV != nil {
			extra = append(extra, "TLS_FALLBACK_SCSV "+yesNo(*r.FallbackSCSV))
		}
		if len(extra) > 0 {
			fmt.Fprintf(w, "  %s\n", strings.Join(extra, ", "))
		}
		fmt.Fprintln(w)
	}

	if len(r.Ciphers) > 0 {
		fmt.Fprintln(w, c("1", "Cipher suites (TLS <= 1.2)"))
		cs := append([]CipherResult(nil), r.Ciphers...)
		rank := map[string]int{"good": 0, "legacy": 1, "weak": 2, "insecure": 3}
		sort.SliceStable(cs, func(i, j int) bool {
			if cs[i].Protocol != cs[j].Protocol {
				return cs[i].Protocol > cs[j].Protocol
			}
			return rank[cs[i].Grade] < rank[cs[j].Grade]
		})
		for _, x := range cs {
			g := x.Grade
			switch g {
			case "insecure":
				g = c("31;1", g)
			case "weak":
				g = c("33", g)
			case "good":
				g = c("32", g)
			}
			kx := ""
			switch {
			case x.Group != "":
				kx = x.Group
			case x.DHBits > 0:
				kx = fmt.Sprintf("DH %d", x.DHBits)
			}
			fmt.Fprintf(w, "  %-7s %-46s %-8s %s\n", x.Protocol, x.Name, g, kx)
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
	fmt.Fprintf(w, "\nResult: %s (%d error(s), %d warning(s))\n", strings.ToUpper(r.Summary.Status), r.Summary.Errors, r.Summary.Warnings)
}

// WriteSummary renders one line per report (fleet view).
func WriteSummary(w io.Writer, reps []*Report) {
	fmt.Fprintf(w, "%-8s %-40s %-6s %-11s %-10s %s\n", "STATUS", "TARGET", "DAYS", "CHAIN", "BEST", "TOP FINDING")
	for _, r := range reps {
		days, chain := "-", "-"
		if r.Certificate != nil {
			days = strconv.Itoa(r.Certificate.DaysLeft)
		}
		if r.Chain != nil {
			chain = r.Chain.Status
		}
		best := "-"
		for _, p := range r.Protocols {
			if p.Supported {
				best = p.Protocol
			}
		}
		top := ""
		for _, sv := range []Severity{SevError, SevWarning} {
			for _, f := range r.Findings {
				if f.Severity == sv {
					top = "[" + f.Check + "] " + f.Message
					break
				}
			}
			if top != "" {
				break
			}
		}
		fmt.Fprintf(w, "%-8s %-40s %-6s %-11s %-10s %s\n", strings.ToUpper(r.Summary.Status), trunc(r.Name, 40), days, chain, best, trunc(top, 100))
	}
}

func subjectLabel(ci CertInfo) string {
	if i := strings.Index(ci.Subject, "CN="); i >= 0 {
		s := ci.Subject[i:]
		if j := strings.Index(s, ","); j >= 0 {
			s = s[:j]
		}
		return s
	}
	return ci.Subject
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "NO"
}

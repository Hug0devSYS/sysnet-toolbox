package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/pmtu"
)

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
	cGrey   = "\033[90m"
)

var sevLabel = map[pmtu.Severity]string{
	pmtu.SevOK: "OK", pmtu.SevInfo: "INFO", pmtu.SevWarning: "WARN", pmtu.SevCritical: "CRIT", pmtu.SevUnknown: "UNKN",
}

var statusLabel = map[pmtu.Severity]string{
	pmtu.SevOK: "OK", pmtu.SevInfo: "OK", pmtu.SevWarning: "WARNING", pmtu.SevCritical: "CRITICAL", pmtu.SevUnknown: "UNKNOWN",
}

func sevColor(s pmtu.Severity) string {
	switch s {
	case pmtu.SevOK:
		return cGreen
	case pmtu.SevInfo:
		return cCyan
	case pmtu.SevWarning:
		return cYellow
	case pmtu.SevCritical:
		return cRed
	}
	return cGrey
}

// WriteText renders one report for humans.
func WriteText(w io.Writer, r *pmtu.Report, color bool) {
	paint := func(c, s string) string {
		if !color {
			return s
		}
		return c + s + cReset
	}
	head := r.Target
	var meta []string
	if r.Address != "" && r.Address != r.Target {
		meta = append(meta, r.Address)
	}
	if r.Family != "" {
		meta = append(meta, map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[r.Family])
	}
	if r.Method != "" {
		meta = append(meta, r.Method)
	}
	if len(meta) > 0 {
		head += " (" + strings.Join(meta, ", ") + ")"
	}
	fmt.Fprintf(w, "%s  %s\n", paint(cBold, head), paint(sevColor(r.Status), statusLabel[r.Status]))
	row := func(k, v string) { fmt.Fprintf(w, "  %-10s %s\n", k, v) }
	if r.Route.Local.IsValid() {
		v := r.Route.Local.String()
		if r.Route.Interface != "" {
			v += fmt.Sprintf(" via %s, interface MTU %d", r.Route.Interface, r.Route.IfMTU)
		}
		if r.Route.RouteMTU > 0 && r.Route.RouteMTU != r.Route.IfMTU {
			v += fmt.Sprintf(", kernel route MTU %d", r.Route.RouteMTU)
		}
		row("local", v)
	}
	if r.PathMTU > 0 {
		row("path MTU", fmt.Sprintf("%s bytes  (max UDP payload %d, TCP MSS %d; tried up to %d)",
			paint(cBold, fmt.Sprint(r.PathMTU)), r.MaxUDP, r.TCPMSS, r.UpperBound))
		row("PMTUD", r.PMTUD)
	}
	if len(r.PTB) > 0 {
		var parts []string
		for _, p := range r.PTB {
			parts = append(parts, fmt.Sprintf("%s says MTU %d (probe %d)", p.From, p.MTU, p.ProbeSize))
		}
		row("ICMP", strings.Join(parts, "; "))
	} else if r.PathMTU > 0 && r.PathMTU < r.UpperBound {
		row("ICMP", "no fragmentation-needed / packet-too-big message received")
	}
	if t := r.TCP; t != nil {
		k := fmt.Sprintf("TCP/%d", t.Port)
		switch {
		case t.Error != "":
			row(k, "connect failed: "+t.Error)
		default:
			bound := ""
			if t.PeerMSSMin {
				bound = ">= "
			}
			v := fmt.Sprintf("peer MSS %s%d (%d-byte segments)", bound, t.PeerMSS, t.SegmentSize)
			if t.Verdict != "" {
				v += " -> " + t.Verdict
			}
			row(k, v)
		}
	}
	row("probes", fmt.Sprintf("%d in %.1fs", len(r.Probes), float64(r.DurationMs)/1000))
	for _, f := range r.Findings {
		if f.Severity == pmtu.SevOK && len(r.Findings) > 1 {
			continue
		}
		fmt.Fprintf(w, "  %s %s: %s\n", paint(sevColor(f.Severity), "["+sevLabel[f.Severity]+"]"), f.Code, f.Message)
	}
}

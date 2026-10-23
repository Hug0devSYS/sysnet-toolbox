package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// metric accumulates samples of one metric family.
type metric struct {
	help, typ string
	samples   []string
}

type promWriter struct {
	order   []string
	metrics map[string]*metric
}

func (p *promWriter) add(name, help string, labels [][2]string, value float64) {
	m, ok := p.metrics[name]
	if !ok {
		m = &metric{help: help, typ: "gauge"}
		p.metrics[name] = m
		p.order = append(p.order, name)
	}
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%s=\"%s\"", l[0], escapeLabel(l[1]))
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(&b, " %s", formatFloat(value))
	m.samples = append(m.samples, b.String())
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// WriteProm writes the reports in the Prometheus text exposition format,
// suitable for node_exporter's textfile collector.
func WriteProm(w io.Writer, reps []*Report, now time.Time) error {
	p := &promWriter{metrics: map[string]*metric{}}
	for _, r := range reps {
		base := [][2]string{{"target", r.Name}, {"servername", r.ServerName}}
		if r.Connect != "" {
			// Several nodes behind one name (connect=...) must not
			// produce duplicate series, which make node_exporter reject
			// the whole textfile. An absent label keeps existing series.
			base = append(base, [2]string{"connect", r.Connect})
		}
		with := func(k, v string) [][2]string { return append(append([][2]string{}, base...), [2]string{k, v}) }

		ok := r.Certificate != nil && r.Error == ""
		p.add("tlsaudit_probe_success", "1 if a TLS handshake succeeded and a certificate was retrieved.", base, b2f(ok))
		p.add("tlsaudit_scan_duration_seconds", "Duration of the audit of this endpoint.", base, r.DurationMS/1000)
		for _, s := range []Severity{SevError, SevWarning, SevInfo} {
			n := 0
			for _, f := range r.Findings {
				if f.Severity == s {
					n++
				}
			}
			p.add("tlsaudit_findings", "Number of findings by severity.", with("severity", string(s)), float64(n))
		}
		if r.Certificate != nil {
			p.add("tlsaudit_cert_not_after_timestamp_seconds", "Leaf certificate notAfter as a Unix timestamp.", base, float64(r.Certificate.NotAfter.Unix()))
			p.add("tlsaudit_cert_expiry_seconds", "Seconds until the leaf certificate expires (negative once expired).", base, float64(r.Certificate.NotAfter.Unix()-now.Unix()))
		}
		if r.Chain != nil {
			p.add("tlsaudit_chain_trusted", "1 if the served chain validates against the trust store.", base, b2f(r.Chain.Status == ChainTrusted))
		}
		if r.HostnameMatch != nil {
			p.add("tlsaudit_hostname_match", "1 if the certificate covers the audited name.", base, b2f(*r.HostnameMatch))
		}
		for _, pr := range r.Protocols {
			if pr.Error != "" {
				continue
			}
			p.add("tlsaudit_protocol_enabled", "1 if the protocol version is accepted.", with("protocol", pr.Protocol), b2f(pr.Supported))
		}
		if len(r.Ciphers) > 0 {
			counts := map[string]int{}
			for _, c := range r.Ciphers {
				counts[c.Grade]++
			}
			for _, g := range []string{"good", "legacy", "weak", "insecure"} {
				p.add("tlsaudit_cipher_suites", "Number of accepted TLS <= 1.2 cipher suites by grade (all protocol versions).", with("grade", g), float64(counts[g]))
			}
		}
		if r.OCSP != nil {
			p.add("tlsaudit_ocsp_stapled", "1 if the server staples an OCSP response.", base, b2f(r.OCSP.Stapled))
			if r.OCSP.Stapled && r.OCSP.Status != "" {
				p.add("tlsaudit_ocsp_status", "Stapled OCSP certificate status (1 for the reported status).", with("status", r.OCSP.Status), 1)
			}
		}
	}
	p.add("tlsaudit_last_run_timestamp_seconds", "Unix time of the last tlsaudit run.", nil, float64(now.Unix()))

	for _, name := range p.order {
		m := p.metrics[name]
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, m.help, name, m.typ); err != nil {
			return err
		}
		sort.Strings(m.samples)
		for _, s := range m.samples {
			if _, err := fmt.Fprintln(w, s); err != nil {
				return err
			}
		}
	}
	return nil
}

// WritePromFile writes the metrics atomically (temporary file + rename in
// the same directory) so the textfile collector never reads a partial file.
func WritePromFile(path string, reps []*Report, now time.Time) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tlsaudit-*.prom.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := WriteProm(f, reps, now); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

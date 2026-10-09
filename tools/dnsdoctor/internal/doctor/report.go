package doctor

import "time"

// Severity of a finding.
type Severity string

// Severities, in increasing order of importance.
const (
	SevInfo    Severity = "info"
	SevWarning Severity = "warning"
	SevError   Severity = "error"
)

// Check identifiers used in findings.
const (
	CheckDelegation = "delegation"
	CheckNS         = "ns-consistency"
	CheckGlue       = "glue"
	CheckLame       = "lame-delegation"
	CheckSOA        = "soa-serial"
	CheckDiversity  = "diversity"
	CheckDNSSEC     = "dnssec"
)

// Finding is a single diagnostic result.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// AddrResult is the outcome of probing one name server address.
type AddrResult struct {
	Address       string   `json:"address"`
	Status        string   `json:"status"` // ok, lame, unreachable, skipped
	Authoritative bool     `json:"authoritative"`
	Rcode         string   `json:"rcode,omitempty"`
	Serial        *uint32  `json:"soa_serial,omitempty"`
	NS            []string `json:"ns,omitempty"`
	RTTMillis     float64  `json:"rtt_ms,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Address probe statuses.
const (
	StatusOK          = "ok"
	StatusLame        = "lame"
	StatusUnreachable = "unreachable"
	StatusSkipped     = "skipped"
)

// NSHost is one name server host and its probed addresses.
type NSHost struct {
	Name         string       `json:"name"`
	InParent     bool         `json:"in_parent"`
	InChild      bool         `json:"in_child"`
	Glue         []string     `json:"glue,omitempty"`
	Addresses    []AddrResult `json:"addresses"`
	ResolveError string       `json:"resolve_error,omitempty"`
}

// KeyInfo summarises a DNSKEY.
type KeyInfo struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm string `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	Role      string `json:"role"` // KSK, ZSK
	Revoked   bool   `json:"revoked,omitempty"`
}

// ChainLink is the DNSSEC validation state of one zone in the chain.
type ChainLink struct {
	Zone    string    `json:"zone"`
	Status  string    `json:"status"` // secure, insecure, bogus, indeterminate
	DS      []string  `json:"ds,omitempty"`
	DNSKEYs []KeyInfo `json:"dnskeys,omitempty"`
	// SigExpires is the earliest expiration among signatures validated for
	// this zone's DNSKEY (and, for the target, SOA/NS) RRsets.
	SigExpires *time.Time `json:"sig_expires,omitempty"`
	Detail     string     `json:"detail,omitempty"`
}

// DNSSEC validation statuses (RFC 4033 terminology).
const (
	DNSSECSecure        = "secure"
	DNSSECInsecure      = "insecure"
	DNSSECBogus         = "bogus"
	DNSSECIndeterminate = "indeterminate"
	DNSSECSkipped       = "skipped"
)

// DNSSECReport is the result of the chain-of-trust validation.
type DNSSECReport struct {
	Status string      `json:"status"`
	Chain  []ChainLink `json:"chain"`
}

// Summary counts findings by severity.
type Summary struct {
	Status   string `json:"status"` // ok, warning, error
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	Infos    int    `json:"infos"`
}

// Report is the full diagnosis of one zone.
type Report struct {
	Zone        string        `json:"zone"`
	CheckedAt   time.Time     `json:"checked_at"`
	DurationMS  float64       `json:"duration_ms"`
	Queries     int           `json:"queries"`
	ParentZone  string        `json:"parent_zone,omitempty"`
	Delegation  []Referral    `json:"delegation"`
	ParentNS    []string      `json:"parent_ns"`
	ChildNS     []string      `json:"child_ns"`
	Nameservers []NSHost      `json:"nameservers"`
	DNSSEC      *DNSSECReport `json:"dnssec,omitempty"`
	Findings    []Finding     `json:"findings"`
	Summary     Summary       `json:"summary"`
	// Error is set when the diagnosis could not be completed.
	Error string `json:"error,omitempty"`
}

func (r *Report) add(check string, sev Severity, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{Check: check, Severity: sev, Message: sprintf(format, args...)})
}

func (r *Report) summarize() {
	s := Summary{Status: "ok"}
	for _, f := range r.Findings {
		switch f.Severity {
		case SevError:
			s.Errors++
		case SevWarning:
			s.Warnings++
		default:
			s.Infos++
		}
	}
	switch {
	case s.Errors > 0 || r.Error != "":
		s.Status = "error"
	case s.Warnings > 0:
		s.Status = "warning"
	}
	r.Summary = s
}

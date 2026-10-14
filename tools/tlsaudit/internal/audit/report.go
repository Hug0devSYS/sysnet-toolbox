package audit

import (
	"fmt"
	"time"
)

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
	CheckConnect     = "connect"
	CheckCertificate = "certificate"
	CheckExpiry      = "expiry"
	CheckHostname    = "hostname"
	CheckChain       = "chain"
	CheckProtocol    = "protocol"
	CheckCipher      = "cipher"
	CheckKeyExchange = "key-exchange"
	CheckRenego      = "renegotiation"
	CheckFallback    = "fallback-scsv"
	CheckOCSP        = "ocsp"
)

// Chain statuses.
const (
	ChainTrusted    = "trusted"
	ChainIncomplete = "incomplete"
	ChainUntrusted  = "untrusted"
	ChainExpired    = "expired"
	ChainInvalid    = "invalid"
	ChainUnknown    = "unknown"
)

// Finding is a single diagnostic result.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// CertInfo summarises one X.509 certificate.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysLeft           int       `json:"days_left"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	Key                string    `json:"key"`
	KeyBits            int       `json:"key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SHA256             string    `json:"sha256_fingerprint"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
	OCSPServers        []string  `json:"ocsp_servers,omitempty"`
	IssuingURLs        []string  `json:"issuing_certificate_urls,omitempty"`
	MustStaple         bool      `json:"must_staple,omitempty"`
}

// ChainResult is the outcome of chain building and validation.
type ChainResult struct {
	Status string `json:"status"`
	// Served is the chain exactly as sent by the server.
	Served []CertInfo `json:"served"`
	// Verified lists the subjects of the validated path, leaf to root.
	Verified []string `json:"verified,omitempty"`
	// AIAFetched lists intermediates downloaded from AIA caIssuers URLs.
	AIAFetched []string `json:"aia_fetched,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

// ProtocolResult tells whether a protocol version is accepted.
type ProtocolResult struct {
	Protocol  string `json:"protocol"`
	Supported bool   `json:"supported"`
	// Error is set when the probe was inconclusive (timeout, reset after
	// partial data, ...); Supported is then false but unreliable.
	Error string `json:"error,omitempty"`
}

// CipherResult is one accepted cipher suite.
type CipherResult struct {
	Protocol      string `json:"protocol"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	Grade         string `json:"grade"`
	KeyExchange   string `json:"key_exchange"`
	ForwardSecret bool   `json:"forward_secret"`
	DHBits        int    `json:"dh_bits,omitempty"`
	Group         string `json:"group,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// OCSPResult describes the stapled OCSP response.
type OCSPResult struct {
	Stapled        bool       `json:"stapled"`
	Status         string     `json:"status,omitempty"`
	ProducedAt     *time.Time `json:"produced_at,omitempty"`
	ThisUpdate     *time.Time `json:"this_update,omitempty"`
	NextUpdate     *time.Time `json:"next_update,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	SignatureValid bool       `json:"signature_valid"`
	Delegated      bool       `json:"delegated_responder,omitempty"`
	Error          string     `json:"error,omitempty"`
}

// Negotiated is what a default modern client negotiates.
type Negotiated struct {
	Protocol string `json:"protocol"`
	Cipher   string `json:"cipher"`
}

// Summary counts findings by severity.
type Summary struct {
	Status   string `json:"status"` // ok, warning, error
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	Infos    int    `json:"infos"`
}

// Report is the full audit of one endpoint.
type Report struct {
	Target      string    `json:"target"`
	Name        string    `json:"name"`
	ServerName  string    `json:"server_name,omitempty"`
	Address     string    `json:"address,omitempty"`
	StartTLS    string    `json:"starttls,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
	DurationMS  float64   `json:"duration_ms"`
	Connections int       `json:"connections"`

	Negotiated          *Negotiated      `json:"negotiated,omitempty"`
	Certificate         *CertInfo        `json:"certificate,omitempty"`
	HostnameMatch       *bool            `json:"hostname_match,omitempty"`
	Chain               *ChainResult     `json:"chain,omitempty"`
	OCSP                *OCSPResult      `json:"ocsp,omitempty"`
	Protocols           []ProtocolResult `json:"protocols"`
	Ciphers             []CipherResult   `json:"ciphers,omitempty"`
	SecureRenegotiation *bool            `json:"secure_renegotiation,omitempty"`
	FallbackSCSV        *bool            `json:"fallback_scsv,omitempty"`

	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
	// Error is set when the audit could not be completed.
	Error string `json:"error,omitempty"`
}

func (r *Report) add(check string, sev Severity, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{Check: check, Severity: sev, Message: fmt.Sprintf(format, args...)})
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

// protocolSupported reports whether name (e.g. "TLS1.2") was accepted.
func (r *Report) protocolSupported(name string) bool {
	for _, p := range r.Protocols {
		if p.Protocol == name {
			return p.Supported
		}
	}
	return false
}

func ptr[T any](v T) *T { return &v }

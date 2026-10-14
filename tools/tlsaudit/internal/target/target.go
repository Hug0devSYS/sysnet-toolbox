// Package target parses tlsaudit endpoint specifications.
//
// A specification is a target followed by optional key=value options:
//
//	host
//	host:port
//	[2001:db8::1]:8443
//	scheme://host[:port]          e.g. smtp://mx.example.com, ldaps://dc1
//	host:port sni=name connect=10.0.0.5 starttls=smtp
package target

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// StartTLS protocols.
var startTLSProtocols = map[string]bool{
	"smtp": true, "imap": true, "pop3": true, "ftp": true, "ldap": true, "postgres": true,
}

// schemes maps URL-like prefixes to a default port and STARTTLS protocol.
var schemes = map[string]struct {
	port     uint16
	startTLS string
}{
	"https":      {443, ""},
	"tls":        {443, ""},
	"smtp":       {25, "smtp"},
	"submission": {587, "smtp"},
	"smtps":      {465, ""},
	"imap":       {143, "imap"},
	"imaps":      {993, ""},
	"pop3":       {110, "pop3"},
	"pop3s":      {995, ""},
	"ftp":        {21, "ftp"},
	"ftps":       {990, ""},
	"ldap":       {389, "ldap"},
	"ldaps":      {636, ""},
	"postgres":   {5432, "postgres"},
	"postgresql": {5432, "postgres"},
}

// Target is one endpoint to audit.
type Target struct {
	// Spec is the original specification (for labels and messages).
	Spec string `json:"spec"`
	// Host is the host name or IP literal to resolve and verify.
	Host string `json:"host"`
	Port uint16 `json:"port"`
	// ServerName is the SNI value and the name verified against the
	// certificate. Empty means no SNI (IP targets or sni=none).
	ServerName string `json:"server_name,omitempty"`
	// Connect overrides the address actually dialled (IP or host name,
	// optionally with a port), e.g. to audit one node behind a VIP.
	Connect string `json:"connect,omitempty"`
	// StartTLS names the plaintext protocol to upgrade, if any.
	StartTLS string `json:"starttls,omitempty"`
}

// Name returns host:port in canonical form.
func (t Target) Name() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// VerifyName returns the name the certificate must match: the SNI value,
// or the host itself when no SNI is sent.
func (t Target) VerifyName() string {
	if t.ServerName != "" {
		return t.ServerName
	}
	return t.Host
}

// Parse parses one specification.
func Parse(spec string) (Target, error) {
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return Target{}, errors.New("empty target")
	}
	t := Target{Spec: strings.Join(fields, " "), Port: 443}
	hp := fields[0]
	if i := strings.Index(hp, "://"); i >= 0 {
		scheme := strings.ToLower(hp[:i])
		s, ok := schemes[scheme]
		if !ok {
			return Target{}, fmt.Errorf("unknown scheme %q", scheme)
		}
		t.Port, t.StartTLS = s.port, s.startTLS
		hp = strings.TrimSuffix(hp[i+3:], "/")
		if strings.ContainsAny(hp, "/?#@") {
			return Target{}, fmt.Errorf("%q: paths, queries and credentials are not supported", fields[0])
		}
	}
	host, port, err := splitHostPort(hp)
	if err != nil {
		return Target{}, fmt.Errorf("%q: %w", fields[0], err)
	}
	if port != 0 {
		t.Port = port
	}
	t.Host = strings.TrimSuffix(strings.ToLower(host), ".")
	if t.Host == "" {
		return Target{}, fmt.Errorf("%q: empty host", fields[0])
	}
	if _, err := netip.ParseAddr(t.Host); err != nil {
		if !validHostname(t.Host) {
			return Target{}, fmt.Errorf("%q: invalid host name", host)
		}
		t.ServerName = t.Host
	}

	for _, opt := range fields[1:] {
		k, v, ok := strings.Cut(opt, "=")
		if !ok || v == "" {
			return Target{}, fmt.Errorf("option %q: expected key=value", opt)
		}
		switch strings.ToLower(k) {
		case "sni":
			if v == "none" || v == "-" {
				t.ServerName = ""
				continue
			}
			v = strings.TrimSuffix(strings.ToLower(v), ".")
			if !validHostname(v) {
				return Target{}, fmt.Errorf("sni=%q: invalid host name", v)
			}
			t.ServerName = v
		case "connect":
			if _, _, err := splitHostPort(v); err != nil {
				return Target{}, fmt.Errorf("connect=%q: %w", v, err)
			}
			t.Connect = v
		case "starttls":
			v = strings.ToLower(v)
			if v == "none" {
				t.StartTLS = ""
				continue
			}
			if !startTLSProtocols[v] {
				return Target{}, fmt.Errorf("starttls=%q: supported: smtp, imap, pop3, ftp, ldap, postgres", v)
			}
			t.StartTLS = v
		default:
			return Target{}, fmt.Errorf("unknown option %q (sni, connect, starttls)", k)
		}
	}
	return t, nil
}

// splitHostPort accepts host, host:port, [v6] and [v6]:port. A bare IPv6
// literal without brackets is accepted too. Port 0 means "not specified".
func splitHostPort(s string) (string, uint16, error) {
	if s == "" {
		return "", 0, errors.New("empty address")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), 0, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		a, err := netip.ParseAddr(s[1 : len(s)-1])
		if err != nil {
			return "", 0, err
		}
		return a.String(), 0, nil
	}
	if !strings.Contains(s, ":") {
		return s, 0, nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if strings.HasPrefix(s, "[") {
		if _, err := netip.ParseAddr(h); err != nil {
			return "", 0, fmt.Errorf("invalid IPv6 literal %q", h)
		}
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, uint16(n), nil
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || (c == '*' && i == 0 && len(label) == 1)
			if !ok {
				return false
			}
		}
	}
	return true
}

// ParseList reads one specification per line. Blank lines and comments
// (starting with '#') are ignored; errors carry the line number.
func ParseList(r io.Reader, source string) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if i := strings.Index(s, "#"); i >= 0 {
			s = s[:i]
		}
		if strings.TrimSpace(s) == "" {
			continue
		}
		t, err := Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", source, line, err)
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return out, nil
}

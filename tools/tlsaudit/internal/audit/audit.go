// Package audit performs the TLS audit of one endpoint: certificate and
// chain validation, hostname matching, protocol and cipher suite
// enumeration, ephemeral key-exchange strength, secure renegotiation,
// TLS_FALLBACK_SCSV and OCSP stapling.
package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/rawtls"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/starttls"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/target"
)

// Dialer opens TCP connections (net.Dialer in production).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver resolves host names (net.DefaultResolver in production).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options tunes an audit.
type Options struct {
	// Timeout bounds each connection (dial + STARTTLS + handshake).
	Timeout time.Duration
	// WarnDays / CritDays are certificate expiry thresholds.
	WarnDays, CritDays int
	// Roots is the trust store; nil means the system pool.
	Roots *x509.CertPool
	// Ciphers enables cipher suite enumeration (many connections).
	Ciphers bool
	// FetchAIA downloads missing intermediates from AIA caIssuers URLs to
	// tell an incomplete chain from an untrusted CA.
	FetchAIA bool
	// Network is "tcp", "tcp4" or "tcp6".
	Network string
	// Now is the clock (tests); nil means time.Now.
	Now func() time.Time
	// Logf receives debug messages; nil disables logging.
	Logf func(format string, args ...any)
}

// Auditor runs audits. The zero value is not usable; use New.
type Auditor struct {
	Opts     Options
	Dialer   Dialer
	Resolver Resolver
	HTTP     *http.Client
}

// New returns an Auditor using the real network.
func New(o Options) *Auditor {
	if o.Network == "" {
		o.Network = "tcp"
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	return &Auditor{
		Opts:     o,
		Dialer:   &net.Dialer{},
		Resolver: net.DefaultResolver,
		HTTP:     &http.Client{Timeout: o.Timeout},
	}
}

func (a *Auditor) now() time.Time {
	if a.Opts.Now != nil {
		return a.Opts.Now()
	}
	return time.Now()
}

func (a *Auditor) logf(format string, args ...any) {
	if a.Opts.Logf != nil {
		a.Opts.Logf(format, args...)
	}
}

// probeVersions are the versions enumerated with raw ClientHellos.
var probeVersions = []uint16{rawtls.VersionSSL30, rawtls.VersionTLS10, rawtls.VersionTLS11, rawtls.VersionTLS12}

// Audit audits one endpoint. It never returns nil; failures are recorded in
// the report (Error and findings).
func (a *Auditor) Audit(ctx context.Context, t target.Target) *Report {
	start := a.now()
	rep := &Report{
		Target:     t.Spec,
		Name:       t.Name(),
		ServerName: t.ServerName,
		Connect:    t.Connect,
		StartTLS:   t.StartTLS,
		CheckedAt:  start.UTC(),
	}
	defer func() {
		rep.DurationMS = float64(a.now().Sub(start).Microseconds()) / 1000
		rep.summarize()
	}()

	addr, err := a.resolve(ctx, t)
	if err != nil {
		rep.Error = err.Error()
		rep.add(CheckConnect, SevError, "%v", err)
		return rep
	}
	rep.Address = addr
	s := &session{a: a, t: t, addr: addr, rep: rep}

	// 1. Handshake like a modern client: certificate chain, OCSP staple,
	//    negotiated parameters, TLS 1.3 support.
	state, hsErr := s.goHandshake(ctx, tls.VersionTLS10, tls.VersionTLS13)
	if hsErr != nil && isConnectError(hsErr) {
		rep.Error = hsErr.Error()
		rep.add(CheckConnect, SevError, "%v", hsErr)
		return rep
	}
	tls13 := ProtocolResult{Protocol: "TLS1.3"}
	if state != nil {
		rep.Negotiated = &Negotiated{Protocol: tlsVersionName(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite)}
		tls13.Supported = state.Version == tls.VersionTLS13
	}
	if !tls13.Supported {
		st, err := s.goHandshake(ctx, tls.VersionTLS13, tls.VersionTLS13)
		switch {
		case st != nil:
			tls13.Supported = true
			if state == nil {
				state = st
			}
		case err != nil && !isHandshakeRejection(err):
			tls13.Error = err.Error()
		}
	}

	// 2. Raw probes for SSLv3 .. TLS 1.2, plus cipher enumeration.
	var raw = map[uint16]*rawtls.Result{}
	for _, v := range probeVersions {
		pr := ProtocolResult{Protocol: rawtls.VersionName(v)}
		res, err := s.rawProbe(ctx, rawtls.Hello{Version: v, Ciphers: rawtls.AllSuites(), ServerName: t.ServerName})
		switch {
		case err != nil:
			pr.Error = err.Error()
		case res.Accepted && res.Version == v:
			pr.Supported = true
			raw[v] = res
		}
		rep.Protocols = append(rep.Protocols, pr)
	}
	rep.Protocols = append(rep.Protocols, tls13)

	if len(raw) == 0 && state == nil {
		msg := "no TLS handshake succeeded with any protocol version"
		if hsErr != nil {
			msg += ": " + hsErr.Error()
		}
		rep.Error = msg
		rep.add(CheckConnect, SevError, "%s", msg)
		return rep
	}

	// 3. Certificates: prefer crypto/tls (works for TLS 1.3); fall back to
	//    the clear-text Certificate message of a raw TLS <= 1.2 handshake.
	var certs []*x509.Certificate
	var staple []byte
	if state != nil {
		certs, staple = state.PeerCertificates, state.OCSPResponse
	}
	if len(certs) == 0 {
		for i := len(probeVersions) - 1; i >= 0; i-- {
			if r := raw[probeVersions[i]]; r != nil && len(r.Certificates) > 0 {
				for _, der := range r.Certificates {
					c, err := x509.ParseCertificate(der)
					if err != nil {
						rep.add(CheckCertificate, SevError, "unparseable certificate in served chain: %v", err)
						break
					}
					certs = append(certs, c)
				}
				staple = r.OCSPStaple
				break
			}
		}
	}

	if a.Opts.Ciphers {
		for _, v := range probeVersions[1:] {
			if r := raw[v]; r != nil {
				s.enumerate(ctx, v, r)
			}
		}
	} else {
		// Without enumeration, still report the suite each version picks.
		for _, v := range probeVersions[1:] {
			if r := raw[v]; r != nil {
				rep.Ciphers = append(rep.Ciphers, cipherResult(v, r))
			}
		}
	}

	// 4. Secure renegotiation and downgrade protection.
	for i := len(probeVersions) - 1; i >= 0; i-- {
		if r := raw[probeVersions[i]]; r != nil {
			rep.SecureRenegotiation = ptr(r.SecureRenegotiation)
			break
		}
	}
	s.fallbackSCSV(ctx, raw, tls13.Supported)

	// 5. Analysis.
	now := a.now()
	if len(certs) == 0 {
		rep.add(CheckCertificate, SevError, "server did not present a certificate")
	} else {
		issuer := a.checkCertificates(ctx, rep, t, certs, now)
		a.checkOCSP(rep, certs[0], issuer, staple, now)
	}
	checkProtocols(rep)
	checkCiphers(rep)
	return rep
}

// resolve returns the ip:port to dial.
func (a *Auditor) resolve(ctx context.Context, t target.Target) (string, error) {
	host, port := t.Host, t.Port
	if t.Connect != "" {
		h, p, err := net.SplitHostPort(t.Connect)
		if err != nil {
			h = t.Connect // no port
		} else if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = uint16(n)
		}
		host = h
		if len(host) > 1 && host[0] == '[' {
			host = host[1 : len(host)-1]
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if (a.Opts.Network == "tcp4" && !ip.Unmap().Is4()) || (a.Opts.Network == "tcp6" && ip.Unmap().Is4()) {
			return "", fmt.Errorf("address %s does not match the requested address family", ip)
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
	}
	network := map[string]string{"tcp": "ip", "tcp4": "ip4", "tcp6": "ip6"}[a.Opts.Network]
	rctx, cancel := context.WithTimeout(ctx, a.Opts.Timeout)
	defer cancel()
	ips, err := a.Resolver.LookupNetIP(rctx, network, host)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("cannot resolve %s: no %s address", host, network)
	}
	return net.JoinHostPort(ips[0].Unmap().String(), strconv.Itoa(int(port))), nil
}

// session holds per-endpoint probing state.
type session struct {
	a    *Auditor
	t    target.Target
	addr string
	rep  *Report
}

// connectError marks failures to reach the endpoint at all.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

func isConnectError(err error) bool {
	var ce *connectError
	return errors.As(err, &ce)
}

func (s *session) dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, &connectError{fmt.Errorf("time budget exhausted: %w", err)}
	}
	dctx, cancel := context.WithTimeout(ctx, s.a.Opts.Timeout)
	defer cancel()
	s.rep.Connections++
	c, err := s.a.Dialer.DialContext(dctx, s.a.Opts.Network, s.addr)
	if err != nil {
		return nil, &connectError{fmt.Errorf("cannot connect to %s: %w", s.addr, err)}
	}
	deadline := time.Now().Add(s.a.Opts.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if s.t.StartTLS != "" {
		if err := starttls.Negotiate(c, s.t.StartTLS); err != nil {
			c.Close()
			return nil, &connectError{err}
		}
	}
	return c, nil
}

// goSuites lists every TLS <= 1.2 suite crypto/tls implements, including
// the insecure ones, so the reference handshake succeeds on legacy servers.
func goSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// goHandshake performs a crypto/tls handshake. Certificate verification is
// done separately (InsecureSkipVerify) so that broken chains can still be
// inspected.
func (s *session) goHandshake(ctx context.Context, minV, maxV uint16) (*tls.ConnectionState, error) {
	c, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cfg := &tls.Config{
		ServerName:         s.t.ServerName,
		InsecureSkipVerify: true, //nolint:gosec // verification is performed explicitly in checkCertificates
		MinVersion:         minV,
		MaxVersion:         maxV,
		CipherSuites:       goSuites(),
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		s.a.logf("%s: handshake %s-%s: %v", s.rep.Name, tlsVersionName(minV), tlsVersionName(maxV), err)
		return nil, err
	}
	st := tc.ConnectionState()
	s.a.logf("%s: handshake %s %s", s.rep.Name, tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	return &st, nil
}

func (s *session) rawProbe(ctx context.Context, h rawtls.Hello) (*rawtls.Result, error) {
	c, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	res, err := rawtls.Probe(c, h)
	if err != nil {
		s.a.logf("%s: raw %s: %v", s.rep.Name, rawtls.VersionName(h.Version), err)
		return nil, err
	}
	s.a.logf("%s: raw %s (%d suites offered): accepted=%v version=%s cipher=%s alert=%d closed=%v",
		s.rep.Name, rawtls.VersionName(h.Version), len(h.Ciphers), res.Accepted,
		rawtls.VersionName(res.Version), rawtls.SuiteName(res.Cipher), res.Alert, res.Closed)
	return res, nil
}

// enumerate finds every suite accepted for version v by repeatedly removing
// the server's choice from the offered list. first is the result of the
// protocol probe, which offered the full list.
func (s *session) enumerate(ctx context.Context, v uint16, first *rawtls.Result) {
	remaining := rawtls.AllSuites()
	res := first
	for i := 0; i <= len(rawtls.AllSuites()); i++ {
		idx := indexOf(remaining, res.Cipher)
		if idx < 0 {
			s.rep.add(CheckCipher, SevWarning, "%s: server selected cipher suite %s which was not offered (TLS stack bug)",
				rawtls.VersionName(v), rawtls.SuiteName(res.Cipher))
			return
		}
		s.rep.Ciphers = append(s.rep.Ciphers, cipherResult(v, res))
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		if len(remaining) == 0 {
			return
		}
		next, err := s.rawProbe(ctx, rawtls.Hello{Version: v, Ciphers: remaining, ServerName: s.t.ServerName})
		if err != nil {
			s.rep.add(CheckCipher, SevInfo, "%s: cipher enumeration incomplete: %v", rawtls.VersionName(v), err)
			return
		}
		if !next.Accepted || next.Version != v {
			return
		}
		res = next
	}
}

func indexOf(list []uint16, v uint16) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

func cipherResult(v uint16, r *rawtls.Result) CipherResult {
	cl := rawtls.Classify(r.Cipher)
	cr := CipherResult{
		Protocol:      rawtls.VersionName(v),
		ID:            fmt.Sprintf("0x%04X", r.Cipher),
		Name:          rawtls.SuiteName(r.Cipher),
		Grade:         string(cl.Grade),
		KeyExchange:   cl.KeyExchange,
		ForwardSecret: cl.ForwardSecret,
		DHBits:        r.DHBits,
		Reason:        cl.Reason,
	}
	if r.Group != 0 {
		cr.Group = rawtls.GroupName(r.Group)
	}
	return cr
}

// fallbackSCSV checks RFC 7507 downgrade protection when the server accepts
// both a legacy version and a modern one.
func (s *session) fallbackSCSV(ctx context.Context, raw map[uint16]*rawtls.Result, tls13 bool) {
	modern := tls13 || raw[rawtls.VersionTLS12] != nil
	var legacy uint16
	for _, v := range []uint16{rawtls.VersionTLS11, rawtls.VersionTLS10} {
		if raw[v] != nil {
			legacy = v
			break
		}
	}
	if !modern || legacy == 0 {
		return
	}
	res, err := s.rawProbe(ctx, rawtls.Hello{Version: legacy, Ciphers: rawtls.AllSuites(), ServerName: s.t.ServerName, FallbackSCSV: true})
	if err != nil {
		s.rep.add(CheckFallback, SevInfo, "TLS_FALLBACK_SCSV probe inconclusive: %v", err)
		return
	}
	switch {
	case res.Accepted:
		s.rep.FallbackSCSV = ptr(false)
	case res.AlertReceived && res.Alert == rawtls.AlertInappropriateFallback:
		s.rep.FallbackSCSV = ptr(true)
	}
}

// isHandshakeRejection reports whether err is the server refusing a TLS
// version or parameters (as opposed to a network failure).
func isHandshakeRejection(err error) bool {
	if err == nil || isConnectError(err) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

func tlsVersionName(v uint16) string {
	return rawtls.VersionName(v)
}

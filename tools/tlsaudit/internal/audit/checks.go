package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/ocsp"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/rawtls"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/target"
)

var oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// maxPublicValidity is the CA/Browser Forum maximum lifetime of publicly
// trusted TLS certificates issued since 2020-09-01.
const maxPublicValidity = 398 * 24 * time.Hour

func describe(c *x509.Certificate, now time.Time) CertInfo {
	sum := sha256.Sum256(c.Raw)
	ci := CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		Serial:             strings.ToUpper(c.SerialNumber.Text(16)),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		DaysLeft:           int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
		DNSNames:           c.DNSNames,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		SHA256:             hex.EncodeToString(sum[:]),
		IsCA:               c.IsCA,
		SelfSigned:         isSelfSigned(c),
		OCSPServers:        c.OCSPServer,
		IssuingURLs:        c.IssuingCertificateURL,
	}
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.Key, ci.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		ci.Key, ci.KeyBits = "ECDSA "+k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PublicKey:
		ci.Key, ci.KeyBits = "Ed25519", 256
	default:
		ci.Key = c.PublicKeyAlgorithm.String()
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidTLSFeature) {
			var features []int
			if _, err := asn1.Unmarshal(e.Value, &features); err == nil {
				for _, f := range features {
					if f == 5 { // status_request
						ci.MustStaple = true
					}
				}
			}
		}
	}
	return ci
}

func isSelfSigned(c *x509.Certificate) bool {
	// CheckSignature, not CheckSignatureFrom: self-signed end-entity
	// certificates have no CA basic constraint.
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func label(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return "CN=" + c.Subject.CommonName
	}
	return c.Subject.String()
}

func weakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// checkExpiry adds expiry findings for c (what is "leaf certificate" or a
// chain position description) and returns their severity ("" when the
// certificate is valid beyond --warn-days).
func (a *Auditor) checkExpiry(rep *Report, c *x509.Certificate, what string, now time.Time) Severity {
	days := c.NotAfter.Sub(now).Hours() / 24
	switch {
	case now.Before(c.NotBefore):
		rep.add(CheckExpiry, SevError, "%s is not yet valid (notBefore %s)", what, c.NotBefore.UTC().Format(time.RFC3339))
	case now.After(c.NotAfter):
		rep.add(CheckExpiry, SevError, "%s EXPIRED on %s (%d days ago)", what, c.NotAfter.UTC().Format("2006-01-02"), int(-days))
	case days < float64(a.Opts.CritDays):
		rep.add(CheckExpiry, SevError, "%s expires in %d day(s) on %s", what, int(days), c.NotAfter.UTC().Format("2006-01-02"))
	case days < float64(a.Opts.WarnDays):
		rep.add(CheckExpiry, SevWarning, "%s expires in %d day(s) on %s", what, int(days), c.NotAfter.UTC().Format("2006-01-02"))
		return SevWarning
	default:
		return ""
	}
	return SevError
}

// checkCertificates validates the leaf and chain and returns the leaf's
// issuer certificate when it can be determined (for OCSP verification).
func (a *Auditor) checkCertificates(ctx context.Context, rep *Report, t target.Target, certs []*x509.Certificate, now time.Time) *x509.Certificate {
	leaf := certs[0]
	info := describe(leaf, now)
	rep.Certificate = &info
	chain := &ChainResult{Status: ChainUnknown}
	for _, c := range certs {
		chain.Served = append(chain.Served, describe(c, now))
	}
	rep.Chain = chain

	// Leaf properties.
	rep.Certificate.ExpiryStatus = a.checkExpiry(rep, leaf, "certificate", now)
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			rep.add(CheckCertificate, SevError, "weak RSA key: %d bits (minimum 2048)", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			rep.add(CheckCertificate, SevError, "weak ECDSA key: %s", k.Curve.Params().Name)
		}
	}
	if weakSignature(leaf.SignatureAlgorithm) {
		rep.add(CheckCertificate, SevError, "certificate signed with deprecated algorithm %s", leaf.SignatureAlgorithm)
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		rep.add(CheckCertificate, SevWarning, "certificate has no subjectAltName; modern clients ignore the Common Name")
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > maxPublicValidity+24*time.Hour && !info.SelfSigned {
		rep.add(CheckCertificate, SevInfo, "validity period of %d days exceeds the 398-day limit for publicly trusted certificates (fine for a private CA)",
			int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24))
	}

	// Hostname.
	name := t.VerifyName()
	match := leaf.VerifyHostname(name) == nil
	rep.HostnameMatch = ptr(match)
	if !match {
		sans := append([]string{}, leaf.DNSNames...)
		sans = append(sans, info.IPAddresses...)
		if len(sans) == 0 {
			sans = []string{"none"}
		}
		if len(sans) > 8 {
			sans = append(sans[:8], fmt.Sprintf("... (%d more)", len(sans)-8))
		}
		rep.add(CheckHostname, SevError, "certificate does not match %q (SANs: %s)", name, strings.Join(sans, ", "))
	}

	return a.checkChain(ctx, rep, chain, certs, now)
}

func (a *Auditor) verify(leaf *x509.Certificate, inter []*x509.Certificate, now time.Time) ([][]*x509.Certificate, error) {
	pool := x509.NewCertPool()
	for _, c := range inter {
		pool.AddCert(c)
	}
	return leaf.Verify(x509.VerifyOptions{
		Roots:         a.Opts.Roots,
		Intermediates: pool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

func (a *Auditor) checkChain(ctx context.Context, rep *Report, chain *ChainResult, certs []*x509.Certificate, now time.Time) *x509.Certificate {
	leaf := certs[0]
	inter := certs[1:]
	chains, err := a.verify(leaf, inter, now)

	var ua x509.UnknownAuthorityError
	if err != nil && errors.As(err, &ua) && a.Opts.FetchAIA {
		if fetched := a.fetchAIA(ctx, rep, certs); len(fetched) > 0 {
			for _, c := range fetched {
				chain.AIAFetched = append(chain.AIAFetched, label(c))
			}
			if ch, err2 := a.verify(leaf, append(append([]*x509.Certificate{}, inter...), fetched...), now); err2 == nil {
				chain.Status = ChainIncomplete
				chain.Verified = subjects(ch[0])
				chain.Detail = "server does not send all intermediates"
				rep.add(CheckChain, SevError,
					"incomplete chain: server does not send intermediate %s (found via AIA); clients that do not fetch AIA (curl, OpenSSL, Java, Python, Go, most API clients) will reject it",
					strings.Join(chain.AIAFetched, ", "))
				a.checkPath(rep, ch[0], now)
				return issuerOf(ch[0])
			}
		}
	}

	if err == nil {
		chain.Status = ChainTrusted
		chain.Verified = subjects(chains[0])
		a.checkServedOrder(rep, certs, chains[0])
		a.checkPath(rep, chains[0], now)
		return issuerOf(chains[0])
	}

	chain.Detail = err.Error()
	var inv x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		end := servedPathEnd(certs)
		switch {
		case isSelfSigned(end) && end == leaf:
			chain.Status = ChainUntrusted
			rep.add(CheckChain, SevError, "self-signed certificate (%s) is not trusted (use --ca-file for a private CA)", label(leaf))
		case isSelfSigned(end):
			chain.Status = ChainUntrusted
			rep.add(CheckChain, SevError, "chain ends at root %s which is not in the trust store (private CA? use --ca-file)", label(end))
		default:
			chain.Status = ChainIncomplete
			aia := ""
			if len(end.IssuingCertificateURL) > 0 {
				aia = " (AIA caIssuers: " + end.IssuingCertificateURL[0] + ")"
			}
			hint := "use --fetch-aia to confirm, or --ca-file for a private CA"
			if a.Opts.FetchAIA {
				hint = "AIA download did not complete the chain; private CA? use --ca-file"
			}
			rep.add(CheckChain, SevError, "issuer %q of %s was not sent by the server and is not a trusted root%s: incomplete chain or untrusted CA (%s)",
				end.Issuer.String(), label(end), aia, hint)
		}
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		chain.Status = ChainExpired
		for i, c := range certs[1:] {
			if now.After(c.NotAfter) || now.Before(c.NotBefore) {
				a.checkExpiry(rep, c, fmt.Sprintf("chain certificate #%d (%s)", i+1, label(c)), now)
			}
		}
	default:
		chain.Status = ChainInvalid
		rep.add(CheckChain, SevError, "certificate chain is invalid: %v", err)
	}
	// Best effort issuer for OCSP: a served certificate that signed the leaf.
	for _, c := range inter {
		if leaf.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

func subjects(path []*x509.Certificate) []string {
	out := make([]string, 0, len(path))
	for _, c := range path {
		out = append(out, label(c))
	}
	return out
}

func issuerOf(path []*x509.Certificate) *x509.Certificate {
	if len(path) > 1 {
		return path[1]
	}
	return nil
}

// servedPathEnd follows issuer links through the served certificates from
// the leaf and returns the last certificate reached.
func servedPathEnd(certs []*x509.Certificate) *x509.Certificate {
	cur := certs[0]
	used := map[*x509.Certificate]bool{cur: true}
	for {
		if isSelfSigned(cur) {
			return cur
		}
		var next *x509.Certificate
		for _, c := range certs[1:] {
			if !used[c] && bytes.Equal(c.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			return cur
		}
		used[next] = true
		cur = next
	}
}

// checkServedOrder reports out-of-order, superfluous and root certificates
// in the served chain (RFC 8446 §4.4.2 tolerates order issues but many
// clients do not).
func (a *Auditor) checkServedOrder(rep *Report, served, verified []*x509.Certificate) {
	inPath := map[string]bool{}
	for _, c := range verified {
		inPath[string(c.Raw)] = true
	}
	var extra []string
	for i, c := range served[1:] {
		switch {
		case !inPath[string(c.Raw)]:
			extra = append(extra, label(c))
		case isSelfSigned(c):
			rep.add(CheckChain, SevInfo, "server sends the root certificate %s (unnecessary, wastes handshake bytes)", label(c))
		case served[i].CheckSignatureFrom(c) != nil:
			rep.add(CheckChain, SevWarning, "served chain is out of order at position #%d (%s); strict clients may fail", i+1, label(c))
		}
	}
	if len(extra) > 0 {
		rep.add(CheckChain, SevWarning, "server sends %d certificate(s) not part of the validated path: %s", len(extra), strings.Join(extra, ", "))
	}
}

// checkPath checks intermediates of a validated path (expiry, SHA-1).
func (a *Auditor) checkPath(rep *Report, path []*x509.Certificate, now time.Time) {
	for i, c := range path {
		if i == 0 {
			continue
		}
		root := i == len(path)-1 && isSelfSigned(c)
		what := fmt.Sprintf("intermediate %s", label(c))
		if root {
			what = fmt.Sprintf("root %s", label(c))
		}
		a.checkExpiry(rep, c, what, now)
		if !root && weakSignature(c.SignatureAlgorithm) {
			rep.add(CheckChain, SevError, "%s is signed with deprecated algorithm %s", what, c.SignatureAlgorithm)
		}
	}
}

// maxAIA bounds an AIA download.
const maxAIA = 1 << 20

// fetchAIA downloads issuer certificates from caIssuers URLs, following up
// to 3 levels.
func (a *Auditor) fetchAIA(ctx context.Context, rep *Report, certs []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	cur := servedPathEnd(certs)
	for depth := 0; depth < 3 && !isSelfSigned(cur); depth++ {
		var next *x509.Certificate
		for _, u := range cur.IssuingCertificateURL {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				continue
			}
			got, err := a.download(ctx, u)
			if err != nil {
				rep.add(CheckChain, SevInfo, "AIA download %s failed: %v", u, err)
				continue
			}
			for _, c := range got {
				if cur.CheckSignatureFrom(c) == nil {
					next = c
					break
				}
			}
			if next != nil {
				break
			}
		}
		if next == nil {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}

func (a *Auditor) download(ctx context.Context, url string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tlsaudit (AIA fetch)")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAIA+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAIA {
		return nil, errors.New("response too large")
	}
	if certs, err := x509.ParseCertificates(body); err == nil && len(certs) > 0 {
		return certs, nil
	}
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, body = pem.Decode(body)
		if blk == nil {
			break
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no DER/PEM certificate in response (PKCS#7 is not supported)")
	}
	return certs, nil
}

// checkOCSP analyses the stapled OCSP response.
func (a *Auditor) checkOCSP(rep *Report, leaf, issuer *x509.Certificate, staple []byte, now time.Time) {
	res := &OCSPResult{Stapled: len(staple) > 0}
	rep.OCSP = res
	mustStaple := rep.Certificate != nil && rep.Certificate.MustStaple
	if !res.Stapled {
		switch {
		case mustStaple:
			rep.add(CheckOCSP, SevError, "certificate requires OCSP stapling (Must-Staple) but the server sends no OCSP response; Firefox will refuse the connection")
		case len(leaf.OCSPServer) > 0:
			rep.add(CheckOCSP, SevInfo, "no OCSP staple (clients must query %s themselves)", leaf.OCSPServer[0])
		}
		return
	}
	r, err := ocsp.Parse(staple, leaf, issuer)
	if r != nil {
		res.Status = r.Status
		res.ProducedAt = timePtr(r.ProducedAt)
		res.ThisUpdate = timePtr(r.ThisUpdate)
		res.NextUpdate = timePtr(r.NextUpdate)
		res.RevokedAt = timePtr(r.RevokedAt)
		res.SignatureValid = r.SignatureValid
		res.Delegated = r.Delegated
	}
	if err != nil {
		res.Error = err.Error()
		rep.add(CheckOCSP, SevError, "invalid OCSP staple: %v", err)
		if r == nil {
			return
		}
	}
	switch r.Status {
	case ocsp.StatusRevoked:
		rep.add(CheckOCSP, SevError, "certificate is REVOKED (OCSP, revoked at %s)", r.RevokedAt.UTC().Format(time.RFC3339))
	case ocsp.StatusUnknown:
		rep.add(CheckOCSP, SevWarning, "OCSP responder does not know this certificate (status unknown)")
	}
	switch {
	case !r.NextUpdate.IsZero() && now.After(r.NextUpdate):
		rep.add(CheckOCSP, SevError, "stale OCSP staple: nextUpdate %s is in the past (server is not refreshing it)", r.NextUpdate.UTC().Format(time.RFC3339))
	case r.ThisUpdate.After(now.Add(5 * time.Minute)):
		rep.add(CheckOCSP, SevWarning, "OCSP staple thisUpdate %s is in the future (clock skew?)", r.ThisUpdate.UTC().Format(time.RFC3339))
	case r.NextUpdate.IsZero() && now.Sub(r.ProducedAt) > 7*24*time.Hour:
		rep.add(CheckOCSP, SevWarning, "OCSP staple without nextUpdate was produced %d days ago", int(now.Sub(r.ProducedAt).Hours()/24))
	}
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// checkProtocols adds protocol version findings.
func checkProtocols(rep *Report) {
	for _, p := range rep.Protocols {
		switch {
		case p.Error != "":
			rep.add(CheckProtocol, SevInfo, "%s probe inconclusive: %s", p.Protocol, p.Error)
		case !p.Supported:
		case p.Protocol == "SSLv3":
			rep.add(CheckProtocol, SevError, "SSLv3 is enabled (POODLE; prohibited by RFC 7568)")
		case p.Protocol == "TLS1.0" || p.Protocol == "TLS1.1":
			rep.add(CheckProtocol, SevWarning, "%s is enabled (deprecated by RFC 8996)", strings.Replace(p.Protocol, "TLS", "TLS ", 1))
		}
	}
	if !rep.protocolSupported("TLS1.2") && !rep.protocolSupported("TLS1.3") {
		rep.add(CheckProtocol, SevError, "neither TLS 1.2 nor TLS 1.3 is supported")
	} else if !rep.protocolSupported("TLS1.3") {
		rep.add(CheckProtocol, SevInfo, "TLS 1.3 is not supported")
	}
	if rep.SecureRenegotiation != nil && !*rep.SecureRenegotiation {
		rep.add(CheckRenego, SevWarning, "secure renegotiation (RFC 5746) is not supported")
	}
	if rep.FallbackSCSV != nil && !*rep.FallbackSCSV {
		rep.add(CheckFallback, SevWarning, "TLS_FALLBACK_SCSV is not honoured: protocol downgrade attacks are possible while legacy versions stay enabled")
	}
}

// checkCiphers aggregates accepted suites per protocol and grade.
func checkCiphers(rep *Report) {
	type key struct {
		proto string
		grade rawtls.Grade
	}
	groups := map[key][]string{}
	minDH := 0
	for _, c := range rep.Ciphers {
		k := key{c.Protocol, rawtls.Grade(c.Grade)}
		desc := c.Name
		if c.Reason != "" {
			desc += " (" + c.Reason + ")"
		}
		groups[k] = append(groups[k], desc)
		if c.DHBits > 0 && (minDH == 0 || c.DHBits < minDH) {
			minDH = c.DHBits
		}
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].proto != keys[j].proto {
			return keys[i].proto > keys[j].proto
		}
		return keys[i].grade < keys[j].grade
	})
	for _, k := range keys {
		list := groups[k]
		switch k.grade {
		case rawtls.GradeInsecure:
			rep.add(CheckCipher, SevError, "%s accepts %d insecure cipher suite(s): %s", k.proto, len(list), strings.Join(list, ", "))
		case rawtls.GradeWeak:
			rep.add(CheckCipher, SevWarning, "%s accepts %d weak cipher suite(s): %s", k.proto, len(list), strings.Join(list, ", "))
		case rawtls.GradeLegacy:
			rep.add(CheckCipher, SevInfo, "%s accepts %d legacy CBC cipher suite(s)", k.proto, len(list))
		}
	}
	switch {
	case minDH > 0 && minDH < 1024:
		rep.add(CheckKeyExchange, SevError, "DHE uses a %d-bit group (Logjam; minimum 2048)", minDH)
	case minDH > 0 && minDH < 2048:
		rep.add(CheckKeyExchange, SevWarning, "DHE uses a %d-bit group (minimum 2048)", minDH)
	}
}

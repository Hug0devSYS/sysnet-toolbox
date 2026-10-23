package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/ocsp"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/target"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/testpki"
)

func auditor(pool *x509.CertPool) *Auditor {
	return New(Options{Timeout: 3 * time.Second, WarnDays: 30, CritDays: 7, Roots: pool, Ciphers: true})
}

func run(t *testing.T, a *Auditor, addr, spec string) *Report {
	t.Helper()
	tg, err := target.Parse(spec + " connect=" + addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return a.Audit(ctx, tg)
}

func has(r *Report, check string, sev Severity, substr string) bool {
	for _, f := range r.Findings {
		if f.Check == check && f.Severity == sev && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func dump(r *Report) string {
	var b bytes.Buffer
	WriteText(&b, r, false)
	return b.String()
}

func staple(t *testing.T, pki *testpki.PKI, status string, next time.Time) []byte {
	t.Helper()
	now := time.Now()
	der, err := ocsp.Create(pki.Inter.Cert, ocsp.Template{
		Status: status, Serial: pki.Leaf.Cert.SerialNumber, ProducedAt: now,
		ThisUpdate: now.Add(-time.Hour), NextUpdate: next, RevokedAt: now.Add(-time.Hour),
	}, pki.Inter.Key, x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestHealthyEndpoint(t *testing.T) {
	pki := testpki.NewPKI(t, testpki.Options{OCSPServer: []string{"http://ocsp.example.test"}})
	cert := pki.TLSCert(pki.Inter.Cert)
	cert.OCSPStaple = staple(t, pki, ocsp.StatusGood, time.Now().Add(72*time.Hour))
	addr := testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	r := run(t, auditor(pki.Pool()), addr, "www.example.test")
	if r.Summary.Status != "ok" {
		t.Fatalf("status %s\n%s", r.Summary.Status, dump(r))
	}
	if r.Chain.Status != ChainTrusted || !*r.HostnameMatch || !r.OCSP.Stapled || r.OCSP.Status != "good" || !r.OCSP.SignatureValid {
		t.Fatalf("unexpected report\n%s", dump(r))
	}
	if !r.protocolSupported("TLS1.3") || !r.protocolSupported("TLS1.2") || r.protocolSupported("TLS1.1") || r.protocolSupported("SSLv3") {
		t.Fatalf("protocols %+v", r.Protocols)
	}
	if r.Negotiated == nil || r.Negotiated.Protocol != "TLS1.3" {
		t.Fatalf("negotiated %+v", r.Negotiated)
	}
	if len(r.Ciphers) < 4 {
		t.Fatalf("only %d suites enumerated", len(r.Ciphers))
	}
	for _, c := range r.Ciphers {
		if c.Grade != "good" && c.Grade != "legacy" {
			t.Errorf("unexpected suite %+v", c)
		}
	}
	if r.SecureRenegotiation == nil || !*r.SecureRenegotiation || r.FallbackSCSV != nil {
		t.Errorf("reneg %v fallback %v", r.SecureRenegotiation, r.FallbackSCSV)
	}
	if !strings.Contains(dump(r), "Result: OK") {
		t.Error(dump(r))
	}
}

func TestLegacyEndpoint(t *testing.T) {
	pki := testpki.NewPKI(t, testpki.Options{RSABits: 2048})
	addr := testpki.Serve(t, &tls.Config{
		Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert)},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
		},
	})
	r := run(t, auditor(pki.Pool()), addr, "www.example.test")
	if r.Summary.Status != "error" {
		t.Fatalf("status %s\n%s", r.Summary.Status, dump(r))
	}
	for _, want := range []struct {
		check string
		sev   Severity
		sub   string
	}{
		{CheckProtocol, SevWarning, "TLS 1.0 is enabled"},
		{CheckProtocol, SevWarning, "TLS 1.1 is enabled"},
		{CheckProtocol, SevInfo, "TLS 1.3 is not supported"},
		{CheckCipher, SevError, "TLS_RSA_WITH_RC4_128_SHA"},
		{CheckCipher, SevWarning, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	} {
		if !has(r, want.check, want.sev, want.sub) {
			t.Errorf("missing %s/%s %q\n%s", want.check, want.sev, want.sub, dump(r))
		}
	}
	// TLS 1.2 accepts 5 suites, TLS 1.0/1.1 accept the 4 non-GCM ones.
	if len(r.Ciphers) != 5+4+4 {
		t.Errorf("enumerated %d suites, want 13\n%s", len(r.Ciphers), dump(r))
	}
	if r.FallbackSCSV == nil || !*r.FallbackSCSV {
		t.Errorf("Go servers honour TLS_FALLBACK_SCSV, got %v", r.FallbackSCSV)
	}
	// Without enumeration: one suite per version, far fewer connections.
	a := auditor(pki.Pool())
	a.Opts.Ciphers = false
	r2 := run(t, a, addr, "www.example.test")
	if len(r2.Ciphers) != 3 || r2.Connections >= r.Connections {
		t.Errorf("no-ciphers mode: %d suites, %d vs %d connections", len(r2.Ciphers), r2.Connections, r.Connections)
	}
}

func TestChainProblems(t *testing.T) {
	inter := []byte(nil)
	aia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(inter) }))
	defer aia.Close()
	pki := testpki.NewPKI(t, testpki.Options{IssuingURL: []string{aia.URL + "/inter.der"}})
	inter = pki.Inter.Cert.Raw

	// Leaf only: incomplete chain.
	addr := testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert()}})
	r := run(t, auditor(pki.Pool()), addr, "www.example.test")
	if r.Chain.Status != ChainIncomplete || !has(r, CheckChain, SevError, "--fetch-aia") {
		t.Fatalf("leaf only\n%s", dump(r))
	}
	a := auditor(pki.Pool())
	a.Opts.FetchAIA = true
	r = run(t, a, addr, "www.example.test")
	if r.Chain.Status != ChainIncomplete || !has(r, CheckChain, SevError, "found via AIA") || len(r.Chain.Verified) != 3 {
		t.Fatalf("AIA\n%s", dump(r))
	}

	// Untrusted root (system pool does not know the test root), root sent.
	addr = testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert, pki.Root.Cert)}})
	r = run(t, auditor(x509.NewCertPool()), addr, "www.example.test")
	if r.Chain.Status != ChainUntrusted || !has(r, CheckChain, SevError, "not in the trust store") {
		t.Fatalf("untrusted\n%s", dump(r))
	}
	r = run(t, auditor(pki.Pool()), addr, "www.example.test")
	if r.Chain.Status != ChainTrusted || !has(r, CheckChain, SevInfo, "sends the root") {
		t.Fatalf("root sent\n%s", dump(r))
	}

	// Wrong order + unrelated certificate.
	other := testpki.New(t, testpki.Options{CommonName: "Unrelated"}, nil)
	addr = testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert(other.Cert, pki.Inter.Cert)}})
	r = run(t, auditor(pki.Pool()), addr, "www.example.test")
	if r.Chain.Status != ChainTrusted || !has(r, CheckChain, SevWarning, "not part of the validated path") {
		t.Fatalf("unrelated\n%s", dump(r))
	}

	// Self-signed leaf.
	self := testpki.New(t, testpki.Options{CommonName: "self", DNSNames: []string{"www.example.test"}}, nil)
	addr = testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{self.Cert.Raw}, PrivateKey: self.Key}}})
	r = run(t, auditor(pki.Pool()), addr, "www.example.test")
	if r.Chain.Status != ChainUntrusted || !has(r, CheckChain, SevError, "self-signed") {
		t.Fatalf("self-signed\n%s", dump(r))
	}
}

func TestCertificateProblems(t *testing.T) {
	cases := []struct {
		name  string
		opts  testpki.Options
		spec  string
		check string
		sev   Severity
		sub   string
	}{
		{"expiring", testpki.Options{NotAfter: time.Now().Add(10 * 24 * time.Hour)}, "www.example.test", CheckExpiry, SevWarning, "expires in"},
		{"critical", testpki.Options{NotAfter: time.Now().Add(3 * 24 * time.Hour)}, "www.example.test", CheckExpiry, SevError, "expires in"},
		{"expired", testpki.Options{NotBefore: time.Now().Add(-100 * 24 * time.Hour), NotAfter: time.Now().Add(-2 * 24 * time.Hour)}, "www.example.test", CheckExpiry, SevError, "EXPIRED"},
		{"mismatch", testpki.Options{}, "api.example.test", CheckHostname, SevError, `does not match "api.example.test"`},
		{"weak-rsa", testpki.Options{RSABits: 1024}, "www.example.test", CheckCertificate, SevError, "weak RSA key"},
		{"long-lived", testpki.Options{NotAfter: time.Now().Add(800 * 24 * time.Hour)}, "www.example.test", CheckCertificate, SevInfo, "398-day"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pki := testpki.NewPKI(t, c.opts)
			addr := testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert)}})
			a := auditor(pki.Pool())
			a.Opts.Ciphers = false
			r := run(t, a, addr, c.spec)
			if !has(r, c.check, c.sev, c.sub) {
				t.Fatalf("missing %s/%s %q\n%s", c.check, c.sev, c.sub, dump(r))
			}
		})
	}
}

func TestOCSPProblems(t *testing.T) {
	// Must-Staple without staple.
	pki := testpki.NewPKI(t, testpki.Options{MustStaple: true, OCSPServer: []string{"http://ocsp.example.test"}})
	addr := testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert)}})
	a := auditor(pki.Pool())
	a.Opts.Ciphers = false
	r := run(t, a, addr, "www.example.test")
	if !r.Certificate.MustStaple || !has(r, CheckOCSP, SevError, "Must-Staple") {
		t.Fatalf("must-staple\n%s", dump(r))
	}

	for _, c := range []struct {
		status string
		next   time.Time
		sev    Severity
		sub    string
	}{
		{ocsp.StatusRevoked, time.Now().Add(time.Hour), SevError, "REVOKED"},
		{ocsp.StatusUnknown, time.Now().Add(time.Hour), SevWarning, "status unknown"},
		{ocsp.StatusGood, time.Now().Add(-time.Minute), SevError, "stale OCSP staple"},
	} {
		pki := testpki.NewPKI(t, testpki.Options{OCSPServer: []string{"http://ocsp.example.test"}})
		cert := pki.TLSCert(pki.Inter.Cert)
		cert.OCSPStaple = staple(t, pki, c.status, c.next)
		addr := testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{cert}})
		r := run(t, a, addr, "www.example.test")
		if !has(r, CheckOCSP, c.sev, c.sub) {
			t.Errorf("%s: missing %q\n%s", c.status, c.sub, dump(r))
		}
	}
}

func TestConnectFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens any more
	r := run(t, auditor(nil), addr, "www.example.test")
	if r.Error == "" || r.Summary.Status != "error" || !has(r, CheckConnect, SevError, "cannot connect") {
		t.Fatalf("refused\n%s", dump(r))
	}

	// Plain-text server: TCP works, TLS never does.
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	r = run(t, auditor(nil), ln.Addr().String(), "www.example.test")
	if r.Error == "" || !has(r, CheckConnect, SevError, "no TLS handshake succeeded") {
		t.Fatalf("plaintext\n%s", dump(r))
	}

	// Resolution failure via the resolver.
	a := auditor(nil)
	a.Resolver = failResolver{}
	tg, _ := target.Parse("nowhere.invalid")
	r = a.Audit(context.Background(), tg)
	if !has(r, CheckConnect, SevError, "cannot resolve") {
		t.Fatalf("resolve\n%s", dump(r))
	}
}

type failResolver struct{}

func (failResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: "nowhere.invalid", IsNotFound: true}
}

func TestPromOutput(t *testing.T) {
	pki := testpki.NewPKI(t, testpki.Options{})
	addr := testpki.Serve(t, &tls.Config{Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert)}})
	a := auditor(pki.Pool())
	a.Opts.Ciphers = false
	r := run(t, a, addr, "www.example.test")
	path := filepath.Join(t.TempDir(), "tlsaudit.prom")
	now := time.Unix(1_800_000_000, 0)
	if err := WritePromFile(path, []*Report{r, {Name: `we"ird:443`, Error: "x"}}, now); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, want := range []string{
		"# TYPE tlsaudit_probe_success gauge",
		`tlsaudit_probe_success{target="` + r.Name + `",servername="www.example.test",connect="` + addr + `"} 1`,
		`tlsaudit_probe_success{target="we\"ird:443",servername=""} 0`,
		`tlsaudit_protocol_enabled{target="` + r.Name + `",servername="www.example.test",connect="` + addr + `",protocol="TLS1.3"} 1`,
		`tlsaudit_chain_trusted{target="` + r.Name + `",servername="www.example.test",connect="` + addr + `"} 1`,
		"tlsaudit_last_run_timestamp_seconds 1800000000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "# HELP tlsaudit_findings ") != 1 {
		t.Error("HELP must appear once per metric family")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestSummaryAndText(t *testing.T) {
	r := &Report{Name: "a.example:443", Summary: Summary{Status: "warning"},
		Findings:  []Finding{{Check: CheckProtocol, Severity: SevInfo, Message: "info"}, {Check: CheckExpiry, Severity: SevWarning, Message: "expires soon"}},
		Protocols: []ProtocolResult{{Protocol: "TLS1.2", Supported: true}, {Protocol: "TLS1.3", Error: "timeout"}},
	}
	var b bytes.Buffer
	WriteSummary(&b, []*Report{r})
	if !strings.Contains(b.String(), "[expiry] expires soon") || !strings.Contains(b.String(), "TLS1.2") {
		t.Fatal(b.String())
	}
	b.Reset()
	WriteText(&b, r, true)
	if !strings.Contains(b.String(), "\x1b[") || !strings.Contains(b.String(), "TLS1.3 ?") {
		t.Fatal(b.String())
	}
}

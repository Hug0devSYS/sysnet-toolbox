package ocsp_test

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/ocsp"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/testpki"
)

func TestParseStatuses(t *testing.T) {
	pki := testpki.NewPKI(t, testpki.Options{})
	now := time.Now()
	for _, st := range []string{ocsp.StatusGood, ocsp.StatusRevoked, ocsp.StatusUnknown} {
		der, err := ocsp.Create(pki.Inter.Cert, ocsp.Template{
			Status: st, Serial: pki.Leaf.Cert.SerialNumber, ProducedAt: now,
			ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(3 * 24 * time.Hour), RevokedAt: now.Add(-2 * time.Hour),
		}, pki.Inter.Key, x509.ECDSAWithSHA256)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ocsp.Parse(der, pki.Leaf.Cert, pki.Inter.Cert)
		if err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		if r.Status != st || !r.SignatureValid || r.Delegated || r.NextUpdate.IsZero() {
			t.Fatalf("%s: %+v", st, r)
		}
		if st == ocsp.StatusRevoked && r.RevokedAt.IsZero() {
			t.Error("revocation time missing")
		}
	}
}

func TestParseDelegatedAndFailures(t *testing.T) {
	pki := testpki.NewPKI(t, testpki.Options{})
	now := time.Now()
	responder := testpki.New(t, testpki.Options{CommonName: "OCSP responder", ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, pki.Inter)
	tmpl := ocsp.Template{Status: ocsp.StatusGood, Serial: pki.Leaf.Cert.SerialNumber, ProducedAt: now, ThisUpdate: now, ResponderCert: responder.Cert}
	der, err := ocsp.Create(pki.Inter.Cert, tmpl, responder.Key, x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ocsp.Parse(der, pki.Leaf.Cert, pki.Inter.Cert)
	if err != nil || !r.Delegated || !r.SignatureValid || !r.NextUpdate.IsZero() {
		t.Fatalf("delegated: %+v %v", r, err)
	}

	// Responder without the OCSPSigning EKU.
	bad := testpki.New(t, testpki.Options{CommonName: "not a responder"}, pki.Inter)
	tmpl.ResponderCert = bad.Cert
	der, _ = ocsp.Create(pki.Inter.Cert, tmpl, bad.Key, x509.ECDSAWithSHA256)
	if _, err := ocsp.Parse(der, pki.Leaf.Cert, pki.Inter.Cert); err == nil || !strings.Contains(err.Error(), "OCSPSigning") {
		t.Fatalf("missing EKU: %v", err)
	}

	// Signed by the wrong key.
	tmpl.ResponderCert = nil
	der, _ = ocsp.Create(pki.Inter.Cert, tmpl, pki.Leaf.Key, x509.ECDSAWithSHA256)
	if r, err := ocsp.Parse(der, pki.Leaf.Cert, pki.Inter.Cert); err == nil || r == nil || r.SignatureValid {
		t.Fatalf("bad signature accepted: %+v %v", r, err)
	}

	// Response for another serial.
	tmpl.Serial = big.NewInt(42)
	der, _ = ocsp.Create(pki.Inter.Cert, tmpl, pki.Inter.Key, x509.ECDSAWithSHA256)
	if _, err := ocsp.Parse(der, pki.Leaf.Cert, pki.Inter.Cert); err == nil || !strings.Contains(err.Error(), "CertID") {
		t.Fatalf("CertID mismatch: %v", err)
	}

	// Non-successful responseStatus and garbage.
	tryLater, _ := asn1.Marshal(struct{ S asn1.Enumerated }{3})
	if _, err := ocsp.Parse(tryLater, pki.Leaf.Cert, pki.Inter.Cert); err == nil || !strings.Contains(err.Error(), "tryLater") {
		t.Fatalf("tryLater: %v", err)
	}
	if _, err := ocsp.Parse([]byte{1, 2, 3}, pki.Leaf.Cert, pki.Inter.Cert); err == nil {
		t.Fatal("garbage accepted")
	}

	// Unknown issuer: status is reported, signature unverified.
	tmpl.Serial = pki.Leaf.Cert.SerialNumber
	der, _ = ocsp.Create(pki.Inter.Cert, tmpl, pki.Inter.Key, x509.ECDSAWithSHA256)
	r, err = ocsp.Parse(der, pki.Leaf.Cert, nil)
	if err == nil || r == nil || r.Status != ocsp.StatusGood || r.SignatureValid {
		t.Fatalf("nil issuer: %+v %v", r, err)
	}
}

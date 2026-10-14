// Package ocsp parses and verifies stapled OCSP responses (RFC 6960) using
// only the Go standard library.
package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	_ "crypto/sha1"   // register SHA-1 for CertID hashes
	_ "crypto/sha256" // register SHA-256/384/512
	_ "crypto/sha512"
)

// Certificate statuses.
const (
	StatusGood    = "good"
	StatusRevoked = "revoked"
	StatusUnknown = "unknown"
)

var (
	oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidOCSPSigning   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

var sigAlgs = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.5":  x509.SHA1WithRSA,
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.10045.4.1":     x509.ECDSAWithSHA1,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	"1.3.101.112":           x509.PureEd25519,
}

// ASN.1 structures (RFC 6960 §4.2.1).
type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
	Extensions     []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// Response is a parsed and verified OCSP response for one certificate.
type Response struct {
	Status         string
	ProducedAt     time.Time
	ThisUpdate     time.Time
	NextUpdate     time.Time // zero if absent
	RevokedAt      time.Time
	RevokedReason  int
	SignatureValid bool
	// Delegated is true when the response was signed by a delegated OCSP
	// responder certificate rather than by the issuer itself.
	Delegated bool
}

// responseStatus values (RFC 6960 §4.2.1) other than successful.
var responseStatusNames = map[int]string{
	1: "malformedRequest",
	2: "internalError",
	3: "tryLater",
	5: "sigRequired",
	6: "unauthorized",
}

// Parse decodes a DER OCSP response, selects the SingleResponse that matches
// cert (by issuer key hash and serial) and verifies the response signature
// against issuer (directly or via a delegated responder certificate signed
// by issuer). A signature problem is reported as an error.
func Parse(der []byte, cert, issuer *x509.Certificate) (*Response, error) {
	var resp responseASN1
	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return nil, fmt.Errorf("ocsp: malformed response: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("ocsp: trailing data after response")
	}
	if resp.Status != 0 {
		name := responseStatusNames[int(resp.Status)]
		if name == "" {
			name = fmt.Sprintf("status %d", resp.Status)
		}
		return nil, fmt.Errorf("ocsp: responder returned %s", name)
	}
	if !resp.Response.ResponseType.Equal(oidBasicResponse) {
		return nil, fmt.Errorf("ocsp: unsupported response type %v", resp.Response.ResponseType)
	}
	var basic basicResponse
	if rest, err := asn1.Unmarshal(resp.Response.Response, &basic); err != nil || len(rest) > 0 {
		return nil, errors.New("ocsp: malformed BasicOCSPResponse")
	}
	var data responseData
	if rest, err := asn1.Unmarshal(basic.TBSResponseData.FullBytes, &data); err != nil || len(rest) > 0 {
		return nil, errors.New("ocsp: malformed ResponseData")
	}

	var single *singleResponse
	for i := range data.Responses {
		if matches(&data.Responses[i].CertID, cert, issuer) {
			single = &data.Responses[i]
			break
		}
	}
	if single == nil {
		return nil, errors.New("ocsp: response does not cover this certificate (CertID mismatch)")
	}
	r := &Response{
		ProducedAt: data.ProducedAt,
		ThisUpdate: single.ThisUpdate,
		NextUpdate: single.NextUpdate,
	}
	switch {
	case bool(single.Good):
		r.Status = StatusGood
	case bool(single.Unknown):
		r.Status = StatusUnknown
	default:
		r.Status = StatusRevoked
		r.RevokedAt = single.Revoked.RevocationTime
		r.RevokedReason = int(single.Revoked.Reason)
	}

	if issuer == nil {
		return r, errors.New("ocsp: issuer certificate unknown, signature not verified")
	}
	algo, ok := sigAlgs[basic.SignatureAlgorithm.Algorithm.String()]
	if !ok {
		return r, fmt.Errorf("ocsp: unsupported signature algorithm %v, signature not verified", basic.SignatureAlgorithm.Algorithm)
	}
	signer := issuer
	if len(basic.Certificates) > 0 {
		rc, err := x509.ParseCertificate(basic.Certificates[0].FullBytes)
		if err != nil {
			return r, fmt.Errorf("ocsp: bad responder certificate: %w", err)
		}
		if !bytes.Equal(rc.Raw, issuer.Raw) {
			if err := rc.CheckSignatureFrom(issuer); err != nil {
				return r, fmt.Errorf("ocsp: delegated responder certificate not issued by the certificate's issuer: %w", err)
			}
			if !hasOCSPSigning(rc) {
				return r, errors.New("ocsp: delegated responder certificate lacks the OCSPSigning extended key usage")
			}
			signer = rc
			r.Delegated = true
		}
	}
	if err := signer.CheckSignature(algo, basic.TBSResponseData.FullBytes, basic.Signature.RightAlign()); err != nil {
		return r, fmt.Errorf("ocsp: invalid response signature: %w", err)
	}
	r.SignatureValid = true
	return r, nil
}

func hasOCSPSigning(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	for _, u := range c.UnknownExtKeyUsage {
		if u.Equal(oidOCSPSigning) {
			return true
		}
	}
	return false
}

func hashFor(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	}
	return 0
}

func matches(id *certID, cert, issuer *x509.Certificate) bool {
	if cert == nil || id.SerialNumber == nil || id.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}
	if issuer == nil {
		return true // serial-only match; the caller reports the missing issuer
	}
	h := hashFor(id.HashAlgorithm.Algorithm)
	if h == 0 || !h.Available() {
		return false
	}
	nameHash, keyHash, err := issuerHashes(h, issuer)
	if err != nil {
		return false
	}
	return bytes.Equal(nameHash, id.NameHash) && bytes.Equal(keyHash, id.IssuerKeyHash)
}

func issuerHashes(h crypto.Hash, issuer *x509.Certificate) (nameHash, keyHash []byte, err error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, err
	}
	hh := h.New()
	hh.Write(issuer.RawSubject)
	nameHash = hh.Sum(nil)
	hh = h.New()
	hh.Write(spki.PublicKey.RightAlign())
	keyHash = hh.Sum(nil)
	return nameHash, keyHash, nil
}

// Template describes a response to build with Create (used by tests and
// lab tooling; tlsaudit itself never signs anything).
type Template struct {
	Status        string
	ProducedAt    time.Time
	ThisUpdate    time.Time
	NextUpdate    time.Time
	RevokedAt     time.Time
	Serial        *big.Int
	ResponderCert *x509.Certificate // embedded when not the issuer
}

// Create builds a DER OCSP response for cert signed by signer (a private key
// matching issuer or t.ResponderCert), with SHA-256 CertID hashes.
func Create(issuer *x509.Certificate, t Template, signer crypto.Signer, algo x509.SignatureAlgorithm) ([]byte, error) {
	nameHash, keyHash, err := issuerHashes(crypto.SHA256, issuer)
	if err != nil {
		return nil, err
	}
	sr := singleResponse{
		CertID: certID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			NameHash:      nameHash,
			IssuerKeyHash: keyHash,
			SerialNumber:  t.Serial,
		},
		ThisUpdate: t.ThisUpdate.UTC(),
		NextUpdate: t.NextUpdate.UTC(),
	}
	switch t.Status {
	case StatusGood:
		sr.Good = true
	case StatusUnknown:
		sr.Unknown = true
	case StatusRevoked:
		sr.Revoked = revokedInfo{RevocationTime: t.RevokedAt.UTC()}
	default:
		return nil, fmt.Errorf("ocsp: unknown status %q", t.Status)
	}
	responder := issuer
	if t.ResponderCert != nil {
		responder = t.ResponderCert
	}
	rid := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: responder.RawSubject}
	tbs, err := asn1.Marshal(responseData{
		RawResponderID: rid,
		ProducedAt:     t.ProducedAt.UTC().Truncate(time.Second),
		Responses:      []singleResponse{sr},
	})
	if err != nil {
		return nil, err
	}
	var hash crypto.Hash
	var algOID asn1.ObjectIdentifier
	switch algo {
	case x509.ECDSAWithSHA256:
		hash, algOID = crypto.SHA256, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	case x509.SHA256WithRSA:
		hash, algOID = crypto.SHA256, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	default:
		return nil, fmt.Errorf("ocsp: Create does not support %v", algo)
	}
	hh := hash.New()
	hh.Write(tbs)
	sig, err := signer.Sign(nil, hh.Sum(nil), hash)
	if err != nil {
		return nil, err
	}
	br := basicResponse{
		TBSResponseData:    asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algOID},
		Signature:          asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	}
	if t.ResponderCert != nil {
		br.Certificates = []asn1.RawValue{{FullBytes: t.ResponderCert.Raw}}
	}
	brDER, err := asn1.Marshal(br)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(responseASN1{
		Status:   0,
		Response: responseBytes{ResponseType: oidBasicResponse, Response: brDER},
	})
}

// Package testpki builds throw-away certificate hierarchies and TLS servers
// for tlsaudit's tests. It is never used by the tlsaudit binary.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

var serial atomic.Int64

// Cert bundles a certificate and its private key.
type Cert struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Options customises a generated certificate.
type Options struct {
	CommonName  string
	DNSNames    []string
	IPs         []net.IP
	NotBefore   time.Time
	NotAfter    time.Time
	IsCA        bool
	OCSPServer  []string
	IssuingURL  []string
	MustStaple  bool
	RSABits     int // 0 = ECDSA P-256
	SigAlg      x509.SignatureAlgorithm
	ExtKeyUsage []x509.ExtKeyUsage
}

// New creates a certificate signed by parent (self-signed when parent is nil).
func New(t testing.TB, o Options, parent *Cert) *Cert {
	t.Helper()
	var key crypto.Signer
	var err error
	if o.RSABits > 0 {
		key, err = rsa.GenerateKey(rand.Reader, o.RSABits)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-24 * time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1000 + serial.Add(1)),
		Subject:               pkix.Name{CommonName: o.CommonName, Organization: []string{"tlsaudit test"}},
		NotBefore:             o.NotBefore,
		NotAfter:              o.NotAfter,
		DNSNames:              o.DNSNames,
		IPAddresses:           o.IPs,
		BasicConstraintsValid: true,
		IsCA:                  o.IsCA,
		OCSPServer:            o.OCSPServer,
		IssuingCertificateURL: o.IssuingURL,
		SignatureAlgorithm:    o.SigAlg,
	}
	if o.IsCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if o.ExtKeyUsage != nil {
		tmpl.ExtKeyUsage = o.ExtKeyUsage
	}
	if o.MustStaple {
		// TLS Feature extension (RFC 7633) with status_request (5).
		v, _ := asn1.Marshal([]int{5})
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: v,
		})
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Cert{Cert: c, Key: key}
}

// PKI is a root -> intermediate -> leaf hierarchy.
type PKI struct {
	Root, Inter, Leaf *Cert
}

// NewPKI builds a hierarchy whose leaf is valid for the given DNS names
// (and 127.0.0.1). leafOpts may override leaf fields.
func NewPKI(t testing.TB, leafOpts Options) *PKI {
	t.Helper()
	root := New(t, Options{CommonName: "Test Root CA", IsCA: true, NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}, nil)
	inter := New(t, Options{CommonName: "Test Issuing CA", IsCA: true, NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour)}, root)
	if leafOpts.CommonName == "" {
		leafOpts.CommonName = "www.example.test"
	}
	if leafOpts.DNSNames == nil {
		leafOpts.DNSNames = []string{"www.example.test", "example.test"}
	}
	if leafOpts.IPs == nil {
		leafOpts.IPs = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	leaf := New(t, leafOpts, inter)
	return &PKI{Root: root, Inter: inter, Leaf: leaf}
}

// Pool returns a cert pool containing only the root.
func (p *PKI) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.Root.Cert)
	return pool
}

// TLSCert returns a tls.Certificate serving leaf + the given extra chain.
func (p *PKI) TLSCert(chain ...*x509.Certificate) tls.Certificate {
	tc := tls.Certificate{Certificate: [][]byte{p.Leaf.Cert.Raw}, PrivateKey: p.Leaf.Key, Leaf: p.Leaf.Cert}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	return tc
}

// Serve starts a TLS server on 127.0.0.1 with cfg and returns its address.
// Each connection completes the handshake and is then closed.
func Serve(t testing.TB, cfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

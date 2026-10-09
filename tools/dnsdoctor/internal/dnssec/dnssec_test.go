package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

var now = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T, alg uint8) (*dnswire.DNSKEY, crypto.Signer) {
	t.Helper()
	var s crypto.Signer
	var err error
	switch alg {
	case AlgED25519:
		_, s, err = ed25519.GenerateKey(rand.Reader)
	case AlgECDSAP256SHA256:
		s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgECDSAP384SHA384:
		s, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgRSASHA256, AlgRSASHA512:
		s, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyBytes(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &dnswire.DNSKEY{Flags: 257, Protocol: 3, Algorithm: alg, PublicKey: pub}, s
}

func rrset() []dnswire.RR {
	return []dnswire.RR{
		{Name: "Example.TEST.", Type: dnswire.TypeNS, Class: 1, TTL: 3600, Data: &dnswire.NS{Host: "NS2.example.test."}},
		{Name: "example.test.", Type: dnswire.TypeNS, Class: 1, TTL: 3600, Data: &dnswire.NS{Host: "ns1.example.test."}},
	}
}

func sigFor(k *dnswire.DNSKEY, labels uint8) *dnswire.RRSIG {
	return &dnswire.RRSIG{
		TypeCovered: dnswire.TypeNS, Algorithm: k.Algorithm, Labels: labels, OrigTTL: 3600,
		Inception: uint32(now.Add(-24 * time.Hour).Unix()), Expiration: uint32(now.Add(14 * 24 * time.Hour).Unix()),
		KeyTag: KeyTag(k), SignerName: "example.test.",
	}
}

func TestSignVerifyAllAlgorithms(t *testing.T) {
	for _, alg := range []uint8{AlgED25519, AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgRSASHA256, AlgRSASHA512} {
		t.Run(AlgorithmName(alg), func(t *testing.T) {
			k, s := newKey(t, alg)
			sig := sigFor(k, 2)
			if err := Sign(rrset(), sig, s); err != nil {
				t.Fatal(err)
			}
			if err := Verify(rrset(), sig, k, now); err != nil {
				t.Fatalf("verify: %v", err)
			}
			// RRset order and owner/RDATA case must not matter (canonical form).
			rev := rrset()
			rev[0], rev[1] = rev[1], rev[0]
			rev[0].Name = "EXAMPLE.test."
			rev[1].Data = &dnswire.NS{Host: "ns2.EXAMPLE.test."}
			if err := Verify(rev, sig, k, now); err != nil {
				t.Fatalf("verify canonicalised: %v", err)
			}
			// Tampering must fail.
			bad := rrset()
			bad[1].Data = &dnswire.NS{Host: "evil.example.test."}
			if err := Verify(bad, sig, k, now); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("tampered: got %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestVerifyValidityWindow(t *testing.T) {
	k, s := newKey(t, AlgED25519)
	sig := sigFor(k, 2)
	if err := Sign(rrset(), sig, s); err != nil {
		t.Fatal(err)
	}
	if err := Verify(rrset(), sig, k, now.Add(30*24*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
	if err := Verify(rrset(), sig, k, now.Add(-48*time.Hour)); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("got %v, want ErrNotYetValid", err)
	}
}

func TestVerifyKeyChecks(t *testing.T) {
	k, s := newKey(t, AlgED25519)
	sig := sigFor(k, 2)
	if err := Sign(rrset(), sig, s); err != nil {
		t.Fatal(err)
	}
	other, _ := newKey(t, AlgED25519)
	if err := Verify(rrset(), sig, other, now); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("other key: %v", err)
	}
	revoked := *k
	revoked.Flags |= FlagRevoke
	if err := Verify(rrset(), sig, &revoked, now); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("revoked key: %v", err)
	}
	noZone := *k
	noZone.Flags = 0
	if err := Verify(rrset(), sig, &noZone, now); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("non-zone key: %v", err)
	}
	wrongSigner := *sig
	wrongSigner.SignerName = "other.test."
	if err := Verify(rrset(), &wrongSigner, k, now); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong signer: %v", err)
	}
}

func TestWildcardExpansion(t *testing.T) {
	k, s := newKey(t, AlgECDSAP256SHA256)
	wild := []dnswire.RR{{Name: "*.example.test.", Type: dnswire.TypeA, Class: 1, TTL: 300, Data: &dnswire.A{Addr: netip.MustParseAddr("192.0.2.1")}}}
	sig := &dnswire.RRSIG{TypeCovered: dnswire.TypeA, Algorithm: k.Algorithm, Labels: 2, OrigTTL: 300,
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(time.Hour).Unix()),
		KeyTag: KeyTag(k), SignerName: "example.test."}
	if err := Sign(wild, sig, s); err != nil {
		t.Fatal(err)
	}
	expanded := []dnswire.RR{{Name: "host.sub.example.test.", Type: dnswire.TypeA, Class: 1, TTL: 300, Data: &dnswire.A{Addr: netip.MustParseAddr("192.0.2.1")}}}
	if err := Verify(expanded, sig, k, now); err != nil {
		t.Fatalf("wildcard-expanded answer should validate: %v", err)
	}
}

func TestSerialTimeWraps(t *testing.T) {
	// A timestamp just after the 2106 wrap must resolve forward when now is near it.
	n := time.Unix(1<<32-100, 0)
	got := serialTime(50, n)
	if got.Unix() != 1<<32+50 {
		t.Fatalf("got %d", got.Unix())
	}
	if got := serialTime(uint32(now.Unix()), now); !got.Equal(now) {
		t.Fatalf("got %v", got)
	}
}

func TestParseRSAKeyRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {1}, {0, 0, 0, 1}, {9, 1, 2, 3}} {
		if _, err := ParseRSAKey(b); err == nil {
			t.Fatalf("ParseRSAKey(%x) succeeded", b)
		}
	}
	if err := verifyRaw(99, nil, nil, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("got %v", err)
	}
	if Supported(99) || !Supported(AlgED25519) || !Deprecated(AlgRSASHA1) || Deprecated(AlgRSASHA256) {
		t.Fatal("algorithm tables wrong")
	}
}

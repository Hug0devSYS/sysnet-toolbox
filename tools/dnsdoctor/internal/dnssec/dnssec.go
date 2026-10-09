// Package dnssec implements DNSSEC primitives needed to validate a chain of
// trust: key tags, DS digests and RRSIG verification (RFC 4034, RFC 5702,
// RFC 6605, RFC 8080), using only the Go standard library.
package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 DS digests and RSASHA1 still exist in the wild.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

// DNSSEC algorithm numbers (IANA "DNS Security Algorithm Numbers").
const (
	AlgRSASHA1          uint8 = 5
	AlgRSASHA1NSEC3SHA1 uint8 = 7
	AlgRSASHA256        uint8 = 8
	AlgRSASHA512        uint8 = 10
	AlgECDSAP256SHA256  uint8 = 13
	AlgECDSAP384SHA384  uint8 = 14
	AlgED25519          uint8 = 15
)

// DS digest types.
const (
	DigestSHA1   uint8 = 1
	DigestSHA256 uint8 = 2
	DigestSHA384 uint8 = 4
)

// DNSKEY flag bits.
const (
	FlagZone   uint16 = 0x0100
	FlagSEP    uint16 = 0x0001
	FlagRevoke uint16 = 0x0080
)

// AlgorithmName returns the mnemonic for a DNSSEC algorithm.
func AlgorithmName(a uint8) string {
	switch a {
	case AlgRSASHA1:
		return "RSASHA1"
	case AlgRSASHA1NSEC3SHA1:
		return "RSASHA1-NSEC3-SHA1"
	case AlgRSASHA256:
		return "RSASHA256"
	case AlgRSASHA512:
		return "RSASHA512"
	case AlgECDSAP256SHA256:
		return "ECDSAP256SHA256"
	case AlgECDSAP384SHA384:
		return "ECDSAP384SHA384"
	case AlgED25519:
		return "ED25519"
	default:
		return fmt.Sprintf("ALG%d", a)
	}
}

// Deprecated reports whether an algorithm is "MUST NOT"/"NOT RECOMMENDED"
// for signing according to RFC 8624.
func Deprecated(a uint8) bool {
	switch a {
	case 1, 3, 5, 6, 7, 12:
		return true
	}
	return false
}

// Errors returned by Verify.
var (
	ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")
	ErrUnsupportedDigest    = errors.New("dnssec: unsupported digest type")
	ErrBadSignature         = errors.New("dnssec: signature verification failed")
	ErrExpired              = errors.New("dnssec: signature expired")
	ErrNotYetValid          = errors.New("dnssec: signature not yet valid")
	ErrKeyMismatch          = errors.New("dnssec: key does not match signature")
	ErrBadKey               = errors.New("dnssec: malformed public key")
	ErrEmptyRRset           = errors.New("dnssec: empty RRset")
)

// KeyTag computes the RFC 4034 Appendix B key tag of a DNSKEY.
func KeyTag(k *dnswire.DNSKEY) uint16 {
	rd := make([]byte, 0, 4+len(k.PublicKey))
	rd = binary.BigEndian.AppendUint16(rd, k.Flags)
	rd = append(rd, k.Protocol, k.Algorithm)
	rd = append(rd, k.PublicKey...)
	var ac uint32
	for i, b := range rd {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += ac >> 16 & 0xffff
	return uint16(ac & 0xffff)
}

// ComputeDS returns the DS record for a DNSKEY owned by owner.
func ComputeDS(owner string, k *dnswire.DNSKEY, digestType uint8) (*dnswire.DS, error) {
	ownerWire, err := canonicalNameWire(owner)
	if err != nil {
		return nil, err
	}
	rd, err := dnswire.PackRData(dnswire.RR{Type: dnswire.TypeDNSKEY, Data: k}, true)
	if err != nil {
		return nil, err
	}
	input := append(ownerWire, rd...)
	var digest []byte
	switch digestType {
	case DigestSHA1:
		s := sha1.Sum(input) //nolint:gosec
		digest = s[:]
	case DigestSHA256:
		s := sha256.Sum256(input)
		digest = s[:]
	case DigestSHA384:
		s := sha512.Sum384(input)
		digest = s[:]
	default:
		return nil, ErrUnsupportedDigest
	}
	return &dnswire.DS{KeyTag: KeyTag(k), Algorithm: k.Algorithm, DigestType: digestType, Digest: digest}, nil
}

// MatchDS reports whether ds authenticates the DNSKEY owned by owner.
func MatchDS(owner string, ds *dnswire.DS, k *dnswire.DNSKEY) (bool, error) {
	if ds.KeyTag != KeyTag(k) || ds.Algorithm != k.Algorithm {
		return false, nil
	}
	got, err := ComputeDS(owner, k, ds.DigestType)
	if err != nil {
		return false, err
	}
	return bytes.Equal(got.Digest, ds.Digest), nil
}

func canonicalNameWire(name string) ([]byte, error) {
	rr := dnswire.RR{Type: dnswire.TypeNS, Data: &dnswire.NS{Host: name}}
	return dnswire.PackRData(rr, true)
}

// SignedData builds the byte string covered by sig over rrset
// (RFC 4034 section 3.1.8.1 and section 6).
func SignedData(rrset []dnswire.RR, sig *dnswire.RRSIG) ([]byte, error) {
	if len(rrset) == 0 {
		return nil, ErrEmptyRRset
	}
	head, err := sig.PackNoSig()
	if err != nil {
		return nil, err
	}
	owner := rrset[0].Name
	// Wildcard expansion: if the RRSIG labels field is smaller than the
	// owner's label count, the signed owner is "*." + rightmost labels.
	if n := dnswire.CountLabels(owner); int(sig.Labels) < n {
		owner = "*." + dnswire.LastLabels(owner, int(sig.Labels))
		if sig.Labels == 0 {
			owner = "*."
		}
	}
	ownerWire, err := canonicalNameWire(owner)
	if err != nil {
		return nil, err
	}
	class := rrset[0].Class
	if class == 0 {
		class = dnswire.ClassINET
	}

	rdatas := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		rd, err := dnswire.PackRData(rr, true)
		if err != nil {
			return nil, err
		}
		rdatas = append(rdatas, rd)
	}
	sort.Slice(rdatas, func(i, j int) bool { return bytes.Compare(rdatas[i], rdatas[j]) < 0 })

	out := append([]byte(nil), head...)
	var prev []byte
	for i, rd := range rdatas {
		if i > 0 && bytes.Equal(rd, prev) {
			continue // duplicates are removed (RFC 4034 6.3)
		}
		prev = rd
		out = append(out, ownerWire...)
		out = binary.BigEndian.AppendUint16(out, uint16(sig.TypeCovered))
		out = binary.BigEndian.AppendUint16(out, class)
		out = binary.BigEndian.AppendUint32(out, sig.OrigTTL)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
		out = append(out, rd...)
	}
	return out, nil
}

// serialTime converts an RRSIG 32-bit timestamp to the absolute time closest
// to now, using RFC 1982 serial number arithmetic (RFC 4034 3.1.5).
func serialTime(ts uint32, now time.Time) time.Time {
	n := now.Unix()
	base := n &^ 0xffffffff
	t := base | int64(ts)
	const half = int64(1) << 31
	switch {
	case t-n > half:
		t -= 1 << 32
	case n-t > half:
		t += 1 << 32
	}
	return time.Unix(t, 0).UTC()
}

// Validity returns the absolute inception and expiration of sig.
func Validity(sig *dnswire.RRSIG, now time.Time) (inception, expiration time.Time) {
	return serialTime(sig.Inception, now), serialTime(sig.Expiration, now)
}

// Verify checks sig over rrset with key at time now.
func Verify(rrset []dnswire.RR, sig *dnswire.RRSIG, key *dnswire.DNSKEY, now time.Time) error {
	if len(rrset) == 0 {
		return ErrEmptyRRset
	}
	if key.Protocol != 3 || key.Flags&FlagZone == 0 || key.Flags&FlagRevoke != 0 {
		return ErrKeyMismatch
	}
	if sig.Algorithm != key.Algorithm || sig.KeyTag != KeyTag(key) {
		return ErrKeyMismatch
	}
	if !dnswire.IsSubdomain(rrset[0].Name, sig.SignerName) {
		return fmt.Errorf("%w: signer %s is not an ancestor of %s", ErrKeyMismatch, sig.SignerName, rrset[0].Name)
	}
	inc, exp := Validity(sig, now)
	if now.Before(inc) {
		return fmt.Errorf("%w (inception %s)", ErrNotYetValid, inc.Format(time.RFC3339))
	}
	if now.After(exp) {
		return fmt.Errorf("%w (expired %s)", ErrExpired, exp.Format(time.RFC3339))
	}
	data, err := SignedData(rrset, sig)
	if err != nil {
		return err
	}
	return verifyRaw(key.Algorithm, key.PublicKey, data, sig.Signature)
}

func hashFor(alg uint8) (crypto.Hash, bool) {
	switch alg {
	case AlgRSASHA1, AlgRSASHA1NSEC3SHA1:
		return crypto.SHA1, true
	case AlgRSASHA256, AlgECDSAP256SHA256:
		return crypto.SHA256, true
	case AlgRSASHA512:
		return crypto.SHA512, true
	case AlgECDSAP384SHA384:
		return crypto.SHA384, true
	}
	return 0, false
}

func digest(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

func verifyRaw(alg uint8, pub, data, signature []byte) error {
	switch alg {
	case AlgRSASHA1, AlgRSASHA1NSEC3SHA1, AlgRSASHA256, AlgRSASHA512:
		k, err := ParseRSAKey(pub)
		if err != nil {
			return err
		}
		h, _ := hashFor(alg)
		if err := rsa.VerifyPKCS1v15(k, h, digest(h, data), signature); err != nil {
			return ErrBadSignature
		}
		return nil
	case AlgECDSAP256SHA256, AlgECDSAP384SHA384:
		curve, size := elliptic.P256(), 32
		if alg == AlgECDSAP384SHA384 {
			curve, size = elliptic.P384(), 48
		}
		if len(pub) != 2*size {
			return ErrBadKey
		}
		if len(signature) != 2*size {
			return ErrBadSignature
		}
		k := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(pub[:size]),
			Y:     new(big.Int).SetBytes(pub[size:]),
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		h, _ := hashFor(alg)
		if !ecdsa.Verify(k, digest(h, data), r, s) {
			return ErrBadSignature
		}
		return nil
	case AlgED25519:
		if len(pub) != ed25519.PublicKeySize {
			return ErrBadKey
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), data, signature) {
			return ErrBadSignature
		}
		return nil
	default:
		return fmt.Errorf("%w %d", ErrUnsupportedAlgorithm, alg)
	}
}

// ParseRSAKey decodes an RFC 3110 RSA public key.
func ParseRSAKey(pub []byte) (*rsa.PublicKey, error) {
	if len(pub) < 3 {
		return nil, ErrBadKey
	}
	elen := int(pub[0])
	off := 1
	if elen == 0 {
		elen = int(binary.BigEndian.Uint16(pub[1:]))
		off = 3
	}
	if elen == 0 || elen > 4 || off+elen >= len(pub) {
		return nil, ErrBadKey
	}
	e := 0
	for _, b := range pub[off : off+elen] {
		e = e<<8 | int(b)
	}
	if e < 3 {
		return nil, ErrBadKey
	}
	n := new(big.Int).SetBytes(pub[off+elen:])
	if n.BitLen() < 512 {
		return nil, ErrBadKey
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// Supported reports whether Verify can handle algorithm alg.
func Supported(alg uint8) bool {
	switch alg {
	case AlgRSASHA1, AlgRSASHA1NSEC3SHA1, AlgRSASHA256, AlgRSASHA512,
		AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgED25519:
		return true
	}
	return false
}

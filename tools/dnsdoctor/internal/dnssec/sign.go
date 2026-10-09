package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

// PublicKeyBytes encodes a public key in DNSKEY wire format.
// It is used to build test fixtures and lab zones; dnsdoctor itself never
// signs anything at runtime.
func PublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return append([]byte(nil), k...), nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		k.X.FillBytes(out[:size])
		k.Y.FillBytes(out[size:])
		return out, nil
	case *rsa.PublicKey:
		e := big.NewInt(int64(k.E)).Bytes()
		var out []byte
		if len(e) < 256 {
			out = append(out, byte(len(e)))
		} else {
			out = append(out, 0)
			out = binary.BigEndian.AppendUint16(out, uint16(len(e)))
		}
		out = append(out, e...)
		return append(out, k.N.Bytes()...), nil
	}
	return nil, errors.New("dnssec: unsupported key type")
}

// Sign fills in sig.Signature over rrset using signer. sig must already
// carry every other field (type covered, algorithm, labels, TTL, validity,
// key tag, signer name). Intended for tests and lab tooling.
func Sign(rrset []dnswire.RR, sig *dnswire.RRSIG, signer crypto.Signer) error {
	data, err := SignedData(rrset, sig)
	if err != nil {
		return err
	}
	switch sig.Algorithm {
	case AlgED25519:
		s, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
		if err != nil {
			return err
		}
		sig.Signature = s
		return nil
	case AlgECDSAP256SHA256, AlgECDSAP384SHA384:
		k, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("dnssec: ECDSA algorithm requires *ecdsa.PrivateKey")
		}
		h, _ := hashFor(sig.Algorithm)
		r, s, err := ecdsa.Sign(rand.Reader, k, digest(h, data))
		if err != nil {
			return err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		sig.Signature = out
		return nil
	case AlgRSASHA1, AlgRSASHA1NSEC3SHA1, AlgRSASHA256, AlgRSASHA512:
		h, _ := hashFor(sig.Algorithm)
		s, err := signer.Sign(rand.Reader, digest(h, data), h)
		if err != nil {
			return err
		}
		sig.Signature = s
		return nil
	}
	return ErrUnsupportedAlgorithm
}

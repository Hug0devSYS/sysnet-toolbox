// Package ipmath implements exact address arithmetic for IPv4 and IPv6:
// 128-bit integers, inclusive address ranges, range/CIDR conversion, exact
// and lossy aggregation, and address-space subtraction.
package ipmath

import (
	"fmt"
	"math/big"
	"math/bits"
	"strings"
)

// U128 is an unsigned 128-bit integer. IPv4 addresses use the low 32 bits.
type U128 struct{ Hi, Lo uint64 }

// MaxU128 is 2^128 - 1.
var MaxU128 = U128{^uint64(0), ^uint64(0)}

// FromUint64 returns v as a U128.
func FromUint64(v uint64) U128 { return U128{0, v} }

// IsZero reports whether u == 0.
func (u U128) IsZero() bool { return u.Hi == 0 && u.Lo == 0 }

// Cmp returns -1, 0 or +1.
func (u U128) Cmp(v U128) int {
	switch {
	case u.Hi < v.Hi:
		return -1
	case u.Hi > v.Hi:
		return 1
	case u.Lo < v.Lo:
		return -1
	case u.Lo > v.Lo:
		return 1
	}
	return 0
}

// Add returns u+v and whether the addition overflowed.
func (u U128) Add(v U128) (U128, bool) {
	lo, c := bits.Add64(u.Lo, v.Lo, 0)
	hi, c2 := bits.Add64(u.Hi, v.Hi, c)
	return U128{hi, lo}, c2 != 0
}

// Sub returns u-v and whether it borrowed (u < v).
func (u U128) Sub(v U128) (U128, bool) {
	lo, b := bits.Sub64(u.Lo, v.Lo, 0)
	hi, b2 := bits.Sub64(u.Hi, v.Hi, b)
	return U128{hi, lo}, b2 != 0
}

// SatAdd returns u+v, saturating at MaxU128.
func (u U128) SatAdd(v U128) U128 {
	s, o := u.Add(v)
	if o {
		return MaxU128
	}
	return s
}

// Inc returns u+1 and whether it overflowed.
func (u U128) Inc() (U128, bool) { return u.Add(U128{0, 1}) }

// And, Or and Not are bitwise operations.
func (u U128) And(v U128) U128 { return U128{u.Hi & v.Hi, u.Lo & v.Lo} }

// Or returns u | v.
func (u U128) Or(v U128) U128 { return U128{u.Hi | v.Hi, u.Lo | v.Lo} }

// Not returns ^u.
func (u U128) Not() U128 { return U128{^u.Hi, ^u.Lo} }

// Xor returns u ^ v.
func (u U128) Xor(v U128) U128 { return U128{u.Hi ^ v.Hi, u.Lo ^ v.Lo} }

// TrailingZeros returns the number of trailing zero bits (128 for zero).
func (u U128) TrailingZeros() int {
	if u.Lo != 0 {
		return bits.TrailingZeros64(u.Lo)
	}
	if u.Hi != 0 {
		return 64 + bits.TrailingZeros64(u.Hi)
	}
	return 128
}

// LeadingZeros returns the number of leading zero bits (128 for zero).
func (u U128) LeadingZeros() int {
	if u.Hi != 0 {
		return bits.LeadingZeros64(u.Hi)
	}
	return 64 + bits.LeadingZeros64(u.Lo)
}

// BitLen returns the minimum number of bits needed to represent u.
func (u U128) BitLen() int { return 128 - u.LeadingZeros() }

// LowMask returns 2^n - 1 (n bits set), for 0 <= n <= 128.
func LowMask(n int) U128 {
	switch {
	case n <= 0:
		return U128{}
	case n >= 128:
		return MaxU128
	case n >= 64:
		return U128{(uint64(1) << (n - 64)) - 1, ^uint64(0)}
	default:
		return U128{0, (uint64(1) << n) - 1}
	}
}

// Pow2 returns 2^n, saturating at MaxU128 for n >= 128.
func Pow2(n int) U128 {
	switch {
	case n < 0:
		return U128{}
	case n >= 128:
		return MaxU128
	case n >= 64:
		return U128{uint64(1) << (n - 64), 0}
	default:
		return U128{0, uint64(1) << n}
	}
}

// Big returns u as a *big.Int.
func (u U128) Big() *big.Int {
	b := new(big.Int).SetUint64(u.Hi)
	b.Lsh(b, 64)
	return b.Or(b, new(big.Int).SetUint64(u.Lo))
}

// String returns the decimal representation of u.
func (u U128) String() string {
	if u.Hi == 0 {
		return big.NewInt(0).SetUint64(u.Lo).String()
	}
	return u.Big().String()
}

// MarshalJSON encodes small values as JSON numbers and values that do not
// fit a float64 exactly (> 2^53) as decimal strings.
func (u U128) MarshalJSON() ([]byte, error) {
	if u.Hi == 0 && u.Lo <= 1<<53 {
		return []byte(u.String()), nil
	}
	return []byte(`"` + u.String() + `"`), nil
}

// UnmarshalJSON accepts a JSON number or a decimal string.
func (u *U128) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 128 {
		return fmt.Errorf("invalid 128-bit unsigned integer %s", b)
	}
	lo := new(big.Int).And(n, new(big.Int).SetUint64(^uint64(0)))
	u.Lo = lo.Uint64()
	u.Hi = new(big.Int).Rsh(n, 64).Uint64()
	return nil
}

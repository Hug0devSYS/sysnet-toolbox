// Package dnswire implements the subset of the DNS wire format (RFC 1035,
// RFC 4034, RFC 6891) that dnsdoctor needs: message packing/unpacking with
// name compression, and canonical RDATA encoding for DNSSEC validation.
//
// Domain names are represented as presentation-format strings, fully
// qualified with a trailing dot. Label bytes that are not safe to print
// ('.', '\\', non-printable ASCII) are escaped as "\." / "\\" / "\DDD".
package dnswire

import (
	"errors"
	"fmt"
	"strings"
)

// Limits from RFC 1035 section 2.3.4.
const (
	maxLabelLen = 63
	maxNameLen  = 255
)

// Errors returned while handling names.
var (
	ErrLabelTooLong = errors.New("dnswire: label exceeds 63 octets")
	ErrNameTooLong  = errors.New("dnswire: name exceeds 255 octets")
	ErrEmptyLabel   = errors.New("dnswire: empty label")
	ErrBadEscape    = errors.New("dnswire: invalid escape sequence")
)

// Fqdn returns name with a trailing dot. The empty string becomes the root.
func Fqdn(name string) string {
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	// The final dot is a separator only if it is preceded by an even number
	// of backslashes; "foo\." ends with a literal dot inside the label.
	n := 0
	for i := len(name) - 2; i >= 0 && name[i] == '\\'; i-- {
		n++
	}
	if n%2 == 1 {
		return name + "."
	}
	return name
}

// CanonicalName returns the RFC 4034 section 6.2 canonical form of name
// (fully qualified, US-ASCII letters lowercased).
func CanonicalName(name string) string {
	return strings.ToLower(Fqdn(name))
}

// EqualNames reports whether two names are equal, ignoring ASCII case.
func EqualNames(a, b string) bool {
	return strings.EqualFold(Fqdn(a), Fqdn(b))
}

// labelsOf splits a presentation-format name into raw (unescaped) labels.
// The root name yields an empty slice.
func labelsOf(name string) ([][]byte, error) {
	name = Fqdn(name)
	if name == "." {
		return nil, nil
	}
	var labels [][]byte
	var cur []byte
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch c {
		case '\\':
			if i+1 >= len(name) {
				return nil, ErrBadEscape
			}
			n := name[i+1]
			if n >= '0' && n <= '9' {
				if i+3 >= len(name) {
					return nil, ErrBadEscape
				}
				d := name[i+1 : i+4]
				v := 0
				for _, ch := range []byte(d) {
					if ch < '0' || ch > '9' {
						return nil, ErrBadEscape
					}
					v = v*10 + int(ch-'0')
				}
				if v > 255 {
					return nil, ErrBadEscape
				}
				cur = append(cur, byte(v))
				i += 3
			} else {
				cur = append(cur, n)
				i++
			}
		case '.':
			if len(cur) == 0 {
				return nil, ErrEmptyLabel
			}
			if len(cur) > maxLabelLen {
				return nil, ErrLabelTooLong
			}
			labels = append(labels, cur)
			cur = nil
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) != 0 {
		// Fqdn guarantees a trailing separator; reaching here means the
		// last dot was escaped, which Fqdn already handled.
		return nil, fmt.Errorf("dnswire: unterminated name %q", name)
	}
	return labels, nil
}

// escapeLabel converts a raw label into presentation format.
func escapeLabel(l []byte) string {
	var b strings.Builder
	for _, c := range l {
		switch {
		case c == '.' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x21 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// CountLabels returns the number of labels in name, excluding the root
// label and, per RFC 4034 section 3.1.3, a leading "*" wildcard label.
func CountLabels(name string) int {
	labels, err := labelsOf(name)
	if err != nil {
		return 0
	}
	n := len(labels)
	if n > 0 && len(labels[0]) == 1 && labels[0][0] == '*' {
		n--
	}
	return n
}

// Parent returns the name with its leftmost label removed. Parent(".") is ".".
func Parent(name string) string {
	labels, err := labelsOf(name)
	if err != nil || len(labels) <= 1 {
		return "."
	}
	return joinLabels(labels[1:])
}

// LastLabels returns the rightmost n labels of name as a name.
func LastLabels(name string, n int) string {
	labels, err := labelsOf(name)
	if err != nil || n <= 0 {
		return "."
	}
	if n >= len(labels) {
		return joinLabels(labels)
	}
	return joinLabels(labels[len(labels)-n:])
}

func joinLabels(labels [][]byte) string {
	if len(labels) == 0 {
		return "."
	}
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = escapeLabel(l)
	}
	return strings.Join(parts, ".") + "."
}

// IsSubdomain reports whether child is equal to or below parent.
func IsSubdomain(child, parent string) bool {
	c := CanonicalName(child)
	p := CanonicalName(parent)
	if p == "." {
		return true
	}
	if c == p {
		return true
	}
	return strings.HasSuffix(c, "."+p)
}

// ValidateName checks that name is syntactically valid on the wire.
func ValidateName(name string) error {
	_, err := nameWire(name, false)
	return err
}

// nameWire encodes a name without compression. If canonical is true the
// name is lowercased first.
func nameWire(name string, canonical bool) ([]byte, error) {
	if canonical {
		name = CanonicalName(name)
	}
	labels, err := labelsOf(name)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	if len(out) > maxNameLen {
		return nil, ErrNameTooLong
	}
	return out, nil
}

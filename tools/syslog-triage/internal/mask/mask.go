// Package mask tokenizes log messages and replaces obviously variable
// tokens (addresses, numbers, identifiers) with typed placeholders before
// clustering, so that "port 22" and "port 2222" fall into the same pattern
// while interface names, keywords and paths stay intact.
package mask

import (
	"net/netip"
	"strings"
)

// Placeholders produced by Tokens. Wildcard is the Drain parameter token.
const (
	IP       = "<IP>"
	CIDR     = "<CIDR>"
	MAC      = "<MAC>"
	UUID     = "<UUID>"
	HEX      = "<HEX>"
	NUM      = "<NUM>"
	Wildcard = "<*>"
)

// IsPlaceholder reports whether tok is (or contains) a placeholder.
func IsPlaceholder(tok string) bool {
	return strings.Contains(tok, "<") && (strings.Contains(tok, IP) || strings.Contains(tok, NUM) ||
		strings.Contains(tok, HEX) || strings.Contains(tok, MAC) || strings.Contains(tok, UUID) ||
		strings.Contains(tok, CIDR) || strings.Contains(tok, Wildcard))
}

// Tokens splits msg on white space and masks variable tokens. At most
// maxTokens tokens are returned (0 = no limit); the remainder of a longer
// message is folded into a final Wildcard token.
func Tokens(msg string, maxTokens int) []string {
	fields := strings.Fields(msg)
	if maxTokens > 0 && len(fields) > maxTokens {
		fields = append(fields[:maxTokens-1], Wildcard)
	}
	for i, f := range fields {
		fields[i] = Token(f)
	}
	return fields
}

const openPunct = "([{<\"'`#"
const closePunct = ")]}>\"'`,;:.!?"

// Token masks a single white-space-free token, keeping surrounding
// punctuation and the key of key=value pairs.
func Token(tok string) string {
	if len(tok) < 14 && !hasDigit(tok) {
		return tok
	}
	// key=value / key:value with a short alphabetic key.
	if i := strings.IndexByte(tok, '='); i > 0 && i < len(tok)-1 {
		return tok[:i+1] + Token(tok[i+1:])
	}
	if tok[0] == '[' {
		if _, err := netip.ParseAddrPort(strings.TrimRight(tok, closePunct[1:])); err == nil {
			return IP
		}
	}
	start, end := 0, len(tok)
	for start < end && strings.IndexByte(openPunct, tok[start]) >= 0 {
		start++
	}
	for end > start && strings.IndexByte(closePunct, tok[end-1]) >= 0 {
		end--
	}
	core := tok[start:end]
	if core == "" {
		return tok
	}
	if strings.IndexByte(core, ',') > 0 && strings.ContainsAny(core, ".:") {
		// Lists of addresses: "192.0.2.1,192.0.2.2".
		parts := strings.Split(core, ",")
		allNum := true
		for j, p := range parts {
			if m := classify(p); m != "" {
				parts[j] = m
				allNum = allNum && m == NUM
			} else {
				allNum = false
			}
		}
		if !allNum {
			return tok[:start] + strings.Join(parts, ",") + tok[end:]
		}
	}
	if m := classify(core); m != "" {
		return tok[:start] + m + tok[end:]
	}
	// "func:123", "addr#port", "a,b": masks the numeric parts. '/' is not
	// a separator: interface names such as Gi1/0/1 must stay intact.
	for _, sep := range []byte{':', ',', '#'} {
		if strings.IndexByte(core, sep) > 0 {
			parts := strings.Split(core, string(sep))
			changed := false
			for j, p := range parts {
				if m := classify(p); m != "" {
					parts[j], changed = m, true
				}
			}
			if changed {
				return tok[:start] + strings.Join(parts, string(sep)) + tok[end:]
			}
		}
	}
	return tok
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// classify returns the placeholder for core or "" to keep it.
func classify(core string) string {
	if isMAC(core) {
		return MAC
	}
	if !hasDigit(core) {
		return ""
	}
	if strings.ContainsAny(core, ".:") {
		if isIPLike(core) {
			return IP
		}
		if _, err := netip.ParsePrefix(core); err == nil {
			return CIDR
		}
		// Cisco ASA style "address/port".
		if i := strings.LastIndexByte(core, '/'); i > 0 && isIPLike(core[:i]) && isNumber(core[i+1:]) {
			return IP + "/" + NUM
		}
	}
	if isNumber(core) {
		return NUM
	}
	if strings.IndexByte(core, '-') > 0 {
		if isUUID(core) {
			return UUID
		}
	}
	if len(core) > 2 && core[0] == '0' && (core[1] == 'x' || core[1] == 'X') && allHex(core[2:]) {
		return HEX
	}
	if len(core) >= 8 && allHex(core) && hasHexLetter(core) {
		return HEX
	}
	if isNumberWithUnit(core) {
		return NUM
	}
	return ""
}

func allHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

func hasHexLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if c >= 'a' && c <= 'f' {
			return true
		}
	}
	return false
}

// isNumber accepts integers, decimals, signed values, times (12:34:56),
// dates (2026-11-13, 13/11/2026) and similar digit groups.
func isNumber(s string) bool {
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && strings.IndexByte(".,:-_/+", c) < 0 {
			return false
		}
	}
	return true
}

// isNumberWithUnit accepts "250ms", "1.5s", "10GB", "1000Mbps", "95%".
func isNumberWithUnit(s string) bool {
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	if i == 0 || i == len(s) {
		return false
	}
	unit := s[i:]
	if len(unit) > 4 {
		return false
	}
	for j := 0; j < len(unit); j++ {
		c := unit[j]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '%') {
			return false
		}
	}
	return true
}

func isIPLike(s string) bool {
	if strings.HasPrefix(s, "[") {
		s = strings.TrimPrefix(s, "[")
		if i := strings.Index(s, "]"); i >= 0 {
			s = s[:i]
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddrPort(s); err == nil {
		return true
	}
	// IPv4 with port "1.2.3.4:5678" is covered above; IPv4 with a dotted
	// port (BSD netstat style "1.2.3.4.5678").
	if strings.Count(s, ".") == 4 && !strings.Contains(s, ":") {
		if i := strings.LastIndexByte(s, '.'); i > 0 {
			if _, err := netip.ParseAddr(s[:i]); err == nil && isNumber(s[i+1:]) {
				return true
			}
		}
	}
	return false
}

func isMAC(s string) bool {
	switch len(s) {
	case 17: // aa:bb:cc:dd:ee:ff or aa-bb-...
		sep := s[2]
		if sep != ':' && sep != '-' {
			return false
		}
		for i := 0; i < 17; i++ {
			if i%3 == 2 {
				if s[i] != sep {
					return false
				}
			} else if !isHex(s[i]) {
				return false
			}
		}
		return true
	case 14: // aabb.ccdd.eeff (Cisco)
		for i := 0; i < 14; i++ {
			if i%5 == 4 {
				if s[i] != '.' {
					return false
				}
			} else if !isHex(s[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	return true
}

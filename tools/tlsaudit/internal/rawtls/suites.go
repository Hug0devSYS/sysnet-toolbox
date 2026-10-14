package rawtls

import (
	"sort"
	"strings"
)

// Grade classifies a cipher suite.
type Grade string

// Cipher suite grades, from worst to best.
const (
	// GradeInsecure suites are broken: NULL encryption, export-grade,
	// anonymous key exchange, RC4, single DES, RC2 or MD5 MACs.
	GradeInsecure Grade = "insecure"
	// GradeWeak suites are deprecated: 3DES/IDEA (64-bit blocks, SWEET32)
	// and key exchanges without forward secrecy (static RSA/DH/ECDH).
	GradeWeak Grade = "weak"
	// GradeLegacy suites are acceptable for compatibility only: forward
	// secret but CBC mode (MAC-then-encrypt, Lucky13-class issues).
	GradeLegacy Grade = "legacy"
	// GradeGood suites are forward secret AEAD suites (GCM, CCM, ChaCha20).
	GradeGood Grade = "good"
)

// Suite describes an IANA TLS cipher suite.
type Suite struct {
	ID   uint16
	Name string
}

// suiteNames lists the TLS 1.0–1.2 cipher suites tlsaudit offers during
// enumeration. It deliberately includes broken suites so that servers still
// accepting them are detected. PSK/SRP/Kerberos suites are omitted because
// they require out-of-band credentials and are never negotiated by an
// unauthenticated scanner.
var suiteNames = map[uint16]string{
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0042: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0043: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
	0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0x00BA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00BE: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00C0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00C4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC09C: "TLS_RSA_WITH_AES_128_CCM",
	0xC09D: "TLS_RSA_WITH_AES_256_CCM",
	0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
	0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
	0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

// Signalling cipher suite values.
const (
	scsvRenegotiation uint16 = 0x00FF
	scsvFallback      uint16 = 0x5600
)

// AllSuites returns every suite tlsaudit can offer, strongest first (servers
// that honour the client's order then pick a good suite first).
func AllSuites() []uint16 {
	ids := make([]uint16, 0, len(suiteNames))
	for id := range suiteNames {
		ids = append(ids, id)
	}
	rank := map[Grade]int{GradeGood: 0, GradeLegacy: 1, GradeWeak: 2, GradeInsecure: 3}
	sort.Slice(ids, func(i, j int) bool {
		gi, gj := rank[Classify(ids[i]).Grade], rank[Classify(ids[j]).Grade]
		if gi != gj {
			return gi < gj
		}
		return ids[i] > ids[j]
	})
	return ids
}

// SuiteName returns the IANA name of a cipher suite, or a hex placeholder.
func SuiteName(id uint16) string {
	if n, ok := suiteNames[id]; ok {
		return n
	}
	if n, ok := tls13Names[id]; ok {
		return n
	}
	return "UNKNOWN_0x" + hex16(id)
}

var tls13Names = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
}

func hex16(v uint16) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[v>>12&0xF], digits[v>>8&0xF], digits[v>>4&0xF], digits[v&0xF]})
}

// Class is the analysis of one cipher suite.
type Class struct {
	Grade         Grade
	KeyExchange   string // RSA, DHE_RSA, ECDHE_ECDSA, DH_anon, ...
	ForwardSecret bool
	Reason        string // why the suite is not "good"
}

// Classify grades a cipher suite from its IANA name.
func Classify(id uint16) Class {
	if _, ok := tls13Names[id]; ok {
		return Class{Grade: GradeGood, KeyExchange: "TLS13", ForwardSecret: true}
	}
	name, ok := suiteNames[id]
	if !ok {
		return Class{Grade: GradeWeak, KeyExchange: "unknown", Reason: "unknown cipher suite"}
	}
	kex := strings.TrimPrefix(name, "TLS_")
	enc := ""
	if i := strings.Index(kex, "_WITH_"); i >= 0 {
		kex, enc = kex[:i], kex[i+len("_WITH_"):]
	}
	c := Class{KeyExchange: kex, ForwardSecret: strings.HasPrefix(kex, "DHE_") || strings.HasPrefix(kex, "ECDHE_")}
	switch {
	case strings.HasPrefix(enc, "NULL"):
		c.Grade, c.Reason = GradeInsecure, "no encryption (NULL cipher)"
	case strings.Contains(kex, "EXPORT"):
		c.Grade, c.Reason = GradeInsecure, "export-grade cryptography (FREAK/Logjam)"
	case strings.Contains(kex, "anon"):
		c.Grade, c.Reason = GradeInsecure, "anonymous key exchange (no server authentication)"
	case strings.HasPrefix(enc, "RC4"):
		c.Grade, c.Reason = GradeInsecure, "RC4 stream cipher (RFC 7465)"
	case strings.HasPrefix(enc, "DES_") || strings.HasPrefix(enc, "DES40"):
		c.Grade, c.Reason = GradeInsecure, "single DES (56-bit key)"
	case strings.HasPrefix(enc, "RC2"):
		c.Grade, c.Reason = GradeInsecure, "RC2 cipher"
	case strings.HasSuffix(enc, "_MD5"):
		c.Grade, c.Reason = GradeInsecure, "MD5 MAC"
	case strings.HasPrefix(enc, "3DES") || strings.HasPrefix(enc, "IDEA"):
		c.Grade, c.Reason = GradeWeak, "64-bit block cipher (SWEET32)"
	case !c.ForwardSecret:
		c.Grade, c.Reason = GradeWeak, "no forward secrecy (static "+strings.SplitN(kex, "_", 2)[0]+" key exchange)"
	case strings.Contains(enc, "_CBC_"):
		c.Grade, c.Reason = GradeLegacy, "CBC mode (MAC-then-encrypt)"
	default:
		c.Grade = GradeGood
	}
	return c
}

// needsServerKeyExchange reports whether the suite carries ephemeral
// key-exchange parameters worth parsing.
func needsServerKeyExchange(id uint16) (dhe, ecdhe bool) {
	k := Classify(id).KeyExchange
	return strings.HasPrefix(k, "DHE_") || k == "DH_anon", strings.HasPrefix(k, "ECDHE_") || k == "ECDH_anon"
}

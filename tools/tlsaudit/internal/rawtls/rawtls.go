// Package rawtls sends hand-crafted SSLv3/TLS 1.0–1.2 ClientHello messages
// and parses the server's first flight (ServerHello, Certificate,
// CertificateStatus, ServerKeyExchange) without completing the handshake.
//
// This lets tlsaudit enumerate protocol versions and cipher suites that Go's
// crypto/tls refuses to negotiate (SSLv3, export, NULL, anonymous, DHE, ...)
// and inspect ephemeral key-exchange parameters. No key material is ever
// generated and no application data is exchanged.
package rawtls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// Protocol versions.
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// VersionName returns a human-readable protocol name.
func VersionName(v uint16) string {
	switch v {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS1.0"
	case VersionTLS11:
		return "TLS1.1"
	case VersionTLS12:
		return "TLS1.2"
	case VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// TLS record content types, handshake types and alerts used here.
const (
	recordAlert     = 21
	recordHandshake = 22

	hsClientHello       = 1
	hsServerHello       = 2
	hsCertificate       = 11
	hsServerKeyExchange = 12
	hsServerHelloDone   = 14
	hsCertificateStatus = 22

	// AlertInappropriateFallback is sent by servers honouring TLS_FALLBACK_SCSV.
	AlertInappropriateFallback = 86
)

// Named groups offered in supported_groups. Finite-field (ffdhe) groups are
// intentionally NOT offered: RFC 7919 servers would then refuse legacy DHE
// suites and hide weak DH parameters from the audit.
var offeredGroups = []uint16{29, 23, 24, 25} // x25519, secp256r1, secp384r1, secp521r1

// GroupName returns the name of a TLS named group.
func GroupName(id uint16) string {
	switch id {
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25:
		return "secp521r1"
	case 29:
		return "x25519"
	case 30:
		return "x448"
	}
	return fmt.Sprintf("group-%d", id)
}

var offeredSigAlgs = []uint16{
	0x0403, 0x0503, 0x0603, // ecdsa_secp256r1_sha256 ... secp521r1_sha512
	0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha256 ... sha512
	0x0807,                 // ed25519
	0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha256 ... sha512
	0x0203, 0x0201, // ecdsa_sha1, rsa_pkcs1_sha1
	0x0402, 0x0202, // dsa_sha256, dsa_sha1 (for DHE_DSS suites)
}

// Hello describes the ClientHello to send.
type Hello struct {
	Version    uint16   // legacy_version (SSLv3 .. TLS 1.2)
	Ciphers    []uint16 // offered cipher suites
	ServerName string   // SNI; ignored if empty or an IP literal
	// FallbackSCSV appends TLS_FALLBACK_SCSV (RFC 7507).
	FallbackSCSV bool
}

// Marshal encodes the ClientHello as one TLS record. random must be 32 bytes
// (nil means crypto/rand).
func (h Hello) Marshal(random []byte) ([]byte, error) {
	if h.Version < VersionSSL30 || h.Version > VersionTLS12 {
		return nil, fmt.Errorf("rawtls: unsupported hello version %s", VersionName(h.Version))
	}
	if len(h.Ciphers) == 0 {
		return nil, errors.New("rawtls: no cipher suites to offer")
	}
	if random == nil {
		random = make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
	}
	if len(random) != 32 {
		return nil, errors.New("rawtls: random must be 32 bytes")
	}

	var body []byte
	body = binary.BigEndian.AppendUint16(body, h.Version)
	body = append(body, random...)
	body = append(body, 0) // empty session id

	suites := append([]uint16(nil), h.Ciphers...)
	if h.Version == VersionSSL30 {
		suites = append(suites, scsvRenegotiation)
	}
	if h.FallbackSCSV {
		suites = append(suites, scsvFallback)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(suites)))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // compression: null only

	if h.Version >= VersionTLS10 {
		var ext []byte
		if h.ServerName != "" {
			if _, err := netip.ParseAddr(h.ServerName); err != nil {
				name := []byte(h.ServerName)
				var sni []byte
				sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)+3))
				sni = append(sni, 0) // host_name
				sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
				sni = append(sni, name...)
				ext = appendExt(ext, 0, sni)
			}
		}
		groups := binary.BigEndian.AppendUint16(nil, uint16(2*len(offeredGroups)))
		for _, g := range offeredGroups {
			groups = binary.BigEndian.AppendUint16(groups, g)
		}
		ext = appendExt(ext, 10, groups)
		ext = appendExt(ext, 11, []byte{1, 0}) // ec_point_formats: uncompressed
		if h.Version >= VersionTLS12 {
			sa := binary.BigEndian.AppendUint16(nil, uint16(2*len(offeredSigAlgs)))
			for _, s := range offeredSigAlgs {
				sa = binary.BigEndian.AppendUint16(sa, s)
			}
			ext = appendExt(ext, 13, sa)
		}
		ext = appendExt(ext, 5, []byte{1, 0, 0, 0, 0}) // status_request (OCSP)
		ext = appendExt(ext, 0xff01, []byte{0})        // renegotiation_info (empty)

		// RFC 7685 padding: some load balancers hang on ClientHellos whose
		// handshake length is between 256 and 511 bytes.
		hsLen := 4 + len(body) + 2 + len(ext)
		if hsLen >= 256 && hsLen < 512 {
			pad := 512 - hsLen - 4
			if pad < 0 {
				pad = 0
			}
			ext = appendExt(ext, 21, make([]byte, pad))
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
		body = append(body, ext...)
	}

	hs := []byte{hsClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	if len(hs) > 1<<14 {
		return nil, errors.New("rawtls: ClientHello too large")
	}
	recVer := VersionTLS10
	if h.Version == VersionSSL30 {
		recVer = VersionSSL30
	}
	rec := []byte{recordHandshake, byte(recVer >> 8), byte(recVer), byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...), nil
}

func appendExt(b []byte, typ uint16, data []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// Result is what the server answered to one ClientHello.
type Result struct {
	// Accepted is true when the server answered with a ServerHello.
	Accepted bool
	// Version and Cipher are the values selected in the ServerHello.
	Version uint16
	Cipher  uint16
	// SecureRenegotiation is true when the ServerHello carried the
	// renegotiation_info extension (RFC 5746).
	SecureRenegotiation bool
	// Alert is the alert description when the server rejected the hello
	// with an alert (AlertReceived is then true).
	AlertReceived bool
	Alert         uint8
	// Closed is true when the server closed the connection without a
	// ServerHello or alert (a common way to reject SSLv3 or unknown suites).
	Closed bool
	// Certificates is the DER chain from the Certificate message, if read.
	Certificates [][]byte
	// OCSPStaple is the DER OCSP response from CertificateStatus, if any.
	OCSPStaple []byte
	// DHBits is the size of the DHE prime (DHE suites only).
	DHBits int
	// Group is the named curve of an ECDHE key exchange (ECDHE suites only).
	Group uint16
}

// maxFlight bounds the bytes read from a server's first flight.
const maxFlight = 256 << 10

// Probe writes the ClientHello to conn and reads the server's first flight
// until ServerHelloDone, an alert, connection close or the deadline. conn's
// deadline must be set by the caller. Network errors other than a clean
// close or reset are returned as errors (the result is then indeterminate).
func Probe(conn net.Conn, h Hello) (*Result, error) {
	msg, err := h.Marshal(nil)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		if isClosed(err) {
			return &Result{Closed: true}, nil
		}
		return nil, err
	}
	return ReadFlight(conn)
}

// ReadFlight parses a server's first flight from r.
func ReadFlight(r io.Reader) (*Result, error) {
	res := &Result{}
	var hsBuf []byte
	read := 0
	hdr := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if res.Accepted && isTimeoutOrClosed(err) {
				return res, nil // partial flight, ServerHello already seen
			}
			if isClosed(err) {
				res.Closed = true
				return res, nil
			}
			return nil, err
		}
		typ, n := hdr[0], int(binary.BigEndian.Uint16(hdr[3:5]))
		if hdr[1] != 3 || n > 1<<14+2048 {
			if !res.Accepted && hdr[0]&0x80 != 0 {
				// SSLv2-format record: treat as a rejection of our hello.
				res.Closed = true
				return res, nil
			}
			return nil, fmt.Errorf("rawtls: malformed TLS record header % x", hdr)
		}
		read += 5 + n
		if read > maxFlight {
			return res, nil
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			if res.Accepted {
				return res, nil
			}
			if isClosed(err) {
				res.Closed = true
				return res, nil
			}
			return nil, err
		}
		switch typ {
		case recordAlert:
			if len(payload) >= 2 {
				res.AlertReceived = true
				res.Alert = payload[1]
			}
			return res, nil
		case recordHandshake:
			hsBuf = append(hsBuf, payload...)
			done, err := res.consume(&hsBuf)
			if err != nil {
				return nil, err
			}
			if done {
				return res, nil
			}
		default:
			// ChangeCipherSpec or application data in a first flight:
			// nothing more we can parse in clear text.
			if res.Accepted {
				return res, nil
			}
			return nil, fmt.Errorf("rawtls: unexpected record type %d before ServerHello", typ)
		}
	}
}

// consume parses complete handshake messages from buf. It returns done=true
// once there is nothing more of interest to read.
func (res *Result) consume(buf *[]byte) (bool, error) {
	for len(*buf) >= 4 {
		b := *buf
		typ := b[0]
		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if n > maxFlight {
			return false, errors.New("rawtls: oversized handshake message")
		}
		if len(b) < 4+n {
			return false, nil // wait for more records
		}
		body := b[4 : 4+n]
		*buf = b[4+n:]
		switch typ {
		case hsServerHello:
			if err := res.parseServerHello(body); err != nil {
				return false, err
			}
		case hsCertificate:
			res.Certificates = parseCertificates(body)
		case hsCertificateStatus:
			// status_type(1)=ocsp, then opaque<1..2^24-1>
			if len(body) >= 4 && body[0] == 1 {
				l := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
				if 4+l <= len(body) {
					res.OCSPStaple = append([]byte(nil), body[4:4+l]...)
				}
			}
		case hsServerKeyExchange:
			res.parseServerKeyExchange(body)
		case hsServerHelloDone:
			return true, nil
		}
		if !res.Accepted {
			return false, errors.New("rawtls: handshake message before ServerHello")
		}
	}
	return false, nil
}

func (res *Result) parseServerHello(b []byte) error {
	if len(b) < 2+32+1 {
		return errors.New("rawtls: short ServerHello")
	}
	res.Version = binary.BigEndian.Uint16(b)
	p := 2 + 32
	sid := int(b[p])
	p += 1 + sid
	if len(b) < p+3 {
		return errors.New("rawtls: short ServerHello")
	}
	res.Cipher = binary.BigEndian.Uint16(b[p:])
	p += 3 // cipher + compression
	res.Accepted = true
	if len(b) < p+2 {
		return nil // no extensions
	}
	extLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	end := min(p+extLen, len(b))
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4 + l
		if typ == 0xff01 {
			res.SecureRenegotiation = true
		}
	}
	return nil
}

func parseCertificates(b []byte) [][]byte {
	if len(b) < 3 {
		return nil
	}
	total := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	b = b[3:]
	if total < len(b) {
		b = b[:total]
	}
	var certs [][]byte
	for len(b) >= 3 {
		l := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 3+l {
			break
		}
		certs = append(certs, append([]byte(nil), b[3:3+l]...))
		b = b[3+l:]
	}
	return certs
}

func (res *Result) parseServerKeyExchange(b []byte) {
	dhe, ecdhe := needsServerKeyExchange(res.Cipher)
	switch {
	case dhe:
		// ServerDHParams: dh_p<1..2^16-1>, dh_g, dh_Ys
		if len(b) < 2 {
			return
		}
		l := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+l || l == 0 {
			return
		}
		p := b[2 : 2+l]
		for len(p) > 0 && p[0] == 0 {
			p = p[1:]
		}
		if len(p) == 0 {
			return
		}
		bits := (len(p) - 1) * 8
		for top := p[0]; top != 0; top >>= 1 {
			bits++
		}
		res.DHBits = bits
	case ecdhe:
		// ServerECDHParams: curve_type(1) = named_curve(3), namedcurve(2)
		if len(b) >= 3 && b[0] == 3 {
			res.Group = binary.BigEndian.Uint16(b[1:])
		}
	}
}

func isClosed(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && !op.Timeout() {
		// connection reset / broken pipe
		return true
	}
	return false
}

func isTimeoutOrClosed(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return isClosed(err)
}

// Deadline is a helper returning the earlier of now+d and ctxDeadline.
func Deadline(d time.Duration, ctxDeadline time.Time, hasCtx bool) time.Time {
	t := time.Now().Add(d)
	if hasCtx && ctxDeadline.Before(t) {
		return ctxDeadline
	}
	return t
}

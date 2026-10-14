package rawtls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/testpki"
)

func probe(t *testing.T, addr string, h Hello) *Result {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	r, err := Probe(c, h)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return r
}

func TestProbeAgainstGoServer(t *testing.T) {
	pki := testpki.NewPKI(t, testpki.Options{})
	addr := testpki.Serve(t, &tls.Config{
		Certificates: []tls.Certificate{pki.TLSCert(pki.Inter.Cert)},
		MinVersion:   tls.VersionTLS11,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	})

	r := probe(t, addr, Hello{Version: VersionTLS12, Ciphers: AllSuites(), ServerName: "www.example.test"})
	if !r.Accepted || r.Version != VersionTLS12 || r.Cipher != 0xC02B {
		t.Fatalf("TLS1.2: %+v", r)
	}
	if !r.SecureRenegotiation {
		t.Error("secure renegotiation not detected")
	}
	if len(r.Certificates) != 2 {
		t.Fatalf("got %d certificates", len(r.Certificates))
	}
	leaf, err := x509.ParseCertificate(r.Certificates[0])
	if err != nil || leaf.Subject.CommonName != "www.example.test" {
		t.Fatalf("leaf: %v %v", leaf, err)
	}
	if r.Group != 29 {
		t.Errorf("ECDHE group = %d, want x25519", r.Group)
	}

	// TLS 1.1 offered with only AEAD suites: no common suite (GCM needs 1.2).
	r = probe(t, addr, Hello{Version: VersionTLS11, Ciphers: []uint16{0xC02B}})
	if r.Accepted {
		t.Fatalf("TLS1.1 GCM should be rejected: %+v", r)
	}
	if !r.AlertReceived && !r.Closed {
		t.Fatalf("expected alert or close: %+v", r)
	}

	// TLS 1.0 is below the server minimum.
	r = probe(t, addr, Hello{Version: VersionTLS10, Ciphers: AllSuites()})
	if r.Accepted && r.Version == VersionTLS10 {
		t.Fatalf("TLS1.0 accepted: %+v", r)
	}

	// Fallback SCSV: TLS1.1 hello with SCSV to a TLS1.2 server must fail.
	r = probe(t, addr, Hello{Version: VersionTLS11, Ciphers: AllSuites(), FallbackSCSV: true})
	if r.Accepted || !r.AlertReceived || r.Alert != AlertInappropriateFallback {
		t.Fatalf("fallback SCSV not honoured: %+v", r)
	}

	// SSLv3: Go servers just alert/close.
	r = probe(t, addr, Hello{Version: VersionSSL30, Ciphers: AllSuites()})
	if r.Accepted && r.Version == VersionSSL30 {
		t.Fatalf("SSLv3 accepted: %+v", r)
	}
}

func TestMarshalPaddingAndSNI(t *testing.T) {
	random := bytes.Repeat([]byte{1}, 32)
	b, err := Hello{Version: VersionTLS12, Ciphers: AllSuites(), ServerName: "a.example"}.Marshal(random)
	if err != nil {
		t.Fatal(err)
	}
	hsLen := int(binary.BigEndian.Uint16(b[3:5]))
	if hsLen != len(b)-5 || (hsLen >= 256 && hsLen < 512) {
		t.Fatalf("bad length %d", hsLen)
	}
	if !bytes.Contains(b, []byte("a.example")) {
		t.Error("SNI missing")
	}
	small, _ := Hello{Version: VersionTLS10, Ciphers: []uint16{0x002F}, ServerName: "x"}.Marshal(random)
	if l := len(small) - 5; l >= 256 && l < 512 {
		t.Errorf("small hello length %d in the 256..511 range", l)
	}
	ip, _ := Hello{Version: VersionTLS12, Ciphers: []uint16{0x002F}, ServerName: "192.0.2.1"}.Marshal(random)
	if bytes.Contains(ip, []byte("192.0.2.1")) {
		t.Error("IP literal must not be sent as SNI")
	}
	ssl3, _ := Hello{Version: VersionSSL30, Ciphers: []uint16{0x002F}}.Marshal(random)
	if ssl3[1] != 3 || ssl3[2] != 0 {
		t.Errorf("SSLv3 record version %x", ssl3[1:3])
	}
	if _, err := (Hello{Version: VersionTLS13, Ciphers: []uint16{1}}).Marshal(random); err == nil {
		t.Error("TLS1.3 legacy hello should be refused")
	}
	if _, err := (Hello{Version: VersionTLS12}).Marshal(random); err == nil {
		t.Error("empty cipher list should be refused")
	}
}

// flight builds handshake records for a fake server.
func flight(msgs ...[]byte) []byte {
	var hs []byte
	for _, m := range msgs {
		hs = append(hs, m...)
	}
	var out []byte
	// split across two records to exercise reassembly
	half := len(hs) / 2
	for _, part := range [][]byte{hs[:half], hs[half:]} {
		out = append(out, recordHandshake, 3, 3, byte(len(part)>>8), byte(len(part)))
		out = append(out, part...)
	}
	return out
}

func hsMsg(typ byte, body []byte) []byte {
	return append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func serverHello(version, cipher uint16, reneg bool) []byte {
	b := binary.BigEndian.AppendUint16(nil, version)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, cipher)
	b = append(b, 0)
	if reneg {
		b = append(b, 0, 5, 0xff, 0x01, 0, 1, 0)
	}
	return hsMsg(hsServerHello, b)
}

func TestReadFlightDHE(t *testing.T) {
	prime := append([]byte{0x80}, make([]byte, 127)...) // 1024-bit
	ske := binary.BigEndian.AppendUint16(nil, uint16(len(prime)))
	ske = append(ske, prime...)
	ske = append(ske, 0, 1, 2, 0, 1, 7)
	staple := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	cs := append([]byte{1, 0, 0, byte(len(staple))}, staple...)
	cert := []byte{0xde, 0xad}
	certMsg := []byte{0, 0, 5, 0, 0, 2}
	certMsg = append(certMsg, cert...)
	data := flight(serverHello(VersionTLS12, 0x009E, false), hsMsg(hsCertificate, certMsg),
		hsMsg(hsCertificateStatus, cs), hsMsg(hsServerKeyExchange, ske), hsMsg(hsServerHelloDone, nil))
	r, err := ReadFlight(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Accepted || r.Cipher != 0x009E || r.DHBits != 1024 || r.SecureRenegotiation {
		t.Fatalf("%+v", r)
	}
	if len(r.Certificates) != 1 || !bytes.Equal(r.Certificates[0], cert) || !bytes.Equal(r.OCSPStaple, staple) {
		t.Fatalf("certs=%x staple=%x", r.Certificates, r.OCSPStaple)
	}
}

func TestReadFlightRejections(t *testing.T) {
	r, err := ReadFlight(bytes.NewReader([]byte{recordAlert, 3, 1, 0, 2, 2, 40}))
	if err != nil || r.Accepted || !r.AlertReceived || r.Alert != 40 {
		t.Fatalf("alert: %+v %v", r, err)
	}
	r, err = ReadFlight(bytes.NewReader(nil))
	if err != nil || !r.Closed {
		t.Fatalf("EOF: %+v %v", r, err)
	}
	if _, err := ReadFlight(bytes.NewReader([]byte("HTTP/1.1 400 Bad Request\r\n"))); err == nil {
		t.Fatal("garbage accepted")
	}
	// Partial flight: ServerHello then EOF is still an acceptance.
	r, err = ReadFlight(bytes.NewReader(flight(serverHello(VersionTLS10, 0x0005, true))))
	if err != nil || !r.Accepted || r.Version != VersionTLS10 || !r.SecureRenegotiation {
		t.Fatalf("partial: %+v %v", r, err)
	}
	// Truncated / malformed handshake messages must not panic.
	for _, bad := range [][]byte{
		flight(hsMsg(hsServerHello, []byte{3, 3})),
		flight(hsMsg(hsCertificate, []byte{0, 0, 9, 0, 0, 7, 1})),
	} {
		_, _ = ReadFlight(bytes.NewReader(bad))
	}
}

func TestClassify(t *testing.T) {
	cases := map[uint16]Grade{
		0xC02F: GradeGood,     // ECDHE_RSA AES128-GCM
		0xCCA8: GradeGood,     // ECDHE_RSA CHACHA20
		0xC013: GradeLegacy,   // ECDHE_RSA AES128-CBC-SHA
		0x002F: GradeWeak,     // RSA kex
		0x009C: GradeWeak,     // RSA kex GCM
		0xC012: GradeWeak,     // 3DES
		0x0005: GradeInsecure, // RC4
		0x0001: GradeInsecure, // NULL
		0x0003: GradeInsecure, // EXPORT
		0x0034: GradeInsecure, // anon
		0x0015: GradeInsecure, // DES
		0x1301: GradeGood,     // TLS1.3
	}
	for id, want := range cases {
		if got := Classify(id); got.Grade != want {
			t.Errorf("%s: %s (%s), want %s", SuiteName(id), got.Grade, got.Reason, want)
		}
	}
	all := AllSuites()
	if Classify(all[0]).Grade != GradeGood || Classify(all[len(all)-1]).Grade != GradeInsecure {
		t.Error("AllSuites not ordered strongest first")
	}
	if SuiteName(0xABCD) != "UNKNOWN_0xABCD" {
		t.Error(SuiteName(0xABCD))
	}
}

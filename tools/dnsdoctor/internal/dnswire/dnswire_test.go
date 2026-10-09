package dnswire

import (
	"bytes"
	"net/netip"
	"reflect"
	"testing"
)

func TestNameHelpers(t *testing.T) {
	cases := []struct{ in, fqdn string }{
		{"", "."}, {".", "."}, {"example.com", "example.com."}, {"example.com.", "example.com."},
		{`a\.b`, `a\.b.`}, {`a\\.`, `a\\.`},
	}
	for _, c := range cases {
		if got := Fqdn(c.in); got != c.fqdn {
			t.Errorf("Fqdn(%q) = %q, want %q", c.in, got, c.fqdn)
		}
	}
	if !EqualNames("Example.COM", "example.com.") {
		t.Error("EqualNames should ignore case")
	}
	if Parent("www.example.com.") != "example.com." || Parent("com.") != "." || Parent(".") != "." {
		t.Error("Parent wrong")
	}
	if CountLabels("*.example.com.") != 2 || CountLabels(".") != 0 || CountLabels("a.b.c") != 3 {
		t.Error("CountLabels wrong")
	}
	if LastLabels("a.b.example.com.", 2) != "example.com." {
		t.Error("LastLabels wrong")
	}
	if !IsSubdomain("www.Example.com", "example.COM.") || IsSubdomain("badexample.com", "example.com") || !IsSubdomain("x.", ".") {
		t.Error("IsSubdomain wrong")
	}
	if err := ValidateName("a..b"); err == nil {
		t.Error("empty label accepted")
	}
	long := bytes.Repeat([]byte("a"), 64)
	if err := ValidateName(string(long) + ".com"); err != ErrLabelTooLong {
		t.Errorf("long label: %v", err)
	}
	if err := ValidateName(`bad\9`); err == nil {
		t.Error("bad escape accepted")
	}
}

func TestEscapedLabelRoundTrip(t *testing.T) {
	w, err := nameWire(`a\.b\032c.example.`, false)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{5, 'a', '.', 'b', ' ', 'c', 7}, append([]byte("example"), 0)...)
	if !bytes.Equal(w, want) {
		t.Fatalf("wire = %v", w)
	}
	name, _, err := readName(w, 0)
	if err != nil || name != `a\.b\032c.example.` {
		t.Fatalf("readName = %q, %v", name, err)
	}
}

func sampleMsg() *Msg {
	m := &Msg{
		Header:   Header{ID: 0xbeef, Response: true, Authoritative: true, Rcode: RcodeSuccess},
		Question: []Question{{Name: "example.test.", Type: TypeSOA, Class: ClassINET}},
		Answer: []RR{
			{Name: "example.test.", Type: TypeSOA, Class: 1, TTL: 3600, Data: &SOA{MName: "ns1.example.test.", RName: "hostmaster.example.test.", Serial: 2026100901, Refresh: 7200, Retry: 900, Expire: 1209600, Minimum: 300}},
			{Name: "example.test.", Type: TypeRRSIG, Class: 1, TTL: 3600, Data: &RRSIG{TypeCovered: TypeSOA, Algorithm: 13, Labels: 2, OrigTTL: 3600, Expiration: 2, Inception: 1, KeyTag: 42, SignerName: "example.test.", Signature: []byte{1, 2, 3}}},
		},
		Authority: []RR{
			{Name: "example.test.", Type: TypeNS, Class: 1, TTL: 3600, Data: &NS{Host: "ns1.example.test."}},
			{Name: "example.test.", Type: TypeDS, Class: 1, TTL: 3600, Data: &DS{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: []byte{0xaa, 0xbb}}},
		},
		Additional: []RR{
			{Name: "ns1.example.test.", Type: TypeA, Class: 1, TTL: 3600, Data: &A{Addr: netip.MustParseAddr("192.0.2.53")}},
			{Name: "ns1.example.test.", Type: TypeAAAA, Class: 1, TTL: 3600, Data: &AAAA{Addr: netip.MustParseAddr("2001:db8::53")}},
			{Name: "example.test.", Type: TypeDNSKEY, Class: 1, TTL: 3600, Data: &DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: []byte{9, 9}}},
			{Name: "example.test.", Type: TypeMX, Class: 1, TTL: 3600, Data: &Unknown{Raw: []byte{0, 10, 0}}},
		},
		EDNS: &EDNS{UDPSize: 1232, DO: true},
	}
	return m
}

func TestPackUnpackRoundTrip(t *testing.T) {
	m := sampleMsg()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, m)
	}
}

func TestUnpackCompression(t *testing.T) {
	// Response with the answer owner and NS target compressed against the question.
	b := []byte{
		0x12, 0x34, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 2, 0, 1,
		0xc0, 12, 0, 2, 0, 1, 0, 0, 0x0e, 0x10, 0, 6, 3, 'n', 's', '1', 0xc0, 12,
	}
	m, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Authoritative || len(m.Answer) != 1 {
		t.Fatalf("bad header/answer: %+v", m)
	}
	ns := m.Answer[0].Data.(*NS)
	if m.Answer[0].Name != "example.test." || ns.Host != "ns1.example.test." {
		t.Fatalf("got %s -> %s", m.Answer[0].Name, ns.Host)
	}
}

func TestUnpackRejectsMalformed(t *testing.T) {
	loop := []byte{0, 0, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}
	if _, err := Unpack(loop); err == nil {
		t.Error("pointer loop accepted")
	}
	forward := []byte{0, 0, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 14, 0, 0, 1, 0, 1}
	if _, err := Unpack(forward); err == nil {
		t.Error("forward pointer accepted")
	}
	if _, err := Unpack([]byte{1, 2, 3}); err != ErrShort {
		t.Error("short header accepted")
	}
	good, _ := sampleMsg().Pack()
	for i := 12; i < len(good); i += 7 {
		if _, err := Unpack(good[:i]); err == nil {
			t.Errorf("truncated message (%d bytes) accepted", i)
		}
	}
}

func TestExtendedRcode(t *testing.T) {
	m := &Msg{Header: Header{ID: 1, Response: true, Rcode: RcodeBadVers}, EDNS: &EDNS{UDPSize: 512}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(b)
	if err != nil || got.Rcode != RcodeBadVers {
		t.Fatalf("rcode = %d, %v", got.Rcode, err)
	}
	if RcodeString(3) != "NXDOMAIN" || RcodeString(77) != "RCODE77" || TypeDS.String() != "DS" || Type(999).String() != "TYPE999" {
		t.Error("mnemonics wrong")
	}
}

func TestCanonicalRData(t *testing.T) {
	rr := RR{Type: TypeSOA, Data: &SOA{MName: "NS1.Example.", RName: "Host.Example."}}
	canon, _ := PackRData(rr, true)
	plain, _ := PackRData(rr, false)
	if bytes.Equal(canon, plain) {
		t.Fatal("canonical form should lowercase names")
	}
	if !bytes.Contains(canon, []byte("ns1")) {
		t.Fatal("not lowercased")
	}
}

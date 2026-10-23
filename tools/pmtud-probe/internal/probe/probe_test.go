package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func extErrBytes(errno uint32, origin, typ, code uint8, info uint32, offender netip.Addr) []byte {
	ne := binary.NativeEndian
	b := make([]byte, sizeofExtErr)
	ne.PutUint32(b[0:], errno)
	b[4], b[5], b[6] = origin, typ, code
	ne.PutUint32(b[8:], info)
	switch {
	case offender.Is4():
		sa := make([]byte, 16)
		ne.PutUint16(sa, afInet)
		a := offender.As4()
		copy(sa[4:], a[:])
		b = append(b, sa...)
	case offender.Is6():
		sa := make([]byte, 28)
		ne.PutUint16(sa, afInet6)
		a := offender.As16()
		copy(sa[8:], a[:])
		b = append(b, sa...)
	default:
		b = append(b, make([]byte, 16)...)
	}
	return b
}

func TestParseExtErr(t *testing.T) {
	r := netip.MustParseAddr("198.51.100.1")
	e, err := ParseExtErr(extErrBytes(90, OriginICMP, 3, 4, 1400, r))
	if err != nil {
		t.Fatal(err)
	}
	if e.Errno != 90 || e.Origin != OriginICMP || e.Type != 3 || e.Code != 4 || e.Info != 1400 || e.Offender != r {
		t.Fatalf("bad decode: %+v", e)
	}
	r6 := netip.MustParseAddr("2001:db8::1")
	e, err = ParseExtErr(extErrBytes(90, OriginICMP6, 2, 0, 1280, r6))
	if err != nil || e.Offender != r6 || e.Info != 1280 {
		t.Fatalf("bad v6 decode: %+v %v", e, err)
	}
	e, err = ParseExtErr(extErrBytes(90, OriginLocal, 0, 0, 1500, netip.Addr{}))
	if err != nil || e.Offender.IsValid() {
		t.Fatalf("AF_UNSPEC offender should be invalid: %+v %v", e, err)
	}
	if _, err := ParseExtErr(make([]byte, 10)); err == nil {
		t.Fatal("short buffer accepted")
	}
	// Truncated sockaddr must not panic.
	if _, err := ParseExtErr(extErrBytes(90, OriginICMP, 3, 4, 1400, r)[:sizeofExtErr+5]); err != nil {
		t.Fatal(err)
	}
}

func TestClassify(t *testing.T) {
	tgt := netip.MustParseAddr("192.0.2.10")
	rtr := netip.MustParseAddr("198.51.100.1")
	tgt6 := netip.MustParseAddr("2001:db8::10")
	rtr6 := netip.MustParseAddr("2001:db8::1")
	cases := []struct {
		name   string
		e      ExtErr
		target netip.Addr
		method Method
		want   Outcome
		mtu    int
	}{
		{"frag needed", ExtErr{Errno: 90, Origin: OriginICMP, Type: 3, Code: 4, Info: 1400, Offender: rtr}, tgt, MethodICMP, TooBig, 1400},
		{"frag needed no mtu", ExtErr{Errno: 90, Origin: OriginICMP, Type: 3, Code: 4, Info: 0, Offender: rtr}, tgt, MethodUDP, TooBig, 0},
		{"port unreach from target", ExtErr{Errno: 111, Origin: OriginICMP, Type: 3, Code: 3, Offender: tgt}, tgt, MethodUDP, Reply, 0},
		{"port unreach from firewall", ExtErr{Errno: 111, Origin: OriginICMP, Type: 3, Code: 3, Offender: rtr}, tgt, MethodUDP, Unreachable, 0},
		{"port unreach icmp method", ExtErr{Errno: 111, Origin: OriginICMP, Type: 3, Code: 3, Offender: tgt}, tgt, MethodICMP, Unreachable, 0},
		{"admin prohibited", ExtErr{Errno: 13, Origin: OriginICMP, Type: 3, Code: 13, Offender: rtr}, tgt, MethodUDP, Unreachable, 0},
		{"ptb v6", ExtErr{Errno: 90, Origin: OriginICMP6, Type: 2, Info: 1280, Offender: rtr6}, tgt6, MethodUDP, TooBig, 1280},
		{"port unreach v6", ExtErr{Errno: 111, Origin: OriginICMP6, Type: 1, Code: 4, Offender: tgt6}, tgt6, MethodUDP, Reply, 0},
		{"admin v6", ExtErr{Errno: 13, Origin: OriginICMP6, Type: 1, Code: 1, Offender: rtr6}, tgt6, MethodUDP, Unreachable, 0},
		{"local emsgsize", ExtErr{Errno: 90, Origin: OriginLocal, Info: 1500}, tgt, MethodUDP, LocalTooBig, 1500},
		{"local other", ExtErr{Errno: 113, Origin: OriginLocal}, tgt, MethodUDP, Unreachable, 0},
	}
	for _, c := range cases {
		r := Classify(c.e, c.target, c.method, 1500)
		if r.Outcome != c.want || r.MTU != c.mtu || r.Size != 1500 || r.Detail == "" {
			t.Errorf("%s: got %v mtu=%d detail=%q, want %v mtu=%d", c.name, r.Outcome, r.MTU, r.Detail, c.want, c.mtu)
		}
	}
}

func TestOverhead(t *testing.T) {
	if Overhead(netip.MustParseAddr("192.0.2.1")) != 28 || Overhead(netip.MustParseAddr("2001:db8::1")) != 48 {
		t.Fatal("bad overhead")
	}
	if Overhead(netip.MustParseAddr("::ffff:192.0.2.1")) != 48 {
		// 4in6 must be unmapped by callers; the raw value is treated as IPv6.
		t.Fatal("4in6 overhead")
	}
	if MinProbe(netip.MustParseAddr("192.0.2.1")) != 36 {
		t.Fatal("bad min probe")
	}
}

func TestParseTCPInfo(t *testing.T) {
	b := make([]byte, 104)
	ne := binary.NativeEndian
	b[5] = TCPIOptTimestamps | 2
	ne.PutUint32(b[16:], 1348)
	ne.PutUint32(b[60:], 1500)
	ne.PutUint32(b[84:], 1460)
	ti, err := ParseTCPInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	if ti.SndMSS != 1348 || ti.PMTU != 1500 || ti.AdvMSS != 1460 || ti.OptionBytes() != 12 {
		t.Fatalf("bad tcp_info: %+v", ti)
	}
	if _, err := ParseTCPInfo(b[:40]); err == nil {
		t.Fatal("short tcp_info accepted")
	}
	if (TCPInfo{}).OptionBytes() != 0 {
		t.Fatal("no timestamps should cost 0")
	}
}

func TestOutcomeString(t *testing.T) {
	for o, s := range map[Outcome]string{Reply: "reply", TooBig: "too-big", LocalTooBig: "local-too-big", Unreachable: "unreachable", Timeout: "timeout", 42: "outcome(42)"} {
		if o.String() != s {
			t.Errorf("%d: %q", o, o.String())
		}
	}
	for o := Reply; o <= Timeout; o++ {
		b, _ := o.MarshalText()
		var back Outcome
		if err := back.UnmarshalText(b); err != nil || back != o {
			t.Errorf("round trip %v: %v %v", o, back, err)
		}
	}
	var o Outcome
	if o.UnmarshalText([]byte("nope")) == nil {
		t.Error("unknown outcome accepted")
	}
}

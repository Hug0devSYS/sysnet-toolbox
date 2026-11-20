package ntp

import (
	"net/netip"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	p := Packet{
		Leap: LeapAddSec, Version: 4, Mode: ModeServer, Stratum: 2, Poll: 6, Precision: -23,
		RootDelay: 0x00010000, RootDispersion: 0x00000800, RefID: [4]byte{192, 0, 2, 1},
		RefTime: 1, OrigTime: 2, RecvTime: 3, XmitTime: 0xffffffffffffffff,
	}
	b := p.Encode()
	if len(b) != PacketLen {
		t.Fatalf("len %d", len(b))
	}
	if b[0] != 0x64 { // LI=1 VN=4 Mode=4
		t.Fatalf("first byte %#x", b[0])
	}
	got, err := Decode(append(b, make([]byte, 20)...)) // extension fields ignored
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, p)
	}
	if _, err := Decode(b[:47]); err == nil {
		t.Fatal("short packet accepted")
	}
}

func TestTimestampConversion(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 500_000_000, time.UTC)
	ts := TimeToNTP(now)
	if got := NTPToTime(ts, now); got.Sub(now).Abs() > time.Nanosecond {
		t.Fatalf("round trip %v vs %v", got, now)
	}
	// Era 0 ends 2036-02-07T06:28:16Z; a timestamp just after the rollover
	// (seconds field near 0) must map to era 1 for a pivot near 2036.
	rollover := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	after := rollover.Add(10 * time.Second)
	ts = TimeToNTP(after)
	if ts>>32 != 10 {
		t.Fatalf("seconds field after rollover = %d, want 10", ts>>32)
	}
	if got := NTPToTime(ts, rollover.Add(-time.Minute)); !got.Equal(after) {
		t.Fatalf("era 1: got %v want %v", got, after)
	}
	before := rollover.Add(-10 * time.Second)
	if got := NTPToTime(TimeToNTP(before), rollover.Add(time.Minute)); !got.Equal(before) {
		t.Fatalf("era 0 near rollover: got %v want %v", got, before)
	}
	// A pivot far in the past keeps era 0.
	old := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := NTPToTime(TimeToNTP(old), now); !got.Equal(old) {
		t.Fatalf("old timestamp %v", got)
	}
	// Fraction rounding never overflows to the next second.
	if got := NTPToTime(uint64(3913056000)<<32|0xffffffff, now); got.Nanosecond() != 999_999_999 {
		t.Fatalf("fraction rounding: %d", got.Nanosecond())
	}
}

func TestShortFormat(t *testing.T) {
	if d := ShortToDuration(0x00018000); d != 1500*time.Millisecond {
		t.Fatalf("1.5s: %v", d)
	}
	if v := DurationToShort(1500 * time.Millisecond); v != 0x00018000 {
		t.Fatalf("encode 1.5s: %#x", v)
	}
	if v := DurationToShort(-time.Second); v != 0 {
		t.Fatal("negative not clamped")
	}
	if v := DurationToShort(100000 * time.Second); v != 0xffffffff {
		t.Fatal("overflow not saturated")
	}
	if d := PrecisionDuration(-20); d < 950*time.Nanosecond || d > 960*time.Nanosecond {
		t.Fatalf("2^-20 = %v", d)
	}
}

func TestRefID(t *testing.T) {
	p := Packet{Stratum: 1, RefID: [4]byte{'G', 'P', 'S', 0}}
	if s := p.RefIDString(); s != "GPS" {
		t.Fatalf("stratum 1: %q", s)
	}
	p = Packet{Stratum: 1, RefID: [4]byte{'\x1b', '[', '2', 'J'}}
	if s := p.RefIDString(); s != "?[2J" {
		t.Fatalf("control chars not escaped: %q", s)
	}
	p = Packet{Stratum: 3, RefID: [4]byte{192, 0, 2, 7}}
	if s := p.RefIDString(); s != "192.0.2.7" {
		t.Fatalf("stratum 3: %q", s)
	}
	p = Packet{Stratum: 0, RefID: [4]byte{'R', 'A', 'T', 'E'}}
	if !p.IsKoD() || p.KissCode() != "RATE" {
		t.Fatal("kiss code")
	}
	if id := RefIDFor(netip.MustParseAddr("::ffff:192.0.2.9")); id != [4]byte{192, 0, 2, 9} {
		t.Fatalf("v4-mapped refid %v", id)
	}
	// First four bytes of MD5(2001:db8::1), computed independently.
	if id := RefIDFor(netip.MustParseAddr("2001:db8::1")); id != [4]byte{0x39, 0xab, 0x9b, 0x37} {
		t.Fatalf("IPv6 refid %x", id)
	}
}

// Package ntp implements the client side of the NTPv4 wire protocol
// (RFC 5905) needed to measure a server: request encoding, response
// decoding and validation, timestamp conversion across NTP eras and the
// offset/delay computation of one exchange.
//
// It only ever sends client-mode (mode 3) requests; it never answers,
// never uses control (mode 6) or private (mode 7) queries.
package ntp

import (
	"crypto/md5" //nolint:gosec // RFC 5905 defines the IPv6 refid as the first 4 bytes of an MD5 digest.
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"
)

// PacketLen is the size of an NTP header without extension fields.
const PacketLen = 48

// Modes (RFC 5905, figure 10).
const (
	ModeClient = 3
	ModeServer = 4
)

// Leap indicator values.
const (
	LeapNone    = 0
	LeapAddSec  = 1
	LeapDelSec  = 2
	LeapUnknown = 3 // clock not synchronised
)

// MaxStratum is the "unsynchronised" stratum value (RFC 5905).
const MaxStratum = 16

// Packet is an NTP header. Timestamps are kept in their raw 64-bit NTP
// format so that the origin check compares exact bit patterns.
type Packet struct {
	Leap           uint8
	Version        uint8
	Mode           uint8
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      uint32 // NTP short format (16.16 seconds)
	RootDispersion uint32 // NTP short format
	RefID          [4]byte
	RefTime        uint64
	OrigTime       uint64
	RecvTime       uint64
	XmitTime       uint64
}

// Encode serialises the header (48 bytes).
func (p *Packet) Encode() []byte {
	b := make([]byte, PacketLen)
	b[0] = p.Leap<<6 | (p.Version&7)<<3 | p.Mode&7
	b[1] = p.Stratum
	b[2] = byte(p.Poll)
	b[3] = byte(p.Precision)
	binary.BigEndian.PutUint32(b[4:], p.RootDelay)
	binary.BigEndian.PutUint32(b[8:], p.RootDispersion)
	copy(b[12:16], p.RefID[:])
	binary.BigEndian.PutUint64(b[16:], p.RefTime)
	binary.BigEndian.PutUint64(b[24:], p.OrigTime)
	binary.BigEndian.PutUint64(b[32:], p.RecvTime)
	binary.BigEndian.PutUint64(b[40:], p.XmitTime)
	return b
}

// ErrShortPacket is returned for datagrams smaller than an NTP header.
var ErrShortPacket = errors.New("short NTP packet")

// Decode parses an NTP header. Extension fields and MACs after the first
// 48 bytes are ignored.
func Decode(b []byte) (Packet, error) {
	if len(b) < PacketLen {
		return Packet{}, fmt.Errorf("%w: %d bytes", ErrShortPacket, len(b))
	}
	var p Packet
	p.Leap = b[0] >> 6
	p.Version = (b[0] >> 3) & 7
	p.Mode = b[0] & 7
	p.Stratum = b[1]
	p.Poll = int8(b[2])
	p.Precision = int8(b[3])
	p.RootDelay = binary.BigEndian.Uint32(b[4:])
	p.RootDispersion = binary.BigEndian.Uint32(b[8:])
	copy(p.RefID[:], b[12:16])
	p.RefTime = binary.BigEndian.Uint64(b[16:])
	p.OrigTime = binary.BigEndian.Uint64(b[24:])
	p.RecvTime = binary.BigEndian.Uint64(b[32:])
	p.XmitTime = binary.BigEndian.Uint64(b[40:])
	return p, nil
}

// ntpEpochOffset is the number of seconds from 1900-01-01 to 1970-01-01.
const ntpEpochOffset = 2208988800

const eraSeconds = int64(1) << 32

// TimeToNTP converts a time to a 64-bit NTP timestamp (era is implicit).
func TimeToNTP(t time.Time) uint64 {
	secs := t.Unix() + ntpEpochOffset
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	return uint64(secs)<<32 | frac
}

// NTPToTime converts a 64-bit NTP timestamp to a time, choosing the NTP era
// that puts the result closest to pivot (RFC 5905 section 6: timestamps are
// unambiguous within 68 years of the local clock). This handles the
// February 2036 era rollover.
func NTPToTime(ts uint64, pivot time.Time) time.Time {
	secs := int64(ts >> 32)
	frac := ts & 0xffffffff
	nsec := int64((frac*1e9 + 1<<31) >> 32)
	if nsec >= 1e9 { // rounding of 0xffffffff
		nsec = 1e9 - 1
	}
	unix := secs - ntpEpochOffset // era 0
	p := pivot.Unix()
	// Shift by whole eras towards the pivot.
	if d := p - unix; d > eraSeconds/2 {
		unix += ((d + eraSeconds/2) / eraSeconds) * eraSeconds
	} else if d < -eraSeconds/2 {
		unix -= ((-d + eraSeconds/2) / eraSeconds) * eraSeconds
	}
	return time.Unix(unix, nsec).UTC()
}

// ShortToDuration converts an NTP short-format (16.16) value.
func ShortToDuration(v uint32) time.Duration {
	return time.Duration((uint64(v)*uint64(time.Second) + 1<<15) >> 16)
}

// DurationToShort converts a non-negative duration to NTP short format,
// saturating at the largest representable value.
func DurationToShort(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	v := (uint64(d) << 16) / uint64(time.Second)
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// PrecisionDuration converts a log2-seconds precision value.
func PrecisionDuration(p int8) time.Duration {
	return time.Duration(math.Ldexp(float64(time.Second), int(p)))
}

// IsKoD reports whether the packet is a Kiss-o'-Death message.
func (p *Packet) IsKoD() bool { return p.Stratum == 0 }

// KissCode returns the ASCII kiss code of a KoD packet (e.g. "RATE").
func (p *Packet) KissCode() string { return asciiRefID(p.RefID) }

// RefIDString renders the reference identifier the way ntpq/chronyc do:
// ASCII for stratum 0/1 (kiss codes, "GPS", "PPS"...), a dotted quad for
// stratum 2 and above (an IPv4 upstream address, or the first four bytes
// of the MD5 digest of an IPv6 upstream address).
func (p *Packet) RefIDString() string {
	if p.Stratum <= 1 {
		s := asciiRefID(p.RefID)
		if s == "" {
			return "-"
		}
		return s
	}
	return netip.AddrFrom4(p.RefID).String()
}

func asciiRefID(id [4]byte) string {
	out := make([]byte, 0, 4)
	for _, c := range id {
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7e {
			out = append(out, '?')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// RefIDFor returns the refid a stratum >= 2 server uses when it is
// synchronised to addr: the IPv4 address itself, or the first four bytes
// of MD5(IPv6 address) (RFC 5905 section 7.3).
func RefIDFor(addr netip.Addr) [4]byte {
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.As4()
	}
	a16 := addr.As16()
	sum := md5.Sum(a16[:]) //nolint:gosec // protocol-defined, not a security use
	var id [4]byte
	copy(id[:], sum[:4])
	return id
}

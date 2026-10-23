// Package probe sends single path-MTU probes: one IP datagram of an exact
// size with the Don't Fragment bit set (IPv4) or local fragmentation
// disabled (IPv6), and reports what came back.
//
// The Linux implementation needs no privileges. It uses connected UDP
// sockets (the target answers with ICMP port unreachable) or unprivileged
// ICMP "ping" sockets (net.ipv4.ping_group_range), with IP_MTU_DISCOVER set
// to IP_PMTUDISC_PROBE so the kernel's cached path MTU is ignored, and
// IP_RECVERR so ICMP errors (fragmentation needed / packet too big, port
// unreachable, administratively prohibited...) are read from the socket
// error queue together with the address of the router that sent them.
package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Method selects the probe transport.
type Method string

// Probe methods.
const (
	MethodICMP Method = "icmp" // ICMP echo request, needs a reply from the target
	MethodUDP  Method = "udp"  // UDP datagram to a (normally closed) port, needs ICMP port unreachable
)

// Outcome classifies what happened to one probe.
type Outcome int

// Probe outcomes.
const (
	// Reply: the probe reached the target (echo reply, ICMP port
	// unreachable from the target itself, or a UDP answer).
	Reply Outcome = iota
	// TooBig: a router answered ICMP "fragmentation needed" (IPv4) or
	// ICMPv6 "packet too big"; Result.MTU carries the advertised MTU.
	TooBig
	// LocalTooBig: the local stack refused to send the datagram because it
	// exceeds the outgoing interface or route MTU.
	LocalTooBig
	// Unreachable: another ICMP error (administratively prohibited, host
	// unreachable, time exceeded...) or a port unreachable sent by a third
	// party.
	Unreachable
	// Timeout: nothing came back before the deadline.
	Timeout
)

func (o Outcome) String() string {
	switch o {
	case Reply:
		return "reply"
	case TooBig:
		return "too-big"
	case LocalTooBig:
		return "local-too-big"
	case Unreachable:
		return "unreachable"
	case Timeout:
		return "timeout"
	}
	return fmt.Sprintf("outcome(%d)", int(o))
}

// MarshalText implements encoding.TextMarshaler (used by JSON output).
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (o *Outcome) UnmarshalText(b []byte) error {
	for c := Reply; c <= Timeout; c++ {
		if c.String() == string(b) {
			*o = c
			return nil
		}
	}
	return fmt.Errorf("unknown probe outcome %q", b)
}

// Result describes the answer to one probe.
type Result struct {
	Outcome  Outcome
	Size     int        // IP packet size that was probed (headers included)
	MTU      int        // advertised/local MTU for TooBig and LocalTooBig (0 = not given)
	From     netip.Addr // sender of the ICMP error or reply, if known
	ICMPType int        // ICMP type of the error, -1 if none
	ICMPCode int        // ICMP code of the error, -1 if none
	RTT      time.Duration
	Detail   string // human-readable description of the answer
}

// Prober sends one probe of an exact IP packet size.
//
// Probe returns an error only for local failures that say nothing about the
// path (socket creation refused, context cancelled...). Everything the
// network did, including silence, is reported in Result.
type Prober interface {
	Probe(ctx context.Context, size int, timeout time.Duration) (Result, error)
	// Overhead is the number of header bytes (IP + ICMP/UDP) in a probe,
	// i.e. the smallest valid probe size without payload.
	Overhead() int
	Method() Method
	Target() netip.Addr
}

// Errors returned by probers.
var (
	ErrUnsupported = errors.New("probing is only supported on Linux")
	ErrPermission  = errors.New("permission denied")
)

// Header sizes.
const (
	IPv4Header = 20
	IPv6Header = 40
	L4Header   = 8 // UDP and ICMP echo headers are both 8 bytes
	TCPHeader  = 20
	// NonceLen is the number of payload bytes used to match answers to
	// probes; it fits in the 8 bytes of payload that minimal ICMP error
	// quotes carry after the UDP header.
	NonceLen = 8
)

// IPHeader returns the IP header size for addr's family.
func IPHeader(addr netip.Addr) int {
	if addr.Is4() && !addr.Is4In6() {
		return IPv4Header
	}
	return IPv6Header
}

// Overhead returns IP + L4 header bytes for addr's family.
func Overhead(addr netip.Addr) int { return IPHeader(addr) + L4Header }

// MinProbe is the smallest probe size that still carries the nonce.
func MinProbe(addr netip.Addr) int { return Overhead(addr) + NonceLen }

// Origins of a struct sock_extended_err (linux/errqueue.h).
const (
	OriginNone  = 0
	OriginLocal = 1
	OriginICMP  = 2
	OriginICMP6 = 3
)

// ExtErr is a decoded struct sock_extended_err plus its offender address.
type ExtErr struct {
	Errno    uint32
	Origin   uint8
	Type     uint8
	Code     uint8
	Info     uint32 // MTU for EMSGSIZE errors
	Data     uint32
	Offender netip.Addr
}

// sizeofExtErr is sizeof(struct sock_extended_err).
const sizeofExtErr = 16

// Address families as found in sockaddr structures on Linux.
const (
	afInet  = 2
	afInet6 = 10
)

// ParseExtErr decodes the payload of an IP_RECVERR / IPV6_RECVERR control
// message: a struct sock_extended_err in host byte order, followed by the
// offender's sockaddr (SO_EE_OFFENDER).
func ParseExtErr(b []byte) (ExtErr, error) {
	if len(b) < sizeofExtErr {
		return ExtErr{}, fmt.Errorf("short sock_extended_err: %d bytes", len(b))
	}
	ne := binary.NativeEndian
	e := ExtErr{
		Errno:  ne.Uint32(b[0:]),
		Origin: b[4],
		Type:   b[5],
		Code:   b[6],
		Info:   ne.Uint32(b[8:]),
		Data:   ne.Uint32(b[12:]),
	}
	sa := b[sizeofExtErr:]
	if len(sa) >= 2 {
		switch ne.Uint16(sa) {
		case afInet:
			if len(sa) >= 8 {
				e.Offender = netip.AddrFrom4([4]byte(sa[4:8]))
			}
		case afInet6:
			if len(sa) >= 24 {
				e.Offender = netip.AddrFrom16([16]byte(sa[8:24]))
			}
		}
	}
	return e, nil
}

// errno values used by the classifier (identical on every Linux arch).
const (
	errnoEMSGSIZE = 90
)

// Classify turns an extended socket error into a probe Result for a probe
// sent to target with the given method.
func Classify(e ExtErr, target netip.Addr, method Method, size int) Result {
	r := Result{Size: size, From: e.Offender, ICMPType: -1, ICMPCode: -1}
	switch e.Origin {
	case OriginLocal:
		if e.Errno == errnoEMSGSIZE {
			r.Outcome, r.MTU = LocalTooBig, int(e.Info)
			r.Detail = fmt.Sprintf("local stack refused %d bytes (MTU %d)", size, e.Info)
		} else {
			r.Outcome = Unreachable
			r.Detail = fmt.Sprintf("local error (errno %d)", e.Errno)
		}
		return r
	case OriginICMP:
		r.ICMPType, r.ICMPCode = int(e.Type), int(e.Code)
		switch {
		case e.Type == 3 && e.Code == 4:
			r.Outcome, r.MTU = TooBig, int(e.Info)
			r.Detail = fmt.Sprintf("ICMP fragmentation needed, next-hop MTU %d", e.Info)
			if e.Info == 0 {
				r.Detail = "ICMP fragmentation needed without next-hop MTU (pre-RFC 1191 router)"
			}
		case e.Type == 3 && e.Code == 3 && method == MethodUDP && sameAddr(e.Offender, target):
			r.Outcome, r.Detail = Reply, "ICMP port unreachable from target"
		default:
			r.Outcome, r.Detail = Unreachable, icmp4Name(e.Type, e.Code)
		}
		return r
	case OriginICMP6:
		r.ICMPType, r.ICMPCode = int(e.Type), int(e.Code)
		switch {
		case e.Type == 2:
			r.Outcome, r.MTU = TooBig, int(e.Info)
			r.Detail = fmt.Sprintf("ICMPv6 packet too big, MTU %d", e.Info)
		case e.Type == 1 && e.Code == 4 && method == MethodUDP && sameAddr(e.Offender, target):
			r.Outcome, r.Detail = Reply, "ICMPv6 port unreachable from target"
		default:
			r.Outcome, r.Detail = Unreachable, icmp6Name(e.Type, e.Code)
		}
		return r
	}
	r.Outcome = Unreachable
	r.Detail = fmt.Sprintf("socket error (errno %d, origin %d)", e.Errno, e.Origin)
	return r
}

func sameAddr(a, b netip.Addr) bool { return a.IsValid() && a.Unmap() == b.Unmap() }

func icmp4Name(t, c uint8) string {
	switch t {
	case 3:
		names := map[uint8]string{
			0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
			3: "port unreachable", 5: "source route failed", 6: "destination network unknown",
			7: "destination host unknown", 9: "network administratively prohibited",
			10: "host administratively prohibited", 13: "communication administratively prohibited",
		}
		if n, ok := names[c]; ok {
			return "ICMP " + n
		}
		return fmt.Sprintf("ICMP destination unreachable (code %d)", c)
	case 11:
		return "ICMP time exceeded"
	case 12:
		return "ICMP parameter problem"
	}
	return fmt.Sprintf("ICMP type %d code %d", t, c)
}

func icmp6Name(t, c uint8) string {
	switch t {
	case 1:
		names := map[uint8]string{
			0: "no route to destination", 1: "communication administratively prohibited",
			3: "address unreachable", 4: "port unreachable", 5: "source address failed ingress/egress policy",
			6: "reject route to destination",
		}
		if n, ok := names[c]; ok {
			return "ICMPv6 " + n
		}
		return fmt.Sprintf("ICMPv6 destination unreachable (code %d)", c)
	case 3:
		return "ICMPv6 time exceeded"
	case 4:
		return "ICMPv6 parameter problem"
	}
	return fmt.Sprintf("ICMPv6 type %d code %d", t, c)
}

// Nonce builds the probe payload prefix: 4 random bytes + 4-byte sequence.
func Nonce(key uint32, seq uint32) [NonceLen]byte {
	var n [NonceLen]byte
	binary.BigEndian.PutUint32(n[0:], key)
	binary.BigEndian.PutUint32(n[4:], seq)
	return n
}

// Route describes the local side of the path to a target.
type Route struct {
	Local     netip.Addr `json:"local_address"`
	Interface string     `json:"interface,omitempty"`
	IfMTU     int        `json:"interface_mtu,omitempty"` // MTU of the outgoing interface
	RouteMTU  int        `json:"route_mtu,omitempty"`     // kernel IP_MTU: route MTU or cached path MTU
}

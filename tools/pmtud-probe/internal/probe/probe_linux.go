//go:build linux

package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Linux socket option values (identical on every architecture).
const (
	solIP             = 0
	solIPv6           = 41
	solTCP            = 6
	ipMTUDiscover     = 10
	ipRecvErr         = 11
	ipMTU             = 14
	ipPMTUDiscProbe   = 3
	ipv6MTUDiscover   = 23
	ipv6MTU           = 24
	ipv6RecvErr       = 25
	ipv6PMTUDiscProbe = 3
	ipv6DontFrag      = 62
	tcpInfo           = 11
	protoICMP         = 1
	protoICMPv6       = 58
)

type sockProber struct {
	target netip.Addr
	port   uint16
	method Method
	v6     bool
	key    uint32
	seq    atomic.Uint32
}

// New returns a Linux prober for target. udpPort is the destination port
// for MethodUDP (ignored for ICMP). For MethodICMP it checks that the
// kernel allows unprivileged ping sockets and returns an error wrapping
// ErrPermission otherwise.
func New(target netip.Addr, method Method, udpPort int) (Prober, error) {
	if !target.IsValid() {
		return nil, errors.New("invalid target address")
	}
	if method != MethodICMP && method != MethodUDP {
		return nil, fmt.Errorf("unknown method %q", method)
	}
	if udpPort < 1 || udpPort > 65535 {
		return nil, fmt.Errorf("invalid UDP port %d", udpPort)
	}
	var kb [4]byte
	if _, err := rand.Read(kb[:]); err != nil {
		return nil, err
	}
	p := &sockProber{
		target: target.Unmap(),
		port:   uint16(udpPort),
		method: method,
		v6:     target.Is6() && !target.Is4In6(),
		key:    binary.BigEndian.Uint32(kb[:]),
	}
	fd, err := p.socket()
	if err != nil {
		return nil, err
	}
	syscall.Close(fd)
	return p, nil
}

func (p *sockProber) Overhead() int      { return Overhead(p.target) }
func (p *sockProber) Method() Method     { return p.method }
func (p *sockProber) Target() netip.Addr { return p.target }

func (p *sockProber) socket() (int, error) {
	fam, proto := syscall.AF_INET, 0
	if p.v6 {
		fam = syscall.AF_INET6
	}
	if p.method == MethodICMP {
		proto = protoICMP
		if p.v6 {
			proto = protoICMPv6
		}
	}
	fd, err := syscall.Socket(fam, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, proto)
	if err != nil {
		if p.method == MethodICMP && (errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)) {
			return -1, fmt.Errorf("%w: unprivileged ICMP sockets are disabled (sysctl net.ipv4.ping_group_range); use --method udp", ErrPermission)
		}
		return -1, fmt.Errorf("socket: %w", err)
	}
	opts := [][3]int{{solIP, ipMTUDiscover, ipPMTUDiscProbe}, {solIP, ipRecvErr, 1}}
	if p.v6 {
		opts = [][3]int{{solIPv6, ipv6MTUDiscover, ipv6PMTUDiscProbe}, {solIPv6, ipv6RecvErr, 1}, {solIPv6, ipv6DontFrag, 1}}
	}
	for _, o := range opts {
		if err := syscall.SetsockoptInt(fd, o[0], o[1], o[2]); err != nil {
			syscall.Close(fd)
			return -1, fmt.Errorf("setsockopt(%d, %d): %w", o[0], o[1], err)
		}
	}
	return fd, nil
}

func (p *sockProber) sockaddr(port uint16) (syscall.Sockaddr, error) {
	if !p.v6 {
		return &syscall.SockaddrInet4{Port: int(port), Addr: p.target.As4()}, nil
	}
	sa := &syscall.SockaddrInet6{Port: int(port), Addr: p.target.As16()}
	if z := p.target.Zone(); z != "" {
		ifi, err := net.InterfaceByName(z)
		if err != nil {
			return nil, fmt.Errorf("zone %q: %w", z, err)
		}
		sa.ZoneId = uint32(ifi.Index)
	}
	return sa, nil
}

// Probe sends one datagram of exactly size bytes (IP header included) on a
// fresh connected socket and waits up to timeout for an answer.
func (p *sockProber) Probe(ctx context.Context, size int, timeout time.Duration) (Result, error) {
	if size < MinProbe(p.target) || size > 65535 {
		return Result{}, fmt.Errorf("probe size %d out of range [%d, 65535]", size, MinProbe(p.target))
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	fd, err := p.socket()
	if err != nil {
		return Result{}, err
	}
	port := p.port
	if p.method == MethodICMP {
		port = 0
	}
	sa, err := p.sockaddr(port)
	if err != nil {
		syscall.Close(fd)
		return Result{}, err
	}
	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		if res, ok := localSendError(err, size); ok {
			return res, nil
		}
		return Result{}, fmt.Errorf("connect: %w", err)
	}
	f := os.NewFile(uintptr(fd), "probe")
	conn, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return Result{}, fmt.Errorf("wrapping socket: %w", err)
	}
	defer conn.Close()
	rc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return Result{}, err
	}

	seq := p.seq.Add(1)
	nonce := Nonce(p.key, seq)
	pkt := p.packet(size, uint16(seq), nonce)

	start := time.Now()
	var werr error
	if err := rc.Write(func(fd uintptr) bool {
		_, werr = syscall.Write(int(fd), pkt)
		return !errors.Is(werr, syscall.EAGAIN)
	}); err != nil {
		return Result{}, err
	}
	if werr != nil {
		if errors.Is(werr, syscall.EMSGSIZE) {
			mtu := 0
			_ = rc.Control(func(fd uintptr) { mtu = getMTU(int(fd), p.v6) })
			return Result{Outcome: LocalTooBig, Size: size, MTU: mtu, ICMPType: -1, ICMPCode: -1,
				Detail: fmt.Sprintf("local stack refused %d bytes (route/interface MTU %d)", size, mtu)}, nil
		}
		if res, ok := localSendError(werr, size); ok {
			return res, nil
		}
		return Result{}, fmt.Errorf("send: %w", werr)
	}

	deadline := start.Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	var (
		res  Result
		done bool
		rerr error
		buf  = make([]byte, 65536)
		oob  = make([]byte, 512)
	)
	err = rc.Read(func(fd uintptr) bool {
		for {
			n, oobn, _, _, err := syscall.Recvmsg(int(fd), buf, oob, syscall.MSG_ERRQUEUE)
			if err == nil {
				if r, ok := p.fromErrQueue(buf[:n], oob[:oobn], size, uint16(seq), nonce); ok {
					res, done = r, true
					return true
				}
				continue
			}
			if !errors.Is(err, syscall.EAGAIN) {
				rerr = fmt.Errorf("recvmsg(MSG_ERRQUEUE): %w", err)
				return true
			}
			n, _, err = syscall.Recvfrom(int(fd), buf, 0)
			switch {
			case err == nil:
				if p.isReply(buf[:n], uint16(seq), nonce) {
					res, done = Result{Outcome: Reply, Size: size, From: p.target, ICMPType: -1, ICMPCode: -1, Detail: p.replyDetail()}, true
					return true
				}
				continue
			case errors.Is(err, syscall.EAGAIN):
				return false
			case errors.Is(err, syscall.EINTR):
				continue
			default:
				// A pending socket error (ECONNREFUSED, EMSGSIZE...) that is
				// also queued on the error queue: loop to read it there.
				continue
			}
		}
	})
	rtt := time.Since(start)
	switch {
	case done:
		res.RTT = rtt
		return res, nil
	case rerr != nil:
		return Result{}, rerr
	case err != nil && ctx.Err() != nil:
		return Result{}, ctx.Err()
	case err != nil && !errors.Is(err, os.ErrDeadlineExceeded):
		return Result{}, err
	}
	return Result{Outcome: Timeout, Size: size, ICMPType: -1, ICMPCode: -1, RTT: rtt, Detail: "no answer"}, nil
}

func (p *sockProber) replyDetail() string {
	if p.method == MethodICMP {
		return "echo reply"
	}
	return "UDP answer from target"
}

// packet builds the transport payload handed to the kernel: the UDP
// payload, or an ICMP echo request (the kernel fills in id and checksum).
func (p *sockProber) packet(size int, seq uint16, nonce [NonceLen]byte) []byte {
	b := make([]byte, size-IPHeader(p.target))
	if p.method == MethodUDP {
		b = b[:len(b)-L4Header]
		copy(b, nonce[:])
	} else {
		b[0] = 8
		if p.v6 {
			b[0] = 128
		}
		binary.BigEndian.PutUint16(b[6:], seq)
		copy(b[L4Header:], nonce[:])
	}
	fill := NonceLen
	if p.method == MethodICMP {
		fill += L4Header
	}
	for i := fill; i < len(b); i++ {
		b[i] = byte(i) // non-zero filler defeats link-layer compression
	}
	return b
}

func (p *sockProber) isReply(b []byte, seq uint16, nonce [NonceLen]byte) bool {
	if p.method == MethodUDP {
		return true // any datagram from the connected peer proves delivery
	}
	want := byte(0)
	if p.v6 {
		want = 129
	}
	return len(b) >= L4Header+NonceLen && b[0] == want &&
		binary.BigEndian.Uint16(b[6:]) == seq && [NonceLen]byte(b[L4Header:L4Header+NonceLen]) == nonce
}

// fromErrQueue decodes one error-queue message. data is the (possibly
// truncated) quote of the offending datagram's transport payload.
func (p *sockProber) fromErrQueue(data, oob []byte, size int, seq uint16, nonce [NonceLen]byte) (Result, bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return Result{}, false
	}
	for _, m := range msgs {
		if !(m.Header.Level == solIP && m.Header.Type == ipRecvErr) &&
			!(m.Header.Level == solIPv6 && m.Header.Type == ipv6RecvErr) {
			continue
		}
		e, err := ParseExtErr(m.Data)
		if err != nil {
			continue
		}
		if !p.quoteMatches(data, seq, nonce) {
			return Result{}, false
		}
		return Classify(e, p.target, p.method, size), true
	}
	return Result{}, false
}

func (p *sockProber) quoteMatches(data []byte, seq uint16, nonce [NonceLen]byte) bool {
	if p.method == MethodUDP {
		n := min(len(data), NonceLen)
		return string(data[:n]) == string(nonce[:n])
	}
	if len(data) >= L4Header && binary.BigEndian.Uint16(data[6:]) != seq {
		return false
	}
	if len(data) > L4Header {
		n := min(len(data)-L4Header, NonceLen)
		return string(data[L4Header:L4Header+n]) == string(nonce[:n])
	}
	return true
}

func localSendError(err error, size int) (Result, bool) {
	r := Result{Outcome: Unreachable, Size: size, ICMPType: -1, ICMPCode: -1}
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		r.Detail = "no route to target (local)"
	case errors.Is(err, syscall.EHOSTUNREACH):
		r.Detail = "host unreachable (local neighbour resolution failed)"
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		r.Detail = "blocked by the local firewall (output chain)"
	case errors.Is(err, syscall.ECONNREFUSED):
		r.Outcome, r.Detail = Reply, "port unreachable from target"
	default:
		return Result{}, false
	}
	return r, true
}

func getMTU(fd int, v6 bool) int {
	level, opt := solIP, ipMTU
	if v6 {
		level, opt = solIPv6, ipv6MTU
	}
	v, err := syscall.GetsockoptInt(fd, level, opt)
	if err != nil {
		return 0
	}
	return v
}

// LookupRoute asks the kernel which local address and interface it would
// use to reach target, and the MTU of that route (IP_MTU, which reflects a
// cached path MTU learnt from earlier ICMP messages). No packet is sent.
func LookupRoute(target netip.Addr) (Route, error) {
	target = target.Unmap()
	p := &sockProber{target: target, method: MethodUDP, v6: target.Is6()}
	fd, err := p.socket()
	if err != nil {
		return Route{}, err
	}
	defer syscall.Close(fd)
	sa, err := p.sockaddr(9)
	if err != nil {
		return Route{}, err
	}
	if err := syscall.Connect(fd, sa); err != nil {
		return Route{}, fmt.Errorf("no route to %s: %w", target, err)
	}
	var r Route
	r.RouteMTU = getMTU(fd, p.v6)
	ls, err := syscall.Getsockname(fd)
	if err != nil {
		return r, err
	}
	switch a := ls.(type) {
	case *syscall.SockaddrInet4:
		r.Local = netip.AddrFrom4(a.Addr)
	case *syscall.SockaddrInet6:
		r.Local = netip.AddrFrom16(a.Addr)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return r, nil
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap() == r.Local {
					r.Interface, r.IfMTU = ifi.Name, ifi.MTU
					return r, nil
				}
			}
		}
	}
	return r, nil
}

// TCPCheck opens a TCP connection to target:port (handshake only, no data
// is sent) and returns the kernel's TCP_INFO for it.
func TCPCheck(ctx context.Context, target netip.Addr, port int, timeout time.Duration) (TCPInfo, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(target.Unmap(), uint16(port)).String())
	if err != nil {
		return TCPInfo{}, err
	}
	defer c.Close()
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		return TCPInfo{}, err
	}
	var (
		buf  [232]byte
		gerr error
		n    = uint32(len(buf))
	)
	if err := rc.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solTCP, tcpInfo,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
		if e != 0 {
			gerr = e
		}
	}); err != nil {
		return TCPInfo{}, err
	}
	if gerr != nil {
		return TCPInfo{}, fmt.Errorf("getsockopt(TCP_INFO): %w", gerr)
	}
	return ParseTCPInfo(buf[:n])
}

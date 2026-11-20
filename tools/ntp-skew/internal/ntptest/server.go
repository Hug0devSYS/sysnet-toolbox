// Package ntptest provides a scriptable NTP server on a loopback UDP socket
// for tests: offset, stratum, refid, leap indicator, kiss codes and
// misbehaviour (wrong origin, silence) are configurable per server.
package ntptest

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/ntp"
)

// Behaviour describes how the server answers.
type Behaviour struct {
	Offset           time.Duration // added to the server's clock
	Stratum          uint8
	RefID            [4]byte
	Leap             uint8
	RootDelay        time.Duration
	RootDispersion   time.Duration
	RefAge           time.Duration // reference timestamp = now - RefAge
	KissCode         string        // answer with a KoD
	Silent           bool          // never answer
	WrongOriginFirst bool          // send a spoofed answer (bad origin) before the real one
	Version          uint8
}

// Server is a running fake server.
type Server struct {
	Addr netip.AddrPort
	conn *net.UDPConn
	mu   sync.Mutex
	b    Behaviour
	reqs int
	wg   sync.WaitGroup
}

// Start listens on 127.0.0.1 (random port).
func Start(b Behaviour) (*Server, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	s := &Server{conn: c, b: b, Addr: c.LocalAddr().(*net.UDPAddr).AddrPort()}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

// Requests returns the number of requests received.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs
}

// Close stops the server.
func (s *Server) Close() {
	s.conn.Close()
	s.wg.Wait()
}

func (s *Server) loop() {
	defer s.wg.Done()
	buf := make([]byte, 512)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		recv := time.Now()
		req, err := ntp.Decode(buf[:n])
		if err != nil || req.Mode != ntp.ModeClient {
			continue
		}
		s.mu.Lock()
		s.reqs++
		b := s.b
		s.mu.Unlock()
		if b.Silent {
			continue
		}
		resp := ntp.Packet{
			Leap: b.Leap, Version: 4, Mode: ntp.ModeServer, Stratum: b.Stratum, Poll: 6, Precision: -20,
			RootDelay: ntp.DurationToShort(b.RootDelay), RootDispersion: ntp.DurationToShort(b.RootDispersion),
			RefID: b.RefID, OrigTime: req.XmitTime,
		}
		if b.Version != 0 {
			resp.Version = b.Version
		}
		if b.KissCode != "" {
			resp.Stratum = 0
			copy(resp.RefID[:], b.KissCode)
		}
		resp.RefTime = ntp.TimeToNTP(recv.Add(b.Offset - b.RefAge))
		resp.RecvTime = ntp.TimeToNTP(recv.Add(b.Offset))
		resp.XmitTime = ntp.TimeToNTP(time.Now().Add(b.Offset))
		if b.WrongOriginFirst {
			bad := resp
			bad.OrigTime ^= 0xdeadbeef
			_, _ = s.conn.WriteToUDPAddrPort(bad.Encode(), from)
		}
		_, _ = s.conn.WriteToUDPAddrPort(resp.Encode(), from)
	}
}

package probe

import (
	"encoding/binary"
	"fmt"
)

// TCPInfo holds the struct tcp_info fields pmtud-probe uses.
type TCPInfo struct {
	Options uint8  // tcpi_options (TCPI_OPT_* bits)
	SndMSS  uint32 // tcpi_snd_mss: current sending MSS (payload bytes)
	RcvMSS  uint32 // tcpi_rcv_mss
	PMTU    uint32 // tcpi_pmtu: path MTU the kernel uses for this connection
	AdvMSS  uint32 // tcpi_advmss: MSS we advertised
	RTT     uint32 // tcpi_rtt in microseconds
}

// TCPIOptTimestamps is TCPI_OPT_TIMESTAMPS.
const TCPIOptTimestamps = 1

// TimestampOptionLen is the per-segment cost of the TCP timestamp option
// (TCPOLEN_TSTAMP_ALIGNED).
const TimestampOptionLen = 12

// ParseTCPInfo decodes the leading part of a Linux struct tcp_info. Field
// offsets are identical on every architecture.
func ParseTCPInfo(b []byte) (TCPInfo, error) {
	if len(b) < 88 {
		return TCPInfo{}, fmt.Errorf("short tcp_info: %d bytes", len(b))
	}
	ne := binary.NativeEndian
	return TCPInfo{
		Options: b[5],
		SndMSS:  ne.Uint32(b[16:]),
		RcvMSS:  ne.Uint32(b[20:]),
		PMTU:    ne.Uint32(b[60:]),
		RTT:     ne.Uint32(b[68:]),
		AdvMSS:  ne.Uint32(b[84:]),
	}, nil
}

// OptionBytes is the TCP option overhead the kernel subtracts from the
// MSS on every segment of this connection.
func (t TCPInfo) OptionBytes() int {
	if t.Options&TCPIOptTimestamps != 0 {
		return TimestampOptionLen
	}
	return 0
}

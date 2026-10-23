//go:build !linux

package probe

import (
	"context"
	"net/netip"
	"time"
)

// New is only implemented on Linux.
func New(netip.Addr, Method, int) (Prober, error) { return nil, ErrUnsupported }

// LookupRoute is only implemented on Linux.
func LookupRoute(netip.Addr) (Route, error) { return Route{}, ErrUnsupported }

// TCPCheck is only implemented on Linux.
func TCPCheck(context.Context, netip.Addr, int, time.Duration) (TCPInfo, error) {
	return TCPInfo{}, ErrUnsupported
}

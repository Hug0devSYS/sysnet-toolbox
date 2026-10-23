// Command pmtud-probe measures the path MTU towards one or more targets,
// detects PMTUD black holes (routers or firewalls that drop oversized
// packets without sending ICMP "fragmentation needed" / ICMPv6 "packet too
// big") and checks TCP MSS clamping. IPv4 and IPv6, no privileges needed
// on Linux.
//
// It is read-only: it sends probe datagrams and TCP handshakes only.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

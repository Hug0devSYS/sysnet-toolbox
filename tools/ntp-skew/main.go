// Command ntp-skew queries several NTP servers, separates truechimers from
// falsetickers with the RFC 5905 intersection algorithm, and reports the
// offset of the local clock against their consensus together with
// configuration hazards visible from the outside (unsynchronised or
// rate-limiting servers, stale references, synchronisation loops, no
// upstream diversity, leap second disagreement).
//
// It is read-only: it sends NTP client-mode requests and never adjusts
// the local clock.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

// Command dnsdoctor performs an end-to-end health check of a DNS zone:
// iterative delegation walk from the root, parent/child NS consistency,
// glue checks, lame delegation detection, SOA serial drift between
// authoritative servers and DNSSEC chain-of-trust validation.
//
// It is strictly read-only: it only sends standard DNS queries.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/cli"
)

func main() {
	// SIGINT/SIGTERM cancel the running diagnosis: the reports gathered so
	// far are still printed (or encoded as JSON) and the exit code is 3.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

// Command tlsaudit audits a fleet of TLS endpoints: certificate expiry,
// chain completeness and trust, hostname (SAN) match, protocol versions,
// cipher suites, DHE strength, secure renegotiation, TLS_FALLBACK_SCSV and
// OCSP stapling. Output is human-readable text, JSON, a one-line-per-target
// summary and/or a Prometheus textfile-collector file.
//
// It is strictly read-only: it performs TLS handshakes (and STARTTLS
// upgrades) only and never sends application data or credentials.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

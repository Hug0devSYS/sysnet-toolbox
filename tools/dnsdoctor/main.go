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

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, nil))
}

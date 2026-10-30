// Command subnet-planner plans IPv4/IPv6 subnets (VLSM), checks prefix and
// IP address inventories (NetBox exports, CSV, JSON) for duplicates and
// overlaps, aggregates routes and computes subnet details.
//
// It is offline and read-only: it only reads files and prints results.
package main

import (
	"os"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.DefaultEnv()))
}

package cli

import (
	"encoding/csv"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/inventory"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/plan"
)

const planHead = `subnet-planner plan - VLSM allocation inside a parent prefix

Usage:
  subnet-planner plan --parent 10.20.0.0/16 users=500 voice=120 mgmt=/26 transit=/31
  subnet-planner plan --parent 2001:db8:42::/48 -f subnets.csv --used netbox-prefixes.csv

Requests are NAME=SIZE where SIZE is a number of usable hosts (e.g. 120) or
a prefix length (e.g. /26). A requests file has one "name,size[,vlan[,note]]"
or "name size [vlan] [note]" per line. Requests are allocated largest first
(ties in input order), each in the smallest free block that holds it, so the
remaining space stays as contiguous as possible. Prefixes listed with --used
(NetBox export, CSV, JSON, plain list) or --exclude are never allocated;
--used rows equal to or containing the parent (its own record, containers
above it) are ignored.

IPv4: a host count H needs a subnet with at least H usable addresses
(network and broadcast excluded; --allow-31 permits /31 and /32).
IPv6: host counts are rounded up to a /64 (--v6-len) because SLAAC needs it.

Flags:
`

const planTail = `
Exit codes: 0 every request allocated, 1 warnings (e.g. IPv6 subnet longer
than /64), 2 one or more requests do not fit, 3 usage or input error.
`

func runPlan(args []string, env Env) int {
	fs := newFlagSet("plan", planHead, planTail, env)
	parentS := fs.String("parent", "", "parent prefix to carve (required)")
	var used, exclude, reqFiles stringList
	fs.Var(&used, "used", "inventory of prefixes already in use (CSV/NetBox export, JSON, list; '-' = stdin); repeatable")
	fs.Var(&exclude, "exclude", "prefix that must not be allocated; repeatable")
	fs.Var(&reqFiles, "f", "requests file ('-' = stdin); repeatable")
	growth := fs.Float64("growth", 0, "extra percentage added to every host count (e.g. 25)")
	reserve := fs.Int64("reserve", 0, "extra addresses added to every host count (gateway, FHRP peers, ...)")
	allow31 := fs.Bool("allow-31", false, "use /31 (RFC 3021) for 2 hosts and /32 for 1 host")
	v6len := fs.Int("v6-len", 64, "longest IPv6 prefix for host-count requests (0 = exact size)")
	order := fs.String("order", "size", "allocation order: size (largest first) or input")
	gateway := fs.String("gateway", "first", "gateway convention shown in the output: first, last or none")
	format := fs.String("format", "text", "output: text, json, csv or netbox (CSV ready for NetBox prefix import)")
	jsonOut := fs.Bool("json", false, "same as --format json")
	vrf := fs.String("vrf", "", "only --used entries of this VRF consume space; also written in --format netbox output")
	nbStatus := fs.String("netbox-status", "reserved", "status written in --format netbox output")
	color := fs.String("color", "auto", "colorize text output: auto, always, never")
	pos, code, ok := parseFlags(fs, args)
	if !ok {
		return code
	}
	if *jsonOut {
		*format = "json"
	}
	col, err := newColorizer(*color, env)
	if err != nil {
		return usageErr(env, "plan", "%v", err)
	}
	switch *format {
	case "text", "json", "csv", "netbox":
	default:
		return usageErr(env, "plan", "--format must be text, json, csv or netbox")
	}
	if *order != "size" && *order != "input" {
		return usageErr(env, "plan", "--order must be size or input")
	}
	if *gateway != "first" && *gateway != "last" && *gateway != "none" {
		return usageErr(env, "plan", "--gateway must be first, last or none")
	}
	if *growth < 0 || *reserve < 0 {
		return usageErr(env, "plan", "--growth and --reserve must not be negative")
	}
	if *v6len < 0 || *v6len > 128 {
		return usageErr(env, "plan", "--v6-len must be between 0 and 128")
	}
	if *parentS == "" {
		return usageErr(env, "plan", "--parent is required (e.g. --parent 10.20.0.0/16)")
	}
	parent, hostBits, err := parsePrefixWithBits(*parentS)
	if err != nil {
		return usageErr(env, "plan", "--parent: %v", err)
	}
	if hostBits {
		fmt.Fprintf(env.Stderr, "subnet-planner plan: --parent %s has host bits set, using %s\n", *parentS, parent)
	}

	var reqs []plan.Request
	for _, a := range pos {
		r, err := plan.ParseRequest(a, len(reqs))
		if err != nil {
			return usageErr(env, "plan", "%v", err)
		}
		reqs = append(reqs, r)
	}
	for _, f := range reqFiles {
		rs, err := readRequestFile(f, env, len(reqs))
		if err != nil {
			return usageErr(env, "plan", "%s: %v", f, err)
		}
		reqs = append(reqs, rs...)
	}
	if len(reqs) == 0 {
		return usageErr(env, "plan", "no requests (give NAME=SIZE arguments or -f FILE)")
	}

	var usedPrefixes []netip.Prefix
	if len(used) > 0 {
		inv, err := loadFiles(used, env)
		if err != nil {
			return usageErr(env, "plan", "--used: %v", err)
		}
		for _, p := range inv.Problems {
			fmt.Fprintf(env.Stderr, "subnet-planner plan: %s:%d: %s (ignored)\n", p.Source, p.Line, p.Message)
		}
		for _, e := range inv.Entries {
			if *vrf != "" && e.VRF != *vrf {
				continue // other VRFs do not consume this VRF's space
			}
			// Address rows consume their own address only.
			if e.Kind == inventory.KindAddress {
				usedPrefixes = append(usedPrefixes, netip.PrefixFrom(e.Addr, e.Addr.BitLen()))
				continue
			}
			if isAncestor(e.Prefix, parent) {
				continue // the parent's own record or one of its containers
			}
			usedPrefixes = append(usedPrefixes, e.Prefix)
		}
	}
	for _, x := range exclude {
		p, err := parsePrefixArg(x)
		if err != nil {
			return usageErr(env, "plan", "--exclude: %v", err)
		}
		usedPrefixes = append(usedPrefixes, p)
	}

	res, err := plan.Plan(parent, usedPrefixes, reqs, plan.Options{
		Growth: *growth, Reserve: *reserve, Allow31: *allow31, V6Len: *v6len,
		InputOrder: *order == "input", Gateway: *gateway,
	})
	if err != nil {
		return usageErr(env, "plan", "%v", err)
	}

	switch *format {
	case "json":
		if err := writeJSON(env.Stdout, res); err != nil {
			return ExitUnknown
		}
	case "csv", "netbox":
		writePlanCSV(env, res, *format == "netbox", *vrf, *nbStatus)
	default:
		renderPlan(env, res, col)
	}

	exit := ExitOK
	for _, a := range res.Allocations {
		if a.Warning != "" && exit < ExitWarning {
			exit = ExitWarning
		}
	}
	if res.Failed() > 0 {
		exit = ExitCritical
	}
	return exit
}

func parsePrefixWithBits(s string) (netip.Prefix, bool, error) {
	if !strings.Contains(s, "/") {
		return netip.Prefix{}, false, fmt.Errorf("%q is not a prefix (missing /length)", s)
	}
	return inventory.ParsePrefix(s)
}

// isAncestor reports whether p is parent itself or contains it: such
// inventory rows describe the space being planned, they do not consume it.
func isAncestor(p, parent netip.Prefix) bool {
	return p.Bits() <= parent.Bits() && ipmath.PrefixRange(p).Contains(ipmath.PrefixRange(parent))
}

func readRequestFile(path string, env Env, first int) ([]plan.Request, error) {
	if path == "-" {
		return plan.ReadRequests(env.Stdin, first)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return plan.ReadRequests(f, first)
}

func renderPlan(env Env, res plan.Result, col colorizer) {
	w := env.Stdout
	fmt.Fprintf(w, "%s %s (%s addresses)\n", col.bold("Parent"), res.Parent, human(res.ParentSize))
	if len(res.InUse) > 0 {
		fmt.Fprintf(w, "In use: %d prefixes excluded\n", len(res.InUse))
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tREQUESTED\tPREFIX\tUSABLE RANGE\tGATEWAY\tUSABLE\tUSE")
	for _, a := range res.Allocations {
		if !a.OK() {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t\t\t\n", a.Name, a.Requested, col.red("NOT ALLOCATED"), a.Error)
			continue
		}
		util := ""
		switch {
		case a.Utilization >= 0.01:
			util = fmt.Sprintf("%.0f%%", a.Utilization*100)
		case a.Utilization > 0:
			util = "<1%"
		}
		gw := a.Gateway
		if gw == "" {
			gw = "-"
		}
		name := a.Name
		if a.VLAN != "" {
			name += " (vlan " + a.VLAN + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s - %s\t%s\t%s\t%s\n", name, a.Requested, col.green(a.Prefix.String()),
			a.FirstUsable, a.LastUsable, gw, human(a.Usable), util)
	}
	tw.Flush()
	for _, a := range res.Allocations {
		if a.Warning != "" {
			fmt.Fprintf(w, "%s %s: %s\n", col.yellow("WARNING"), a.Name, a.Warning)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Allocated %s of %s addresses; %s free in %d block(s)\n",
		human(res.Allocated), human(res.ParentSize), human(res.FreeSize), len(res.Free))
	const maxFree = 16
	for i, p := range res.Free {
		if i == maxFree {
			fmt.Fprintf(w, "  ... %d more (use --json for the full list)\n", len(res.Free)-maxFree)
			break
		}
		fmt.Fprintf(w, "  free %s\n", p)
	}
	if n := res.Failed(); n > 0 {
		fmt.Fprintf(w, "%s %d request(s) not allocated", col.red("CRITICAL"), n)
		if res.MinParentLen >= 0 {
			fmt.Fprintf(w, "; all requests together need at least a /%d", res.MinParentLen)
			if res.MinParentLen < res.Parent.Bits() {
				fmt.Fprint(w, " (larger than the parent)")
			} else if len(res.InUse) > 0 {
				fmt.Fprint(w, " of contiguous free space")
			}
		}
		fmt.Fprintln(w)
	}
}

func writePlanCSV(env Env, res plan.Result, netbox bool, vrf, status string) {
	cw := csv.NewWriter(env.Stdout)
	if netbox {
		header := []string{"prefix", "status", "description"}
		if vrf != "" {
			header = append(header, "vrf")
		}
		_ = cw.Write(header)
		for _, a := range res.Allocations {
			if !a.OK() {
				continue
			}
			desc := a.Name
			if a.Note != "" {
				desc += " - " + a.Note
			}
			row := []string{a.Prefix.String(), status, desc}
			if vrf != "" {
				row = append(row, vrf)
			}
			_ = cw.Write(row)
		}
	} else {
		_ = cw.Write([]string{"name", "requested", "prefix", "netmask", "first_usable", "last_usable", "broadcast", "gateway", "usable", "vlan", "note", "error"})
		for _, a := range res.Allocations {
			prefix := ""
			if a.OK() {
				prefix = a.Prefix.String()
			}
			_ = cw.Write([]string{a.Name, a.Requested, prefix, a.Netmask, a.FirstUsable, a.LastUsable, a.Broadcast, a.Gateway, a.Usable.String(), a.VLAN, a.Note, a.Error})
		}
	}
	cw.Flush()
}

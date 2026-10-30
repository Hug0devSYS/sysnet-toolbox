package cli

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/check"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/inventory"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
)

// --- check ------------------------------------------------------------------

const checkHead = `subnet-planner check - find conflicts in prefix and IP address inventories

Usage:
  subnet-planner check netbox-prefixes.csv [netbox-ip-addresses.csv ...]
  curl -s -H "Authorization: Token $NETBOX_TOKEN" \
    "https://netbox/api/ipam/prefixes/?limit=0" | subnet-planner check -

Inputs: NetBox CSV exports (prefixes and/or IP addresses), any CSV with a
prefix/network/subnet/cidr or address column (',' ';' or tab separated),
NetBox API JSON ({"results": [...]}), subnet-planner plan --json output, or
plain lists (one prefix per line, '#' comments). Columns vrf, status, role,
description/name, vlan and site are used when present.

Checks, per VRF: duplicate prefixes (critical), nested prefixes (allowed
under a "container" parent; see --nesting), prefixes with host bits set,
duplicate IP addresses (critical, except shared roles such as anycast/vrrp),
addresses outside every documented prefix, address masks that disagree with
their subnet, network/broadcast/subnet-router anycast addresses assigned to
hosts, invalid rows. --cross-vrf also reports overlaps between VRFs.

Flags:
`

const checkTail = `
Exit codes: 0 clean, 1 warnings, 2 critical findings, 3 unreadable input.
`

func runCheck(args []string, env Env) int {
	fs := newFlagSet("check", checkHead, checkTail, env)
	jsonOut := fs.Bool("json", false, "JSON report on stdout")
	nesting := fs.String("nesting", "auto", "nested prefixes: auto (allowed under containers), allow, deny (critical)")
	ignoreVRF := fs.Bool("ignore-vrf", false, "analyse every row as one routing table")
	crossVRF := fs.Bool("cross-vrf", false, "also report overlaps between different VRFs")
	shared := fs.String("shared-roles", strings.Join(check.DefaultSharedRoles, ","), "address roles that may be duplicated (comma separated)")
	quiet := fs.Bool("q", false, "print only the summary line")
	color := fs.String("color", "auto", "colorize text output: auto, always, never")
	pos, code, ok := parseFlags(fs, args)
	if !ok {
		return code
	}
	col, err := newColorizer(*color, env)
	if err != nil {
		return usageErr(env, "check", "%v", err)
	}
	if *nesting != check.NestingAuto && *nesting != check.NestingAllow && *nesting != check.NestingDeny {
		return usageErr(env, "check", "--nesting must be auto, allow or deny")
	}
	if len(pos) == 0 {
		if env.StdinIsTTY {
			return usageErr(env, "check", "no input files (use '-' for stdin)")
		}
		pos = []string{"-"}
	}
	inv, err := loadFiles(pos, env)
	if err != nil {
		return usageErr(env, "check", "%v", err)
	}
	var roles []string
	for _, r := range strings.Split(*shared, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, strings.ToLower(r))
		}
	}
	if roles == nil {
		roles = []string{}
	}
	rep := check.Analyze(inv, check.Options{Nesting: *nesting, IgnoreVRF: *ignoreVRF, CrossVRF: *crossVRF, SharedRoles: roles})

	if *jsonOut {
		out := struct {
			check.Report
			Status string `json:"status"`
		}{rep, statusWord(rep)}
		if out.Findings == nil {
			out.Findings = []check.Finding{}
		}
		if err := writeJSON(env.Stdout, out); err != nil {
			return ExitUnknown
		}
	} else {
		renderCheck(env, rep, col, *quiet)
	}
	switch rep.Worst() {
	case check.Critical:
		return ExitCritical
	case check.Warning:
		return ExitWarning
	}
	return ExitOK
}

func statusWord(rep check.Report) string {
	switch {
	case rep.Count(check.Critical) > 0:
		return "CRITICAL"
	case rep.Count(check.Warning) > 0:
		return "WARNING"
	}
	return "OK"
}

func renderCheck(env Env, rep check.Report, col colorizer, quiet bool) {
	w := env.Stdout
	if !quiet {
		for _, f := range rep.Findings {
			sev := f.Severity.String()
			switch f.Severity {
			case check.Critical:
				sev = col.red(sev)
			case check.Warning:
				sev = col.yellow(sev)
			}
			vrf := ""
			if f.VRF != "" {
				vrf = " [vrf " + f.VRF + "]"
			}
			fmt.Fprintf(w, "%s %s%s: %s\n", sev, f.Code, vrf, f.Message)
			for _, r := range f.Refs {
				extra := []string{}
				if r.Label != "" {
					extra = append(extra, r.Label)
				}
				if r.Status != "" {
					extra = append(extra, "status "+r.Status)
				}
				tail := ""
				if len(extra) > 0 {
					tail = " (" + strings.Join(extra, "; ") + ")"
				}
				fmt.Fprintf(w, "    %s  %s%s\n", col.dim(r.Where), r.Raw, tail)
			}
		}
		if len(rep.Findings) > 0 {
			fmt.Fprintln(w)
		}
	}
	var parts []string
	for _, v := range rep.VRFs {
		parts = append(parts, fmt.Sprintf("%s: %d prefixes, %d addresses", v.VRF, v.Prefixes, v.Addresses))
	}
	st := statusWord(rep)
	switch st {
	case "CRITICAL":
		st = col.red(st)
	case "WARNING":
		st = col.yellow(st)
	default:
		st = col.green(st)
	}
	fmt.Fprintf(w, "%s - %d entries checked, %d critical, %d warning(s)", st, rep.Entries, rep.Count(check.Critical), rep.Count(check.Warning))
	if len(parts) > 0 {
		fmt.Fprintf(w, " | %s", strings.Join(parts, "; "))
	}
	fmt.Fprintln(w)
}

// --- aggregate ----------------------------------------------------------------

const aggHead = `subnet-planner aggregate - summarise a list of prefixes

Usage:
  subnet-planner aggregate 10.0.0.0/24 10.0.1.0/24 10.0.2.0/23
  subnet-planner aggregate -f customer-routes.txt --max 8 --format cisco --name CUSTOMER-IN

Without --max the output covers exactly the same addresses as the input with
the fewest prefixes (nested and duplicate prefixes removed, siblings merged).
With --max N each address family is reduced to at most N prefixes by
merging neighbours into their common supernet, always picking the merge that
adds the fewest addresses that were not in the input; the extra space is
reported. Bare addresses are read as host routes.

Flags:
`

func runAggregate(args []string, env Env) int {
	fs := newFlagSet("aggregate", aggHead, "\nExit codes: 0 OK, 1 invalid input lines skipped, 3 usage or input error.\n", env)
	var files stringList
	fs.Var(&files, "f", "read prefixes from a file (list, CSV, JSON; '-' = stdin); repeatable")
	max := fs.Int("max", 0, "at most N prefixes per address family (lossy, see above)")
	format := fs.String("format", "plain", "output: plain, cisco, junos or json")
	jsonOut := fs.Bool("json", false, "same as --format json")
	name := fs.String("name", "AGGREGATE", "prefix-list name for --format cisco/junos")
	pos, code, ok := parseFlags(fs, args)
	if !ok {
		return code
	}
	if *jsonOut {
		*format = "json"
	}
	switch *format {
	case "plain", "cisco", "junos", "json":
	default:
		return usageErr(env, "aggregate", "--format must be plain, cisco, junos or json")
	}
	if *max < 0 {
		return usageErr(env, "aggregate", "--max must not be negative")
	}
	if len(pos) == 0 && len(files) == 0 {
		if env.StdinIsTTY {
			return usageErr(env, "aggregate", "no prefixes (give them as arguments, with -f FILE or on stdin)")
		}
		files = append(files, "-")
	}
	var in []netip.Prefix
	var problems []string
	for _, a := range pos {
		p, err := parsePrefixArg(a)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		in = append(in, p)
	}
	if len(files) > 0 {
		inv, err := loadFiles(files, env)
		if err != nil {
			return usageErr(env, "aggregate", "%v", err)
		}
		for _, p := range inv.Problems {
			problems = append(problems, fmt.Sprintf("%s:%d: %s", p.Source, p.Line, p.Message))
		}
		for _, e := range inv.Entries {
			if e.Kind == inventory.KindAddress {
				in = append(in, netip.PrefixFrom(e.Addr, e.Addr.BitLen()))
			} else {
				in = append(in, e.Prefix)
			}
		}
	}
	for _, p := range problems {
		fmt.Fprintf(env.Stderr, "subnet-planner aggregate: skipped: %s\n", p)
	}
	if len(in) == 0 {
		return usageErr(env, "aggregate", "no valid prefixes")
	}
	res := ipmath.LooseAggregate(in, *max)
	switch *format {
	case "json":
		out := struct {
			Input    int            `json:"input_prefixes"`
			Output   int            `json:"output_prefixes"`
			Prefixes []netip.Prefix `json:"prefixes"`
			ExtraV4  ipmath.U128    `json:"extra_ipv4_addresses"`
			ExtraV6  ipmath.U128    `json:"extra_ipv6_addresses"`
			Exact    bool           `json:"exact"`
			Skipped  []string       `json:"skipped,omitempty"`
		}{len(in), len(res.Prefixes), res.Prefixes, res.ExtraV4, res.ExtraV6, res.ExtraV4.IsZero() && res.ExtraV6.IsZero(), problems}
		if err := writeJSON(env.Stdout, out); err != nil {
			return ExitUnknown
		}
	case "cisco":
		seq4, seq6 := 5, 5
		for _, p := range res.Prefixes {
			if p.Addr().Is4() {
				fmt.Fprintf(env.Stdout, "ip prefix-list %s seq %d permit %s\n", *name, seq4, p)
				seq4 += 5
			} else {
				fmt.Fprintf(env.Stdout, "ipv6 prefix-list %s seq %d permit %s\n", *name, seq6, p)
				seq6 += 5
			}
		}
	case "junos":
		for _, p := range res.Prefixes {
			fmt.Fprintf(env.Stdout, "set policy-options prefix-list %s %s\n", *name, p)
		}
	default:
		for _, p := range res.Prefixes {
			fmt.Fprintln(env.Stdout, p)
		}
	}
	if *format != "json" {
		msg := fmt.Sprintf("%d prefixes in, %d out", len(in), len(res.Prefixes))
		if !res.ExtraV4.IsZero() || !res.ExtraV6.IsZero() {
			msg += fmt.Sprintf(" (lossy: +%s IPv4 and +%s IPv6 addresses not in the input)", human(res.ExtraV4), human(res.ExtraV6))
		}
		fmt.Fprintf(env.Stderr, "subnet-planner aggregate: %s\n", msg)
	}
	if len(problems) > 0 {
		return ExitWarning
	}
	return ExitOK
}

// --- free -----------------------------------------------------------------------

const freeHead = `subnet-planner free - unallocated space of a parent prefix

Usage:
  subnet-planner free --parent 10.20.0.0/16 --used netbox-prefixes.csv
  subnet-planner free --parent 10.20.0.0/16 --used prefixes.txt --split 24 --limit 10

Flags:
`

func runFree(args []string, env Env) int {
	fs := newFlagSet("free", freeHead, "\nExit codes: 0 free space found, 1 none (of the requested size), 3 usage or input error.\n", env)
	parentS := fs.String("parent", "", "parent prefix (required; may also be given as the first argument)")
	var used, exclude stringList
	fs.Var(&used, "used", "inventory of prefixes in use (CSV/NetBox, JSON, list; '-' = stdin); repeatable")
	fs.Var(&exclude, "exclude", "prefix in use; repeatable")
	vrf := fs.String("vrf", "", "only --used entries of this VRF consume space")
	split := fs.Int("split", -1, "list free space as subnets of this prefix length (smaller free blocks are omitted)")
	limit := fs.Int("limit", 256, "maximum number of blocks printed (0 = no limit)")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, code, ok := parseFlags(fs, args)
	if !ok {
		return code
	}
	if *parentS == "" && len(pos) > 0 {
		*parentS, pos = pos[0], pos[1:]
	}
	if *parentS == "" {
		return usageErr(env, "free", "--parent is required")
	}
	exclude = append(exclude, pos...)
	parent, err := parsePrefixArg(*parentS)
	if err != nil {
		return usageErr(env, "free", "--parent: %v", err)
	}
	pr := ipmath.PrefixRange(parent)
	if *split >= 0 && (*split < parent.Bits() || *split > pr.Bits()) {
		return usageErr(env, "free", "--split must be between /%d and /%d", parent.Bits(), pr.Bits())
	}
	var usedR []ipmath.Range
	if len(used) > 0 {
		inv, err := loadFiles(used, env)
		if err != nil {
			return usageErr(env, "free", "--used: %v", err)
		}
		for _, p := range inv.Problems {
			fmt.Fprintf(env.Stderr, "subnet-planner free: %s:%d: %s (ignored)\n", p.Source, p.Line, p.Message)
		}
		for _, e := range inv.Entries {
			if *vrf != "" && e.VRF != *vrf {
				continue
			}
			p := e.Prefix
			if e.Kind == inventory.KindAddress {
				p = netip.PrefixFrom(e.Addr, e.Addr.BitLen())
			} else if isAncestor(p, parent) {
				continue
			}
			usedR = append(usedR, ipmath.PrefixRange(p))
		}
	}
	for _, x := range exclude {
		p, err := parsePrefixArg(x)
		if err != nil {
			return usageErr(env, "free", "%v", err)
		}
		usedR = append(usedR, ipmath.PrefixRange(p))
	}
	free := ipmath.Subtract([]ipmath.Range{pr}, usedR)
	var blocks []netip.Prefix
	var total ipmath.U128
	truncated := false
	for _, r := range free {
		total = total.SatAdd(r.Count())
		for _, b := range r.ToPrefixes() {
			if *split < 0 {
				if *limit > 0 && len(blocks) >= *limit {
					truncated = true
					continue
				}
				blocks = append(blocks, b)
				continue
			}
			if b.Bits() > *split {
				continue
			}
			// Enumerate the /split subnets of b.
			br := ipmath.PrefixRange(b)
			step := ipmath.PrefixSize(*split, br.V6)
			for cur := br.Start; ; {
				if *limit > 0 && len(blocks) >= *limit {
					truncated = true
					break
				}
				blocks = append(blocks, ipmath.PrefixOf(cur, *split, br.V6))
				next, ovf := cur.Add(step)
				if ovf || next.Cmp(br.End) > 0 {
					break
				}
				cur = next
			}
		}
	}
	if *jsonOut {
		out := struct {
			Parent    netip.Prefix   `json:"parent"`
			Free      []netip.Prefix `json:"free"`
			FreeSize  ipmath.U128    `json:"free_addresses"`
			Truncated bool           `json:"truncated"`
		}{parent, blocks, total, truncated}
		if out.Free == nil {
			out.Free = []netip.Prefix{}
		}
		if err := writeJSON(env.Stdout, out); err != nil {
			return ExitUnknown
		}
	} else {
		for _, b := range blocks {
			fmt.Fprintln(env.Stdout, b)
		}
		msg := fmt.Sprintf("%s of %s addresses free in %s", human(total), human(pr.Count()), parent)
		if truncated {
			msg += fmt.Sprintf(" (output limited to %d blocks)", *limit)
		}
		fmt.Fprintf(env.Stderr, "subnet-planner free: %s\n", msg)
	}
	if len(blocks) == 0 {
		return ExitWarning
	}
	return ExitOK
}

// --- info -----------------------------------------------------------------------

const infoHead = `subnet-planner info - subnet calculator

Usage:
  subnet-planner info 192.168.10.37/26 2001:db8:42::/48
  subnet-planner info 10.20.0.0/22 --split 24
  subnet-planner info 10.1.2.3/255.255.255.240

Flags:
`

type infoResult struct {
	Input        string              `json:"input"`
	Address      string              `json:"address,omitempty"`
	Prefix       netip.Prefix        `json:"prefix"`
	Family       string              `json:"family"`
	Netmask      string              `json:"netmask,omitempty"`
	Wildcard     string              `json:"wildcard,omitempty"`
	Network      string              `json:"network"`
	Broadcast    string              `json:"broadcast,omitempty"`
	FirstUsable  string              `json:"first_usable"`
	LastUsable   string              `json:"last_usable"`
	Total        ipmath.U128         `json:"total_addresses"`
	Usable       ipmath.U128         `json:"usable_addresses"`
	Type         string              `json:"type,omitempty"`
	TypeRFC      string              `json:"type_rfc,omitempty"`
	Routable     *bool               `json:"globally_routable,omitempty"`
	ReverseZones ipmath.ReverseZones `json:"reverse_zones"`
	Subnets      []netip.Prefix      `json:"subnets,omitempty"`
	SubnetCount  *ipmath.U128        `json:"subnet_count,omitempty"`
}

func runInfo(args []string, env Env) int {
	fs := newFlagSet("info", infoHead, "\nExit codes: 0 OK, 3 invalid input.\n", env)
	split := fs.Int("split", -1, "also list the subnets of this prefix length")
	limit := fs.Int("limit", 64, "maximum number of subnets / reverse zones listed")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, code, ok := parseFlags(fs, args)
	if !ok {
		return code
	}
	if len(pos) == 0 {
		return usageErr(env, "info", "give at least one prefix or address")
	}
	if *limit <= 0 {
		*limit = 1 << 20
	}
	var results []infoResult
	for _, a := range pos {
		e, err := inventory.Load("arg", strings.NewReader(a))
		if err != nil || len(e.Entries) != 1 {
			return usageErr(env, "info", "%q is not a valid prefix or address", a)
		}
		in := e.Entries[0]
		addr, _, _ := strings.Cut(strings.TrimSpace(a), "/")
		r, err := info(in.Prefix, a, addr, in.HostBits, *split, *limit)
		if err != nil {
			return usageErr(env, "info", "%v", err)
		}
		results = append(results, r)
	}
	if *jsonOut {
		if err := writeJSON(env.Stdout, results); err != nil {
			return ExitUnknown
		}
		return ExitOK
	}
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(env.Stdout)
		}
		renderInfo(env, r)
	}
	return ExitOK
}

func info(p netip.Prefix, raw, addr string, hostBits bool, split, limit int) (infoResult, error) {
	r := ipmath.PrefixRange(p)
	bitsLen := r.Bits()
	res := infoResult{Input: raw, Prefix: p, Total: r.Count(), Network: ipmath.ToAddr(r.Start, r.V6).String()}
	if hostBits {
		res.Address = addr
	}
	first, last, usable := r.Start, r.End, r.Count()
	one := ipmath.FromUint64(1)
	if r.V6 {
		res.Family = "IPv6"
		if p.Bits() <= 126 {
			first, _ = first.Add(one)
			usable, _ = usable.Sub(one)
		}
	} else {
		res.Family = "IPv4"
		mask := ipmath.LowMask(32).And(ipmath.LowMask(32 - p.Bits()).Not())
		res.Netmask = ipmath.ToAddr(mask, false).String()
		res.Wildcard = ipmath.ToAddr(ipmath.LowMask(32-p.Bits()), false).String()
		if p.Bits() <= 30 {
			first, _ = first.Add(one)
			last, _ = last.Sub(one)
			usable, _ = usable.Sub(ipmath.FromUint64(2))
			res.Broadcast = ipmath.ToAddr(r.End, false).String()
		}
	}
	res.FirstUsable = ipmath.ToAddr(first, r.V6).String()
	res.LastUsable = ipmath.ToAddr(last, r.V6).String()
	res.Usable = usable
	if sb, ok := ipmath.Classify(p); ok {
		res.Type, res.TypeRFC = sb.Name, sb.RFC
		g := sb.Global
		res.Routable = &g
	} else {
		res.Type = "mixed (spans several special-purpose blocks)"
	}
	res.ReverseZones = ipmath.ReverseDNSZones(p, limit)
	if split >= 0 {
		if split < p.Bits() || split > bitsLen {
			return res, fmt.Errorf("--split /%d must be between /%d and /%d for %s", split, p.Bits(), bitsLen, p)
		}
		n := ipmath.Pow2(split - p.Bits())
		res.SubnetCount = &n
		step := ipmath.PrefixSize(split, r.V6)
		cur := r.Start
		for i := 0; i < limit; i++ {
			res.Subnets = append(res.Subnets, ipmath.PrefixOf(cur, split, r.V6))
			next, ovf := cur.Add(step)
			if ovf || next.Cmp(r.End) > 0 {
				break
			}
			cur = next
		}
	}
	return res, nil
}

func renderInfo(env Env, r infoResult) {
	w := env.Stdout
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-14s %s\n", k+":", v)
		}
	}
	row("Address", r.Address)
	row("Prefix", r.Prefix.String())
	row("Netmask", r.Netmask)
	row("Wildcard", r.Wildcard)
	row("Network", r.Network)
	row("Broadcast", r.Broadcast)
	row("Usable range", r.FirstUsable+" - "+r.LastUsable)
	row("Addresses", fmt.Sprintf("%s total, %s usable", human(r.Total), human(r.Usable)))
	t := r.Type
	if r.TypeRFC != "" {
		t += " (" + r.TypeRFC + ")"
	}
	if r.Routable != nil && !*r.Routable {
		t += ", not globally routable"
	}
	row("Type", t)
	zones := strings.Join(r.ReverseZones.Zones, " ")
	if total := r.ReverseZones.Total; total.Hi != 0 || total.Lo > uint64(len(r.ReverseZones.Zones)) {
		zones += fmt.Sprintf(" ... (%s zones)", human(total))
	}
	row("Reverse DNS", zones)
	row("", "")
	if r.ReverseZones.Note != "" {
		fmt.Fprintf(w, "%-14s %s\n", "", r.ReverseZones.Note)
	}
	if len(r.Subnets) > 0 {
		fmt.Fprintf(w, "Subnets /%d (%s):\n", r.Subnets[0].Bits(), human(*r.SubnetCount))
		for _, s := range r.Subnets {
			fmt.Fprintf(w, "  %s\n", s)
		}
		if r.SubnetCount.Hi != 0 || r.SubnetCount.Lo > uint64(len(r.Subnets)) {
			fmt.Fprintf(w, "  ... (--limit to show more)\n")
		}
	}
}

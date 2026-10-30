// Package check finds duplicates, overlaps and inconsistencies in prefix
// and IP address inventories (NetBox exports, spreadsheets, plans).
package check

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/inventory"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
)

// Severity of a finding.
type Severity int

// Severities, in increasing order.
const (
	Info Severity = iota
	Warning
	Critical
)

func (s Severity) String() string {
	return [...]string{"INFO", "WARNING", "CRITICAL"}[s]
}

// MarshalJSON encodes the severity as a lower-case string.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(strings.ToLower(s.String())) }

// Nesting modes.
const (
	NestingAuto  = "auto"
	NestingAllow = "allow"
	NestingDeny  = "deny"
)

// Options tune the analysis.
type Options struct {
	// Nesting: auto (containers may hold children; without a status
	// column every nesting is a warning), allow, or deny (critical).
	Nesting string
	// IgnoreVRF analyses every entry as one routing table.
	IgnoreVRF bool
	// CrossVRF reports overlaps between different VRFs.
	CrossVRF bool
	// SharedRoles are address roles allowed to be duplicated.
	SharedRoles []string
}

// DefaultSharedRoles lists NetBox IP roles that are shared by design.
var DefaultSharedRoles = []string{"anycast", "vip", "vrrp", "hsrp", "glbp", "carp"}

// Ref points to one inventory row.
type Ref struct {
	Where  string `json:"where"`
	Raw    string `json:"raw"`
	Label  string `json:"label,omitempty"`
	VRF    string `json:"vrf,omitempty"`
	Status string `json:"status,omitempty"`
}

// Finding is one problem.
type Finding struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Prefix   string   `json:"prefix,omitempty"`
	VRF      string   `json:"vrf,omitempty"`
	Refs     []Ref    `json:"refs"`
}

// VRFStats summarises one VRF.
type VRFStats struct {
	VRF       string `json:"vrf"`
	Prefixes  int    `json:"prefixes"`
	Addresses int    `json:"addresses"`
}

// Report is the result of Analyze.
type Report struct {
	Findings []Finding  `json:"findings"`
	VRFs     []VRFStats `json:"vrfs"`
	Entries  int        `json:"entries"`
}

// Worst returns the highest severity found (Info when none).
func (r Report) Worst() Severity {
	w := Info
	for _, f := range r.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// Count returns the number of findings of severity s.
func (r Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func ref(e inventory.Entry) Ref {
	return Ref{Where: e.Where(), Raw: e.Raw, Label: e.Label(), VRF: e.VRF, Status: e.Status}
}

func vrfName(v string) string {
	if v == "" {
		return "global"
	}
	return v
}

// Analyze runs every check on inv.
func Analyze(inv inventory.Result, opt Options) Report {
	if opt.Nesting == "" {
		opt.Nesting = NestingAuto
	}
	if opt.SharedRoles == nil {
		opt.SharedRoles = DefaultSharedRoles
	}
	rep := Report{Entries: len(inv.Entries)}
	add := func(f Finding) { rep.Findings = append(rep.Findings, f) }

	for _, p := range inv.Problems {
		add(Finding{Severity: Warning, Code: "invalid-entry", Message: p.Message,
			Refs: []Ref{{Where: fmt.Sprintf("%s:%d", p.Source, p.Line), Raw: p.Raw}}})
	}

	byVRF := map[string][]inventory.Entry{}
	for _, e := range inv.Entries {
		if opt.IgnoreVRF {
			e.VRF = ""
		}
		byVRF[e.VRF] = append(byVRF[e.VRF], e)
	}
	vrfs := make([]string, 0, len(byVRF))
	for v := range byVRF {
		vrfs = append(vrfs, v)
	}
	sort.Strings(vrfs)
	anyPrefixes := false
	for _, e := range inv.Entries {
		if e.Kind == inventory.KindPrefix {
			anyPrefixes = true
			break
		}
	}

	for _, v := range vrfs {
		var prefixes, addrs []inventory.Entry
		for _, e := range byVRF[v] {
			if e.Kind == inventory.KindPrefix {
				prefixes = append(prefixes, e)
			} else {
				addrs = append(addrs, e)
			}
		}
		rep.VRFs = append(rep.VRFs, VRFStats{VRF: vrfName(v), Prefixes: len(prefixes), Addresses: len(addrs)})
		tree := checkPrefixes(v, prefixes, inv.HasStatus, opt, add)
		checkAddresses(v, addrs, tree, anyPrefixes, opt, add)
	}
	if opt.CrossVRF && !opt.IgnoreVRF {
		checkCrossVRF(inv.Entries, add)
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Severity > rep.Findings[j].Severity })
	return rep
}

// node is a unique prefix of one VRF with every row that declares it.
type node struct {
	prefix netip.Prefix
	rng    ipmath.Range
	rows   []inventory.Entry
	parent *node
}

func (n *node) status() string {
	for _, r := range n.rows {
		if r.Status != "" {
			return r.Status
		}
	}
	return ""
}

func sortNodes(nodes []*node) {
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i].rng, nodes[j].rng
		if a.V6 != b.V6 {
			return !a.V6
		}
		if c := a.Start.Cmp(b.Start); c != 0 {
			return c < 0
		}
		return a.End.Cmp(b.End) > 0 // parents before children
	})
}

func checkPrefixes(vrf string, entries []inventory.Entry, hasStatus bool, opt Options, add func(Finding)) []*node {
	index := map[netip.Prefix]*node{}
	var nodes []*node
	for _, e := range entries {
		if e.HostBits {
			add(Finding{Severity: Warning, Code: "host-bits-set", Prefix: e.Prefix.String(), VRF: vrfName(vrf),
				Message: fmt.Sprintf("%s has host bits set; read as %s (an address with a mask belongs in the address list)", e.Raw, e.Prefix),
				Refs:    []Ref{ref(e)}})
		}
		n, ok := index[e.Prefix]
		if !ok {
			n = &node{prefix: e.Prefix, rng: ipmath.PrefixRange(e.Prefix)}
			index[e.Prefix] = n
			nodes = append(nodes, n)
		}
		n.rows = append(n.rows, e)
	}
	sortNodes(nodes)
	for _, n := range nodes {
		if len(n.rows) > 1 {
			refs := make([]Ref, 0, len(n.rows))
			for _, r := range n.rows {
				refs = append(refs, ref(r))
			}
			add(Finding{Severity: Critical, Code: "duplicate-prefix", Prefix: n.prefix.String(), VRF: vrfName(vrf),
				Message: fmt.Sprintf("%s is declared %d times in VRF %s", n.prefix, len(n.rows), vrfName(vrf)), Refs: refs})
		}
	}
	var stack []*node
	for _, n := range nodes {
		for len(stack) > 0 && !stack[len(stack)-1].rng.Contains(n.rng) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			n.parent = stack[len(stack)-1]
		}
		stack = append(stack, n)
		if n.parent != nil && opt.Nesting != NestingAllow {
			parent := n.parent
			ps := parent.status()
			sev, code := Warning, "overlap"
			msg := fmt.Sprintf("%s overlaps %s (nested inside it)", n.prefix, parent.prefix)
			switch {
			case opt.Nesting == NestingDeny:
				sev = Critical
			case ps == "container":
				sev = -1
			case ps != "":
				code = "nested-in-assigned"
				msg = fmt.Sprintf("%s is nested inside %s, whose status is %q (only containers should hold child prefixes)", n.prefix, parent.prefix, ps)
			case hasStatus:
				msg += "; the parent has no status (mark it as a container if this is intended)"
			}
			if sev >= 0 {
				add(Finding{Severity: sev, Code: code, Prefix: n.prefix.String(), VRF: vrfName(vrf), Message: msg,
					Refs: []Ref{ref(n.rows[0]), ref(parent.rows[0])}})
			}
		}
	}
	return nodes
}

// mostSpecific returns the longest prefix node containing r. nodes must be
// one family, sorted by sortNodes, with parent links set: the last node
// starting at or before r is nested in every prefix containing r, so the
// answer is on its parent chain.
func mostSpecific(nodes []*node, r ipmath.Range) *node {
	i := sort.Search(len(nodes), func(i int) bool { return nodes[i].rng.Start.Cmp(r.Start) > 0 }) - 1
	if i < 0 {
		return nil
	}
	for n := nodes[i]; n != nil; n = n.parent {
		if n.rng.Contains(r) {
			return n
		}
	}
	return nil
}

func checkAddresses(vrf string, addrs []inventory.Entry, nodes []*node, anyPrefixes bool, opt Options, add func(Finding)) {
	shared := map[string]bool{}
	for _, r := range opt.SharedRoles {
		shared[strings.ToLower(r)] = true
	}
	byAddr := map[netip.Addr][]inventory.Entry{}
	var order []netip.Addr
	for _, e := range addrs {
		if _, ok := byAddr[e.Addr]; !ok {
			order = append(order, e.Addr)
		}
		byAddr[e.Addr] = append(byAddr[e.Addr], e)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].Less(order[j]) })
	// Index prefix nodes by family to keep the containing-prefix lookup
	// cheap on large inventories.
	var v4, v6 []*node
	for _, n := range nodes {
		if n.rng.V6 {
			v6 = append(v6, n)
		} else {
			v4 = append(v4, n)
		}
	}
	for _, a := range order {
		rows := byAddr[a]
		if len(rows) > 1 {
			allShared := true
			for _, r := range rows {
				if !shared[r.Role] {
					allShared = false
				}
			}
			if !allShared {
				refs := make([]Ref, 0, len(rows))
				for _, r := range rows {
					refs = append(refs, ref(r))
				}
				add(Finding{Severity: Critical, Code: "duplicate-address", Prefix: a.String(), VRF: vrfName(vrf),
					Message: fmt.Sprintf("%s is assigned %d times in VRF %s (set a shared role such as anycast/vrrp if intended)", a, len(rows), vrfName(vrf)),
					Refs:    refs})
			}
		}
		e := rows[0]
		host := ipmath.PrefixRange(netip.PrefixFrom(a, a.BitLen()))
		cands := v4
		if a.Is6() {
			cands = v6
		}
		parent := mostSpecific(cands, host)
		subnet := e.Prefix
		if parent != nil {
			subnet = parent.prefix
		}
		if anyPrefixes && parent == nil {
			add(Finding{Severity: Warning, Code: "orphan-address", Prefix: a.String(), VRF: vrfName(vrf),
				Message: fmt.Sprintf("%s is not inside any documented prefix of VRF %s", e.Raw, vrfName(vrf)), Refs: []Ref{ref(e)}})
		}
		if parent != nil && !e.NoMask {
			al, pl := e.Prefix.Bits(), parent.prefix.Bits()
			hostMask := al == a.BitLen()
			switch {
			case al < pl:
				add(Finding{Severity: Warning, Code: "mask-mismatch", Prefix: a.String(), VRF: vrfName(vrf),
					Message: fmt.Sprintf("%s has a shorter mask than its subnet %s: hosts configured this way see a wrong on-link range", e.Raw, parent.prefix),
					Refs:    []Ref{ref(e), ref(parent.rows[0])}})
			case al > pl && !hostMask && parent.status() != "container":
				add(Finding{Severity: Warning, Code: "mask-mismatch", Prefix: a.String(), VRF: vrfName(vrf),
					Message: fmt.Sprintf("%s has a longer mask than its subnet %s", e.Raw, parent.prefix),
					Refs:    []Ref{ref(e), ref(parent.rows[0])}})
			}
		}
		if what := reservedAddress(a, subnet); what != "" {
			add(Finding{Severity: Warning, Code: "reserved-address", Prefix: a.String(), VRF: vrfName(vrf),
				Message: fmt.Sprintf("%s is the %s of %s", a, what, subnet), Refs: []Ref{ref(e)}})
		}
	}
}

// reservedAddress tells whether a is the network/broadcast address of an
// IPv4 subnet, or the subnet-router anycast address of an IPv6 subnet.
func reservedAddress(a netip.Addr, subnet netip.Prefix) string {
	r := ipmath.PrefixRange(subnet)
	u, _ := ipmath.FromAddr(a)
	if a.Is4() {
		if subnet.Bits() > 30 {
			return ""
		}
		if u == r.Start {
			return "network address"
		}
		if u == r.End {
			return "broadcast address"
		}
		return ""
	}
	if subnet.Bits() <= 126 && u == r.Start {
		return "subnet-router anycast address (RFC 4291)"
	}
	return ""
}

func checkCrossVRF(entries []inventory.Entry, add func(Finding)) {
	var nodes []*node
	for _, e := range entries {
		if e.Kind == inventory.KindPrefix {
			nodes = append(nodes, &node{prefix: e.Prefix, rng: ipmath.PrefixRange(e.Prefix), rows: []inventory.Entry{e}})
		}
	}
	sortNodes(nodes)
	seen := map[string]bool{}
	var stack []*node
	for _, n := range nodes {
		for len(stack) > 0 && !stack[len(stack)-1].rng.Overlaps(n.rng) {
			stack = stack[:len(stack)-1]
		}
		for _, anc := range stack {
			a, b := anc.rows[0], n.rows[0]
			if a.VRF == b.VRF {
				continue
			}
			key := a.Prefix.String() + "|" + a.VRF + "|" + b.Prefix.String() + "|" + b.VRF
			if seen[key] {
				continue
			}
			seen[key] = true
			add(Finding{Severity: Warning, Code: "cross-vrf-overlap", Prefix: b.Prefix.String(),
				Message: fmt.Sprintf("%s (VRF %s) overlaps %s (VRF %s): a conflict if routes leak between these VRFs", b.Prefix, vrfName(b.VRF), a.Prefix, vrfName(a.VRF)),
				Refs:    []Ref{ref(b), ref(a)}})
		}
		stack = append(stack, n)
	}
}

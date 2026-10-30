// Package plan implements VLSM subnet allocation for IPv4 and IPv6 inside a
// parent prefix, avoiding prefixes that are already in use.
package plan

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
)

// Request is one subnet to allocate: either a host count or an explicit
// prefix length.
type Request struct {
	Name  string `json:"name"`
	Hosts int64  `json:"hosts,omitempty"`
	// Len is the explicit prefix length, or -1 when Hosts is used.
	Len  int    `json:"-"`
	VLAN string `json:"vlan,omitempty"`
	Note string `json:"note,omitempty"`
	// Order is the position in the input (0-based).
	Order int `json:"-"`
}

// SizeString renders the request size as written.
func (r Request) SizeString() string {
	if r.Len >= 0 {
		return fmt.Sprintf("/%d", r.Len)
	}
	return fmt.Sprintf("%d hosts", r.Hosts)
}

// ParseSize parses "/26" (prefix length) or "120" (usable hosts).
func ParseSize(s string) (hosts int64, l int, err error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "/") {
		n, err := strconv.Atoi(s[1:])
		if err != nil || n < 0 || n > 128 {
			return 0, 0, fmt.Errorf("invalid prefix length %q", s)
		}
		return 0, n, nil
	}
	s = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(s), "hosts"), "h")
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return 0, 0, fmt.Errorf("invalid size %q: use a host count (e.g. 120) or a prefix length (e.g. /26)", s)
	}
	return n, -1, nil
}

// ParseRequest parses "name=SIZE".
func ParseRequest(s string, order int) (Request, error) {
	name, size, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(name) == "" {
		return Request{}, fmt.Errorf("invalid request %q: expected NAME=SIZE, e.g. users=120 or transit=/31", s)
	}
	h, l, err := ParseSize(size)
	if err != nil {
		return Request{}, fmt.Errorf("request %q: %w", s, err)
	}
	return Request{Name: strings.TrimSpace(name), Hosts: h, Len: l, Order: order}, nil
}

// ReadRequests reads one request per line: "name,size[,vlan[,note]]" (CSV,
// ';' also accepted) or "name size [vlan] [note...]". A header line whose
// size column does not parse is skipped; '#' starts a comment.
func ReadRequests(r io.Reader, first int) ([]Request, error) {
	var out []Request
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		var fields []string
		switch {
		case strings.Contains(line, ","):
			fields = strings.Split(line, ",")
		case strings.Contains(line, ";"):
			fields = strings.Split(line, ";")
		default:
			fields = strings.Fields(line)
			if len(fields) > 3 {
				fields = append(fields[:3], strings.Join(fields[3:], " "))
			}
		}
		for i := range fields {
			fields[i] = strings.Trim(strings.TrimSpace(fields[i]), `"`)
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: expected name and size", lineNo)
		}
		h, l, err := ParseSize(fields[1])
		if err != nil {
			if len(out) == 0 && lineNo <= 1 {
				continue // header
			}
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		req := Request{Name: fields[0], Hosts: h, Len: l, Order: first + len(out)}
		if len(fields) > 2 {
			req.VLAN = fields[2]
		}
		if len(fields) > 3 {
			req.Note = strings.Join(fields[3:], ",")
		}
		if req.Name == "" {
			return nil, fmt.Errorf("line %d: empty name", lineNo)
		}
		out = append(out, req)
	}
	return out, sc.Err()
}

// Options tune sizing and allocation.
type Options struct {
	// Growth adds a percentage to every host count (e.g. 20 for +20%).
	Growth float64
	// Reserve adds addresses to every host count (gateway, FHRP peers...).
	Reserve int64
	// Allow31 permits /31 (RFC 3021) and /32 for 2 and 1 hosts.
	Allow31 bool
	// V6Len is the longest prefix used for IPv6 host-count requests
	// (64: SLAAC needs a /64). 0 means size IPv6 subnets exactly.
	V6Len int
	// InputOrder allocates in input order instead of largest first.
	InputOrder bool
	// Gateway is "first", "last" or "none".
	Gateway string
}

// Allocation is the outcome of one request.
type Allocation struct {
	Request
	Requested   string       `json:"requested"`
	Need        int64        `json:"need,omitempty"`
	PrefixLen   int          `json:"prefix_length"`
	Prefix      netip.Prefix `json:"prefix,omitempty"`
	Netmask     string       `json:"netmask,omitempty"`
	FirstUsable string       `json:"first_usable,omitempty"`
	LastUsable  string       `json:"last_usable,omitempty"`
	Broadcast   string       `json:"broadcast,omitempty"`
	Gateway     string       `json:"gateway,omitempty"`
	Usable      ipmath.U128  `json:"usable"`
	// Utilization is the share of usable addresses taken by the requested
	// hosts (before growth and reserve), when the request was a host count.
	Utilization float64 `json:"utilization,omitempty"`
	Error       string  `json:"error,omitempty"`
	Warning     string  `json:"warning,omitempty"`
}

// OK reports whether the request was allocated.
func (a Allocation) OK() bool { return a.Error == "" }

// Result of a plan.
type Result struct {
	Parent      netip.Prefix   `json:"parent"`
	ParentSize  ipmath.U128    `json:"parent_size"`
	InUse       []netip.Prefix `json:"in_use,omitempty"`
	Allocations []Allocation   `json:"allocations"`
	Allocated   ipmath.U128    `json:"allocated_addresses"`
	Free        []netip.Prefix `json:"free"`
	FreeSize    ipmath.U128    `json:"free_addresses"`
	// MinParentLen is the longest parent prefix that would hold every
	// request if it were empty (-1 if none).
	MinParentLen int `json:"min_parent_length"`
}

// Failed returns the number of requests that could not be allocated.
func (r Result) Failed() int {
	n := 0
	for _, a := range r.Allocations {
		if !a.OK() {
			n++
		}
	}
	return n
}

// ErrNoRequests is returned by Plan when there is nothing to allocate.
var ErrNoRequests = errors.New("no subnet requests")

// PrefixLenFor computes the prefix length of a host-count request.
func PrefixLenFor(hosts int64, v6 bool, opt Options) (int, int64, error) {
	need := int64(math.Ceil(float64(hosts) * (1 + opt.Growth/100)))
	need += opt.Reserve
	if need <= 0 {
		return 0, 0, fmt.Errorf("non-positive address count")
	}
	if v6 {
		l := 128 - bits.Len64(uint64(need-1))
		if opt.V6Len > 0 && l > opt.V6Len {
			l = opt.V6Len
		}
		return l, need, nil
	}
	if opt.Allow31 && need <= 2 {
		if need == 1 {
			return 32, need, nil
		}
		return 31, need, nil
	}
	for l := 30; l >= 0; l-- {
		if (int64(1)<<(32-l))-2 >= need {
			return l, need, nil
		}
	}
	return 0, need, fmt.Errorf("%d addresses do not fit in IPv4", need)
}

// Plan allocates reqs inside parent, skipping the used prefixes.
func Plan(parent netip.Prefix, used []netip.Prefix, reqs []Request, opt Options) (Result, error) {
	if len(reqs) == 0 {
		return Result{}, ErrNoRequests
	}
	parent = ipmath.Canonical(parent)
	v6 := parent.Addr().Is6()
	bitsLen := 32
	if v6 {
		bitsLen = 128
	}
	if opt.Gateway == "" {
		opt.Gateway = "first"
	}
	pr := ipmath.PrefixRange(parent)
	res := Result{Parent: parent, ParentSize: pr.Count(), MinParentLen: -1}

	var usedRanges []ipmath.Range
	for _, u := range used {
		ur := ipmath.PrefixRange(u)
		if ur.Overlaps(pr) {
			usedRanges = append(usedRanges, ur)
		}
	}
	for _, r := range ipmath.MergeRanges(usedRanges) {
		if r.Start.Cmp(pr.Start) < 0 {
			r.Start = pr.Start
		}
		if r.End.Cmp(pr.End) > 0 {
			r.End = pr.End
		}
		res.InUse = append(res.InUse, r.ToPrefixes()...)
	}
	free := ipmath.Subtract([]ipmath.Range{pr}, usedRanges)

	allocs := make([]Allocation, len(reqs))
	names := map[string]bool{}
	for i, rq := range reqs {
		if names[rq.Name] {
			return Result{}, fmt.Errorf("duplicate request name %q", rq.Name)
		}
		names[rq.Name] = true
		a := Allocation{Request: rq, Requested: rq.SizeString(), PrefixLen: rq.Len}
		switch {
		case rq.Len >= 0:
			if rq.Len > bitsLen {
				a.Error = fmt.Sprintf("/%d is not a valid %s prefix length", rq.Len, family(v6))
			} else if rq.Len < parent.Bits() {
				a.Error = fmt.Sprintf("/%d is larger than the parent %s", rq.Len, parent)
			}
		default:
			l, need, err := PrefixLenFor(rq.Hosts, v6, opt)
			a.Need = need
			if err != nil {
				a.Error = err.Error()
			} else {
				a.PrefixLen = l
				if l < parent.Bits() {
					a.Error = fmt.Sprintf("needs a /%d, larger than the parent %s", l, parent)
				}
			}
		}
		if v6 && a.Error == "" && a.PrefixLen > 64 && a.PrefixLen != 127 && a.PrefixLen != 128 {
			a.Warning = fmt.Sprintf("/%d: IPv6 LAN subnets should be /64 (SLAAC, RFC 7421); use /127 for point-to-point links (RFC 6164)", a.PrefixLen)
		}
		allocs[i] = a
	}

	order := make([]int, len(allocs))
	for i := range order {
		order[i] = i
	}
	if !opt.InputOrder {
		sort.SliceStable(order, func(x, y int) bool { return allocs[order[x]].PrefixLen < allocs[order[y]].PrefixLen })
	}

	// Empty-parent lower bound: buddy allocation of power-of-two blocks in
	// decreasing size always packs perfectly, so the sum rounded up to a
	// power of two is exactly the smallest parent that fits.
	total := ipmath.U128{}
	ok := true
	for _, a := range allocs {
		if a.Error != "" && a.PrefixLen < 0 {
			ok = false
			continue
		}
		if a.PrefixLen < 0 || a.PrefixLen > bitsLen {
			ok = false
			continue
		}
		var ovf bool
		total, ovf = total.Add(ipmath.PrefixSize(a.PrefixLen, v6))
		if ovf {
			ok = false
		}
	}
	if ok && !total.IsZero() {
		k := total.BitLen() - 1
		if ipmath.Pow2(k) != total {
			k++
		}
		res.MinParentLen = bitsLen - k
	}

	for _, i := range order {
		a := &allocs[i]
		if a.Error != "" {
			continue
		}
		block, found := bestFit(free, a.PrefixLen)
		if !found {
			a.Error = fmt.Sprintf("no free /%d left in %s (largest free block: %s)", a.PrefixLen, parent, largest(free))
			continue
		}
		p := netip.PrefixFrom(block.Addr(), a.PrefixLen)
		fill(a, p, opt)
		free = ipmath.Subtract(free, []ipmath.Range{ipmath.PrefixRange(p)})
		res.Allocated = res.Allocated.SatAdd(ipmath.PrefixRange(p).Count())
	}
	res.Allocations = allocs
	for _, r := range free {
		res.Free = append(res.Free, r.ToPrefixes()...)
		res.FreeSize = res.FreeSize.SatAdd(r.Count())
	}
	return res, nil
}

func family(v6 bool) string {
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

// bestFit returns the smallest free CIDR block that can hold a /l (lowest
// address on ties), keeping large blocks intact for later requests.
func bestFit(free []ipmath.Range, l int) (netip.Prefix, bool) {
	var best netip.Prefix
	found := false
	for _, r := range free {
		for _, b := range r.ToPrefixes() {
			if b.Bits() > l {
				continue
			}
			if !found || b.Bits() > best.Bits() {
				best, found = b, true
				if b.Bits() == l {
					return best, true
				}
			}
		}
	}
	return best, found
}

func largest(free []ipmath.Range) string {
	var best netip.Prefix
	found := false
	for _, r := range free {
		for _, b := range r.ToPrefixes() {
			if !found || b.Bits() < best.Bits() {
				best, found = b, true
			}
		}
	}
	if !found {
		return "none"
	}
	return best.String()
}

func fill(a *Allocation, p netip.Prefix, opt Options) {
	a.Prefix = p
	r := ipmath.PrefixRange(p)
	v6 := r.V6
	one := ipmath.FromUint64(1)
	first, last := r.Start, r.End
	usable := r.Count()
	l := p.Bits()
	if !v6 {
		a.Netmask = ipmath.ToAddr(ipmath.LowMask(32).And(ipmath.LowMask(32-l).Not()), false).String()
		if l <= 30 {
			first, _ = r.Start.Add(one)
			last, _ = r.End.Sub(one)
			usable, _ = usable.Sub(ipmath.FromUint64(2))
			a.Broadcast = ipmath.ToAddr(r.End, false).String()
		}
	} else if l <= 126 {
		first, _ = r.Start.Add(one) // ::0 is the subnet-router anycast address
		usable, _ = usable.Sub(one)
	}
	a.FirstUsable = ipmath.ToAddr(first, v6).String()
	a.LastUsable = ipmath.ToAddr(last, v6).String()
	a.Usable = usable
	if (v6 && l <= 126) || (!v6 && l <= 30) {
		switch opt.Gateway {
		case "first":
			a.Gateway = a.FirstUsable
		case "last":
			a.Gateway = a.LastUsable
		}
	}
	if a.Hosts > 0 && usable.Hi == 0 && usable.Lo > 0 {
		a.Utilization = float64(a.Hosts) / float64(usable.Lo)
	}
}

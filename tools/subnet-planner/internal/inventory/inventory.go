// Package inventory loads prefix and IP address lists from plain text,
// CSV (NetBox exports, spreadsheets) and JSON (NetBox API responses,
// subnet-planner plans).
package inventory

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner/internal/ipmath"
)

// Kind tells prefixes and IP address assignments apart.
type Kind int

// Entry kinds.
const (
	KindPrefix Kind = iota
	KindAddress
)

func (k Kind) String() string {
	if k == KindAddress {
		return "address"
	}
	return "prefix"
}

// MarshalJSON encodes the kind as a string.
func (k Kind) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// Entry is one prefix or IP address assignment.
type Entry struct {
	Kind Kind `json:"kind"`
	// Prefix is canonical (host bits cleared). For an address it is the
	// subnet given by the address mask.
	Prefix netip.Prefix `json:"prefix"`
	// Addr is the host address of an address entry.
	Addr netip.Addr `json:"address,omitempty"`
	Raw  string     `json:"raw"`
	// HostBits is set when a prefix entry was written with host bits
	// (e.g. 10.0.0.5/24 in a prefix list).
	HostBits bool `json:"host_bits,omitempty"`
	// NoMask is set when an address was written without a prefix length.
	NoMask bool   `json:"no_mask,omitempty"`
	VRF    string `json:"vrf,omitempty"`
	Status string `json:"status,omitempty"`
	Role   string `json:"role,omitempty"`
	Name   string `json:"name,omitempty"`
	VLAN   string `json:"vlan,omitempty"`
	Site   string `json:"site,omitempty"`
	Source string `json:"source"`
	Line   int    `json:"line"`
}

// Where returns "source:line".
func (e Entry) Where() string { return fmt.Sprintf("%s:%d", e.Source, e.Line) }

// Label returns the most descriptive identifier of the entry.
func (e Entry) Label() string {
	parts := []string{}
	if e.Name != "" {
		parts = append(parts, e.Name)
	}
	if e.VLAN != "" {
		parts = append(parts, "vlan "+e.VLAN)
	}
	if e.Site != "" {
		parts = append(parts, "site "+e.Site)
	}
	return strings.Join(parts, ", ")
}

// Problem is a row that could not be used.
type Problem struct {
	Source  string `json:"source"`
	Line    int    `json:"line"`
	Raw     string `json:"raw"`
	Message string `json:"message"`
}

// Result of loading one or more files.
type Result struct {
	Entries  []Entry
	Problems []Problem
	// HasStatus is true when at least one entry carried a status.
	HasStatus bool
}

// LoadFile loads path ("-" reads stdin).
func LoadFile(path string, stdin io.Reader) (Result, error) {
	var r io.Reader
	name := path
	if path == "-" {
		r, name = stdin, "<stdin>"
	} else {
		f, err := os.Open(path)
		if err != nil {
			return Result{}, err
		}
		defer f.Close()
		r = f
	}
	return Load(name, r)
}

// maxInput bounds memory use on unexpected input (256 MiB).
const maxInput = 256 << 20

// Load parses r, auto-detecting JSON, CSV with a header, or plain text.
func Load(name string, r io.Reader) (Result, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxInput {
		return Result{}, fmt.Errorf("%s: larger than %d MiB", name, maxInput>>20)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return loadJSON(name, trimmed)
	}
	return loadText(name, data)
}

// --- plain text and CSV ---------------------------------------------------

var columnAliases = map[string][]string{
	"prefix":  {"prefix", "network", "subnet", "cidr", "net", "route"},
	"address": {"address", "ipaddress", "ip", "addr", "ipv4address", "ipv6address", "host"},
	"vrf":     {"vrf", "vrfname", "routinginstance", "routingtable"},
	"status":  {"status", "state"},
	"role":    {"role"},
	"name":    {"name", "description", "descr", "dnsname", "comment", "comments", "label"},
	"vlan":    {"vlan", "vlanid", "vid"},
	"site":    {"site", "scope", "location"},
}

func normHeader(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer(" ", "", "_", "", "-", "", ".", "").Replace(s)
}

func firstDataLine(data []byte) string {
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

func detectDelimiter(line string) rune {
	best, n := ',', strings.Count(line, ",")
	for _, d := range []rune{';', '\t', '|'} {
		if c := strings.Count(line, string(d)); c > n {
			best, n = d, c
		}
	}
	return best
}

func loadText(name string, data []byte) (Result, error) {
	first := firstDataLine(data)
	if first == "" {
		return Result{}, nil
	}
	delim := detectDelimiter(first)
	if !strings.ContainsRune(first, delim) {
		// One column: a CSV only if the first line is a known header.
		cols := mapColumns([]string{first})
		_, isP := cols["prefix"]
		_, isA := cols["address"]
		if !isP && !isA {
			return loadPlain(name, data), nil
		}
	}
	cr := csv.NewReader(bytes.NewReader(data))
	cr.Comma = delim
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true
	var res Result
	cols := map[string]int{}
	rowNo := 0
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := cr.FieldPos(0)
		if err != nil {
			return res, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		rowNo++
		if rowNo == 1 {
			if _, _, ok := parseAny(rec[0]); ok {
				cols = map[string]int{"prefix": 0}
				if len(rec) > 1 {
					cols["name"] = 1
				}
			} else {
				cols = mapColumns(rec)
				if _, ok := cols["prefix"]; !ok {
					if _, ok := cols["address"]; !ok {
						return res, fmt.Errorf("%s: no prefix/network/subnet/cidr or address column in header %q", name, strings.Join(rec, string(delim)))
					}
				}
				continue
			}
		}
		get := func(k string) string {
			if i, ok := cols[k]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		kind, raw := KindPrefix, get("prefix")
		if raw == "" {
			if a := get("address"); a != "" {
				kind, raw = KindAddress, a
			}
		}
		if raw == "" {
			if strings.TrimSpace(strings.Join(rec, "")) != "" {
				res.Problems = append(res.Problems, Problem{name, line, strings.Join(rec, string(delim)), "empty prefix/address cell"})
			}
			continue
		}
		e, perr := makeEntry(kind, raw)
		if perr != nil {
			res.Problems = append(res.Problems, Problem{name, line, raw, perr.Error()})
			continue
		}
		e.VRF = normVRF(get("vrf"))
		e.Status = strings.ToLower(get("status"))
		e.Role = strings.ToLower(get("role"))
		e.Name, e.VLAN, e.Site = get("name"), get("vlan"), get("site")
		e.Source, e.Line = name, line
		if e.Status != "" {
			res.HasStatus = true
		}
		res.Entries = append(res.Entries, e)
	}
	return res, nil
}

func mapColumns(header []string) map[string]int {
	norm := make([]string, len(header))
	for i, h := range header {
		norm[i] = normHeader(h)
	}
	cols := map[string]int{}
	for key, aliases := range columnAliases {
		for _, a := range aliases { // alias order is the preference order
			found := false
			for i, h := range norm {
				if h == a {
					cols[key] = i
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	return cols
}

func loadPlain(name string, data []byte) Result {
	var res Result
	for i, l := range strings.Split(string(data), "\n") {
		if j := strings.IndexByte(l, '#'); j >= 0 {
			l = l[:j]
		}
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		e, err := makeEntry(KindPrefix, fields[0])
		if err != nil {
			res.Problems = append(res.Problems, Problem{name, i + 1, fields[0], err.Error()})
			continue
		}
		if len(fields) > 1 {
			e.Name = strings.Join(fields[1:], " ")
		}
		e.Source, e.Line = name, i+1
		res.Entries = append(res.Entries, e)
	}
	return res
}

// parseAny accepts "a.b.c.d/len", "a.b.c.d" or "a.b.c.d/m.m.m.m".
func parseAny(s string) (netip.Addr, int, bool) {
	s = strings.TrimSpace(s)
	addrPart, lenPart, hasLen := strings.Cut(s, "/")
	if i := strings.IndexByte(addrPart, '%'); i >= 0 {
		addrPart = addrPart[:i] // drop IPv6 zone
	}
	a, err := netip.ParseAddr(addrPart)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	bitsLen := a.BitLen()
	if a.Is4In6() {
		a = a.Unmap()
		bitsLen = 32
		if hasLen {
			l, ok := atoi(lenPart)
			if !ok || l < 96 || l > 128 {
				return netip.Addr{}, 0, false
			}
			return a, l - 96, true
		}
	}
	if !hasLen {
		return a, -1, true
	}
	if l, ok := atoi(lenPart); ok && l >= 0 && l <= bitsLen {
		return a, l, true
	}
	if a.Is4() {
		if m, err := netip.ParseAddr(lenPart); err == nil && m.Is4() {
			if l, ok := maskLen(m); ok {
				return a, l, true
			}
		}
	}
	return netip.Addr{}, 0, false
}

func atoi(s string) (int, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func maskLen(m netip.Addr) (int, bool) {
	u, _ := ipmath.FromAddr(m)
	v := uint32(u.Lo)
	l := 0
	for l < 32 && v&(1<<(31-l)) != 0 {
		l++
	}
	if uint64(v) != uint64(ipmath.LowMask(32).Lo)&^uint64(ipmath.LowMask(32-l).Lo) {
		return 0, false
	}
	return l, true
}

// ParsePrefix parses a prefix as written by humans: CIDR, dotted mask, or a
// bare address (host route). It reports whether host bits were set.
func ParsePrefix(s string) (netip.Prefix, bool, error) {
	e, err := makeEntry(KindPrefix, s)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	return e.Prefix, e.HostBits, nil
}

func makeEntry(kind Kind, raw string) (Entry, error) {
	a, l, ok := parseAny(raw)
	if !ok {
		return Entry{}, fmt.Errorf("not a valid IP prefix or address: %q", raw)
	}
	e := Entry{Kind: kind, Raw: raw}
	if l < 0 {
		l = a.BitLen()
		e.NoMask = kind == KindAddress
	}
	p := netip.PrefixFrom(a, l)
	e.Prefix = p.Masked()
	if kind == KindAddress {
		e.Addr = a
	} else {
		e.HostBits = p.Masked().Addr() != a
	}
	return e, nil
}

func normVRF(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "global", "-", "—", "none", "null", "default", "grt":
		return ""
	}
	return s
}

// --- JSON -------------------------------------------------------------------

func loadJSON(name string, data []byte) (Result, error) {
	var top any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return Result{}, fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	var items []any
	switch v := top.(type) {
	case []any:
		items = v
	case map[string]any:
		for _, k := range []string{"results", "allocations", "prefixes", "items", "data"} {
			if arr, ok := v[k].([]any); ok {
				items = arr
				break
			}
		}
		if items == nil {
			return Result{}, fmt.Errorf("%s: JSON object without a results/allocations/prefixes/items array", name)
		}
	default:
		return Result{}, fmt.Errorf("%s: unsupported JSON document", name)
	}
	var res Result
	for i, it := range items {
		line := i + 1
		switch v := it.(type) {
		case string:
			e, err := makeEntry(KindPrefix, v)
			if err != nil {
				res.Problems = append(res.Problems, Problem{name, line, v, err.Error()})
				continue
			}
			e.Source, e.Line = name, line
			res.Entries = append(res.Entries, e)
		case map[string]any:
			kind, raw := KindPrefix, ""
			for _, k := range []string{"prefix", "cidr", "network", "subnet"} {
				if s, ok := v[k].(string); ok && s != "" {
					raw = s
					break
				}
			}
			if raw == "" {
				if s, ok := v["address"].(string); ok && s != "" {
					kind, raw = KindAddress, s
				}
			}
			if raw == "" {
				// Unallocated plan entries carry no prefix: skip silently.
				if _, isPlan := v["requested"]; isPlan {
					continue
				}
				res.Problems = append(res.Problems, Problem{name, line, "", "object without prefix/address field"})
				continue
			}
			e, err := makeEntry(kind, raw)
			if err != nil {
				res.Problems = append(res.Problems, Problem{name, line, raw, err.Error()})
				continue
			}
			e.VRF = normVRF(jsonName(v["vrf"]))
			e.Status = strings.ToLower(jsonValue(v["status"]))
			e.Role = strings.ToLower(jsonValue(v["role"]))
			e.Name = firstNonEmpty(jsonName(v["name"]), jsonName(v["description"]), jsonName(v["dns_name"]))
			e.VLAN = jsonVLAN(v["vlan"])
			e.Site = jsonName(v["site"])
			if e.Site == "" {
				e.Site = jsonName(v["scope"])
			}
			e.Source, e.Line = name, line
			if e.Status != "" {
				res.HasStatus = true
			}
			res.Entries = append(res.Entries, e)
		default:
			res.Problems = append(res.Problems, Problem{name, line, fmt.Sprint(it), "unsupported JSON item"})
		}
	}
	return res, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// jsonName extracts a display name from a NetBox nested object or string.
func jsonName(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case map[string]any:
		for _, k := range []string{"name", "display", "slug", "label"} {
			if s, ok := x[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// jsonValue extracts a choice value ({"value": "active", "label": ...}).
func jsonValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		for _, k := range []string{"value", "slug", "name", "label"} {
			if s, ok := x[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func jsonVLAN(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case string:
		return x
	case map[string]any:
		if n, ok := x["vid"].(json.Number); ok {
			return n.String()
		}
		return jsonName(x)
	}
	return ""
}

// Prefixes returns the canonical prefixes of the prefix entries.
func (r Result) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(r.Entries))
	for _, e := range r.Entries {
		if e.Kind == KindPrefix {
			out = append(out, e.Prefix)
		}
	}
	return out
}

// Merge appends o to r.
func (r *Result) Merge(o Result) {
	r.Entries = append(r.Entries, o.Entries...)
	r.Problems = append(r.Problems, o.Problems...)
	r.HasStatus = r.HasStatus || o.HasStatus
}

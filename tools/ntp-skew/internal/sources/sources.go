// Package sources turns command-line targets and NTP client configuration
// files (chrony, ntpd, systemd-timesyncd, Windows w32time peer lists) into
// the list of server addresses to measure.
package sources

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultPort is the NTP port.
const DefaultPort = 123

// Spec is a server as written by the user or in a configuration file.
type Spec struct {
	Host   string // name or literal address
	Port   int
	Pool   bool   // "pool" directive: every address is a separate source
	Origin string // where it came from ("args", "/etc/chrony.conf:12")
}

func (s Spec) String() string {
	if s.Port == DefaultPort {
		return s.Host
	}
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// ParseTarget parses one target: "host", "host:port", "[v6]:port", a bare
// IPv6 literal, or a Windows w32time entry such as "time.example,0x9".
func ParseTarget(raw, origin string) (Spec, error) {
	t := strings.TrimSpace(raw)
	if i := strings.Index(t, ","); i >= 0 && strings.HasPrefix(strings.ToLower(t[i+1:]), "0x") {
		t = t[:i] // w32time flags (NtpServer registry value, w32tm /config /manualpeerlist)
	}
	t = strings.TrimPrefix(strings.TrimPrefix(t, "ntp://"), "udp://")
	if t == "" {
		return Spec{}, fmt.Errorf("empty target")
	}
	spec := Spec{Host: t, Port: DefaultPort, Origin: origin}
	if a, err := netip.ParseAddr(strings.Trim(t, "[]")); err == nil {
		spec.Host = a.String()
		return spec, nil
	}
	if strings.Contains(t, ":") {
		h, p, err := net.SplitHostPort(t)
		if err != nil {
			return Spec{}, fmt.Errorf("invalid target %q: %v", raw, err)
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return Spec{}, fmt.Errorf("invalid port in %q", raw)
		}
		spec.Host, spec.Port = h, port
	}
	if err := checkHost(spec.Host); err != nil {
		return Spec{}, fmt.Errorf("invalid target %q: %v", raw, err)
	}
	return spec, nil
}

func checkHost(h string) error {
	if h == "" {
		return fmt.Errorf("empty host")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return nil
	}
	if len(h) > 253 {
		return fmt.Errorf("name too long")
	}
	for _, c := range h {
		if !(c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return fmt.Errorf("unexpected character %q", c)
		}
	}
	return nil
}

// ParseList reads one target per line ("#" comments, blank lines and
// several whitespace-separated targets per line allowed).
func ParseList(r io.Reader, name string) ([]Spec, error) {
	var out []Spec
	sc := bufio.NewScanner(r)
	ln := 0
	for sc.Scan() {
		ln++
		line := stripComment(sc.Text(), "#")
		for _, f := range strings.Fields(line) {
			s, err := ParseTarget(f, fmt.Sprintf("%s:%d", name, ln))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", name, ln, err)
			}
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// ParseConfig extracts the servers of an NTP client configuration:
//
//   - chrony.conf / ntp.conf: "server", "pool" and "peer" directives
//     (options after the name are ignored; ntpd reference clocks
//     127.127.t.u are skipped, chrony "refclock" lines are not servers);
//   - systemd-timesyncd.conf: "NTP=" and "FallbackNTP=" (FallbackNTP only
//     when no NTP= is set, as timesyncd does);
//   - a w32time peer list ("w32tm /query /peers" output or the NtpServer
//     registry value: "a.example,0x9 b.example,0x9").
func ParseConfig(r io.Reader, name string) ([]Spec, error) {
	var direct, fallback []Spec
	sc := bufio.NewScanner(r)
	ln := 0
	for sc.Scan() {
		ln++
		raw := sc.Text()
		line := strings.TrimSpace(stripComment(stripComment(raw, "#"), ";"))
		if line == "" {
			continue
		}
		origin := fmt.Sprintf("%s:%d", name, ln)
		fields := strings.Fields(line)
		key := strings.ToLower(fields[0])
		switch {
		case key == "server" || key == "pool" || key == "peer":
			if len(fields) < 2 {
				return nil, fmt.Errorf("%s: %s without a name", origin, key)
			}
			if strings.HasPrefix(fields[1], "127.127.") {
				continue // ntpd reference clock driver
			}
			s, err := ParseTarget(fields[1], origin)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", origin, err)
			}
			if p := optionValue(fields[2:], "port"); p != "" {
				port, err := strconv.Atoi(p)
				if err != nil || port < 1 || port > 65535 {
					return nil, fmt.Errorf("%s: invalid port %q", origin, p)
				}
				s.Port = port
			}
			s.Pool = key == "pool"
			direct = append(direct, s)
		case isTimesyncdKey(line):
			k, v, _ := strings.Cut(line, "=")
			var specs []Spec
			for _, f := range strings.Fields(v) {
				s, err := ParseTarget(f, origin)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", origin, err)
				}
				specs = append(specs, s)
			}
			// A later assignment replaces the earlier one; an empty one resets.
			if strings.EqualFold(strings.TrimSpace(k), "NTP") {
				direct = specs
			} else {
				fallback = specs
			}
		case strings.HasPrefix(key, "peer:"):
			// w32tm /query /peers: "Peer: time.example,0x9"
			v := strings.TrimSpace(line[len("peer:"):])
			if v == "" {
				continue
			}
			s, err := ParseTarget(v, origin)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", origin, err)
			}
			direct = append(direct, s)
		case strings.Contains(fields[0], ",0x") || strings.Contains(fields[0], ",0X"):
			for _, f := range fields {
				s, err := ParseTarget(f, origin)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", origin, err)
				}
				direct = append(direct, s)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(direct) == 0 {
		direct = fallback
	}
	if len(direct) == 0 {
		return nil, fmt.Errorf("%s: no NTP server found (server/pool/peer, NTP=, or a w32time peer list)", name)
	}
	return direct, nil
}

func isTimesyncdKey(line string) bool {
	k, _, ok := strings.Cut(line, "=")
	if !ok {
		return false
	}
	k = strings.TrimSpace(k)
	return strings.EqualFold(k, "NTP") || strings.EqualFold(k, "FallbackNTP")
}

func optionValue(opts []string, key string) string {
	for i := 0; i+1 < len(opts); i++ {
		if strings.EqualFold(opts[i], key) {
			return opts[i+1]
		}
	}
	return ""
}

func stripComment(s, marker string) string {
	if i := strings.Index(s, marker); i >= 0 {
		return s[:i]
	}
	return s
}

// Source is one address to measure.
type Source struct {
	Spec Spec
	Addr netip.AddrPort
}

// Name returns the name to display: the configured host, plus the address
// when they differ.
func (s Source) Name() string { return s.Spec.Host }

// Resolver looks up the addresses of a name.
type Resolver func(ctx context.Context, network, host string) ([]netip.Addr, error)

// Family restricts resolution.
type Family int

// Address families.
const (
	Any Family = iota
	IPv4
	IPv6
)

// Expand resolves every spec. A "server" name contributes its first
// address (one server, one vote in the selection) unless all is set; a "pool" name (and
// every name when all is set) contributes every address. Duplicate
// addresses are measured once. Resolution failures are returned per spec
// and do not stop the others.
func Expand(ctx context.Context, specs []Spec, fam Family, all bool, resolve Resolver) ([]Source, map[string]error) {
	errs := map[string]error{}
	seen := map[netip.AddrPort]bool{}
	var out []Source
	add := func(s Spec, a netip.Addr) {
		ap := netip.AddrPortFrom(a.Unmap(), uint16(s.Port))
		if seen[ap] {
			return
		}
		seen[ap] = true
		out = append(out, Source{Spec: s, Addr: ap})
	}
	for _, s := range specs {
		if a, err := netip.ParseAddr(s.Host); err == nil {
			a = a.Unmap()
			if fam == IPv4 && !a.Is4() || fam == IPv6 && a.Is4() {
				errs[s.String()] = fmt.Errorf("address family excluded by -4/-6")
				continue
			}
			add(s, a)
			continue
		}
		network := "ip"
		switch fam {
		case IPv4:
			network = "ip4"
		case IPv6:
			network = "ip6"
		}
		addrs, err := resolve(ctx, network, s.Host)
		if err != nil {
			errs[s.String()] = err
			continue
		}
		if len(addrs) == 0 {
			errs[s.String()] = fmt.Errorf("no address")
			continue
		}
		if s.Pool || all {
			for _, a := range addrs {
				add(s, a)
			}
			continue
		}
		add(s, addrs[0])
	}
	return out, errs
}

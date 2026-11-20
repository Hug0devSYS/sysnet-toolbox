package sources

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in, host string
		port     int
		err      bool
	}{
		{"time.example.com", "time.example.com", 123, false},
		{"time.example.com:1123", "time.example.com", 1123, false},
		{"192.0.2.1", "192.0.2.1", 123, false},
		{"192.0.2.1:124", "192.0.2.1", 124, false},
		{"2001:db8::1", "2001:db8::1", 123, false},
		{"[2001:db8::1]", "2001:db8::1", 123, false},
		{"[2001:db8::1]:4123", "2001:db8::1", 4123, false},
		{"time.windows.com,0x9", "time.windows.com", 123, false},
		{"ntp://ntp1.example", "ntp1.example", 123, false},
		{"host:0", "", 0, true},
		{"host:99999", "", 0, true},
		{"bad host", "", 0, true},
		{"x;rm -rf", "", 0, true},
		{"", "", 0, true},
	}
	for _, tc := range cases {
		s, err := ParseTarget(tc.in, "t")
		if (err != nil) != tc.err {
			t.Errorf("%q: err=%v", tc.in, err)
			continue
		}
		if err == nil && (s.Host != tc.host || s.Port != tc.port) {
			t.Errorf("%q: got %s %d", tc.in, s.Host, s.Port)
		}
	}
}

func hosts(specs []Spec) string {
	var out []string
	for _, s := range specs {
		h := s.String()
		if s.Pool {
			h += "(pool)"
		}
		out = append(out, h)
	}
	return strings.Join(out, " ")
}

func TestParseConfig(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"chrony", `# chrony
pool 2.debian.pool.ntp.org iburst maxsources 4
server ntp1.example.com iburst prefer
server 192.0.2.10 port 1123 minpoll 4
! server commented.example
refclock PHC /dev/ptp0 poll 3 dpoll -2
local stratum 10
`, "2.debian.pool.ntp.org(pool) ntp1.example.com 192.0.2.10:1123"},
		{"ntpd", `driftfile /var/lib/ntp/drift
server 127.127.1.0
fudge 127.127.1.0 stratum 10
server 0.rhel.pool.ntp.org iburst
peer 10.0.0.2
restrict default nomodify
`, "0.rhel.pool.ntp.org 10.0.0.2"},
		{"timesyncd", `[Time]
NTP=ntp-a.example ntp-b.example
FallbackNTP=time1.google.com
`, "ntp-a.example ntp-b.example"},
		{"timesyncd fallback", `[Time]
#NTP=
FallbackNTP = ntp.ubuntu.com
`, "ntp.ubuntu.com"},
		{"timesyncd reset", "[Time]\nNTP=a.example\nNTP=b.example\n", "b.example"},
		{"w32tm peers", `#Peers: 2

Peer: dc01.corp.example,0x8
State: Active
Time Remaining: 1023.1s

Peer: time.windows.com,0x9
State: Active
`, "dc01.corp.example time.windows.com"},
		{"w32time registry", "time.windows.com,0x9 ntp.example,0x1\n", "time.windows.com ntp.example"},
	}
	for _, tc := range cases {
		specs, err := ParseConfig(strings.NewReader(tc.text), "conf")
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := hosts(specs); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
	if _, err := ParseConfig(strings.NewReader("driftfile x\n"), "empty"); err == nil {
		t.Error("config without servers accepted")
	}
	if _, err := ParseConfig(strings.NewReader("server\n"), "bad"); err == nil {
		t.Error("server without name accepted")
	}
	if _, err := ParseConfig(strings.NewReader("server a.example port nope\n"), "bad"); err == nil {
		t.Error("bad port accepted")
	}
	specs, _ := ParseConfig(strings.NewReader("\n\nserver a.example\n"), "/etc/chrony.conf")
	if specs[0].Origin != "/etc/chrony.conf:3" {
		t.Errorf("origin %q", specs[0].Origin)
	}
}

func TestParseList(t *testing.T) {
	specs, err := ParseList(strings.NewReader("a.example b.example:1123 # comment\n\n# x\n192.0.2.1\n"), "list")
	if err != nil {
		t.Fatal(err)
	}
	if got := hosts(specs); got != "a.example b.example:1123 192.0.2.1" {
		t.Fatalf("got %s", got)
	}
	if _, err := ParseList(strings.NewReader("ok.example\nbad|host\n"), "list"); err == nil || !strings.Contains(err.Error(), "list:2") {
		t.Fatalf("error without position: %v", err)
	}
}

func TestExpand(t *testing.T) {
	resolve := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		all := map[string][]string{
			"pool.example":   {"192.0.2.1", "192.0.2.2", "2001:db8::1"},
			"server.example": {"2001:db8::5", "192.0.2.5"},
			"dup.example":    {"192.0.2.1"},
		}
		list, ok := all[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, s := range list {
			a := netip.MustParseAddr(s)
			if network == "ip4" && !a.Is4() || network == "ip6" && a.Is4() {
				continue
			}
			out = append(out, a)
		}
		return out, nil
	}
	specs := []Spec{
		{Host: "pool.example", Port: 123, Pool: true},
		{Host: "server.example", Port: 123},
		{Host: "dup.example", Port: 123},
		{Host: "missing.example", Port: 123},
		{Host: "198.51.100.7", Port: 1123},
	}
	addrs := func(srcs []Source) string {
		var out []string
		for _, s := range srcs {
			out = append(out, s.Addr.String())
		}
		return strings.Join(out, " ")
	}
	srcs, errs := Expand(context.Background(), specs, Any, false, resolve)
	if got := addrs(srcs); got != "192.0.2.1:123 192.0.2.2:123 [2001:db8::1]:123 [2001:db8::5]:123 198.51.100.7:1123" {
		t.Fatalf("any: %s", got)
	}
	if len(errs) != 1 || errs["missing.example"] == nil {
		t.Fatalf("errors %v", errs)
	}
	srcs, _ = Expand(context.Background(), specs, IPv4, true, resolve)
	if got := addrs(srcs); got != "192.0.2.1:123 192.0.2.2:123 192.0.2.5:123 198.51.100.7:1123" {
		t.Fatalf("v4 all: %s", got)
	}
	_, errs = Expand(context.Background(), []Spec{{Host: "192.0.2.1", Port: 123}}, IPv6, false, resolve)
	if errs["192.0.2.1"] == nil {
		t.Fatal("literal of excluded family accepted")
	}
}

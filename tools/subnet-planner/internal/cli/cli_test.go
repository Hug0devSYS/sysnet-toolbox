package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errb, Stdin: strings.NewReader(stdin), StdinIsTTY: stdin == ""}
	code := Run(args, env)
	return code, out.String(), errb.String()
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUsageAndVersion(t *testing.T) {
	if code, _, e := run(t, ""); code != ExitUnknown || !strings.Contains(e, "Usage") {
		t.Fatal("no args")
	}
	if code, o, _ := run(t, "", "version"); code != ExitOK || !strings.Contains(o, Version) {
		t.Fatal("version")
	}
	if code, _, _ := run(t, "", "bogus"); code != ExitUnknown {
		t.Fatal("unknown command")
	}
	for _, c := range []string{"plan", "check", "aggregate", "free", "info"} {
		if code, _, e := run(t, "", c, "--help"); code != ExitOK || !strings.Contains(e, "Usage") {
			t.Errorf("%s --help: %d", c, code)
		}
	}
}

func TestPlanText(t *testing.T) {
	code, out, _ := run(t, "", "plan", "--parent", "10.20.0.0/16", "users=500", "voice=120", "transit=/31", "--color", "never")
	if code != ExitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	for _, want := range []string{"10.20.0.0/23", "10.20.2.0/25", "10.20.2.128/31", "98%"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestPlanJSONUsedAndFile(t *testing.T) {
	used := write(t, "netbox.csv", "Prefix,VRF,Status\n10.0.0.0/8,,Container\n10.20.0.0/22,,Container\n10.20.0.0/24,,Active\n10.20.1.0/24,BLUE,Active\n")
	reqs := write(t, "req.csv", "name,size,vlan\nusers,200,10\nvoice,/24,20\n")
	code, out, errs := run(t, "", "plan", "--parent", "10.20.0.0/22", "--used", used, "-f", reqs, "--json")
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errs)
	}
	var res struct {
		Allocations []struct {
			Name   string `json:"name"`
			Prefix string `json:"prefix"`
			VLAN   string `json:"vlan"`
		} `json:"allocations"`
		Free []string `json:"free"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	// Both used prefixes count (no --vrf): users and voice get .2 and .3.
	if res.Allocations[0].Prefix != "10.20.2.0/24" || res.Allocations[1].Prefix != "10.20.3.0/24" || res.Allocations[0].VLAN != "10" {
		t.Fatalf("%+v", res.Allocations)
	}
	// With --vrf BLUE only BLUE's prefix is in use.
	_, out, _ = run(t, "", "plan", "--parent", "10.20.0.0/22", "--used", used, "--vrf", "BLUE", "-f", reqs, "--format", "netbox")
	if !strings.HasPrefix(out, "prefix,status,description,vrf\n10.20.0.0/24,reserved,users,BLUE\n10.20.2.0/24,reserved,voice,BLUE\n") {
		t.Fatalf("netbox csv:\n%s", out)
	}
}

func TestPlanFailures(t *testing.T) {
	code, out, _ := run(t, "", "plan", "--parent", "192.168.1.0/24", "a=200", "b=100", "--color", "never")
	if code != ExitCritical || !strings.Contains(out, "NOT ALLOCATED") || !strings.Contains(out, "at least a /23") {
		t.Fatalf("%d\n%s", code, out)
	}
	code, _, _ = run(t, "", "plan", "--parent", "2001:db8::/48", "odd=/80")
	if code != ExitWarning {
		t.Fatalf("v6 warning: %d", code)
	}
	cases := [][]string{
		{"plan", "a=10"},                                          // no parent
		{"plan", "--parent", "10.0.0.1", "a=10"},                  // not a prefix
		{"plan", "--parent", "10.0.0.0/8"},                        // no requests
		{"plan", "--parent", "10.0.0.0/8", "a"},                   // bad request
		{"plan", "--parent", "10.0.0.0/8", "a=1", "--order", "x"}, // bad flag value
		{"plan", "--parent", "10.0.0.0/8", "a=1", "a=2"},          // duplicate names
		{"plan", "--parent", "10.0.0.0/8", "a=1", "--used", "/nonexistent"},
	}
	for _, c := range cases {
		if code, _, _ := run(t, "", c...); code != ExitUnknown {
			t.Errorf("%v: code %d", c, code)
		}
	}
}

func TestCheck(t *testing.T) {
	f := write(t, "p.csv", "Prefix,Status\n10.0.0.0/16,Container\n10.0.1.0/24,Active\n10.0.1.0/24,Active\n")
	code, out, _ := run(t, "", "check", f, "--color", "never")
	if code != ExitCritical || !strings.Contains(out, "duplicate-prefix") || !strings.Contains(out, "CRITICAL - 3 entries") {
		t.Fatalf("%d\n%s", code, out)
	}
	clean := write(t, "c.csv", "Prefix,Status\n10.0.0.0/16,Container\n10.0.1.0/24,Active\n")
	if code, out, _ := run(t, "", "check", clean, "--color", "never"); code != ExitOK || !strings.HasPrefix(out, "OK - 2 entries") {
		t.Fatalf("clean: %d %s", code, out)
	}
	// stdin, JSON.
	code, out, _ = run(t, "10.0.0.0/23\n10.0.1.0/24\n", "check", "--json")
	if code != ExitWarning {
		t.Fatalf("stdin: %d", code)
	}
	var rep struct {
		Status   string `json:"status"`
		Findings []struct {
			Code string `json:"code"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Status != "WARNING" || rep.Findings[0].Code != "overlap" {
		t.Fatalf("%v %+v", err, rep)
	}
	if code, _, _ := run(t, "", "check"); code != ExitUnknown {
		t.Error("no input on a terminal")
	}
	if code, _, _ := run(t, "", "check", "--nesting", "maybe", f); code != ExitUnknown {
		t.Error("bad nesting")
	}
	if code, out, _ := run(t, "", "check", "-q", "--nesting", "allow", write(t, "x", "10.0.0.0/8\n10.0.0.0/9\n")); code != ExitOK || strings.Count(out, "\n") != 1 {
		t.Errorf("quiet/allow: %d %q", code, out)
	}
}

func TestAggregate(t *testing.T) {
	code, out, errs := run(t, "", "aggregate", "10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/23", "10.0.0.1", "2001:db8::/48", "2001:db8:1::/48")
	if code != ExitOK || out != "10.0.0.0/22\n2001:db8::/47\n" || !strings.Contains(errs, "6 prefixes in, 2 out") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	_, out, _ = run(t, "10.0.0.0/24\n10.0.2.0/24\n", "aggregate", "--max", "1", "--format", "junos", "--name", "PL")
	if out != "set policy-options prefix-list PL 10.0.0.0/22\n" {
		t.Fatalf("junos: %q", out)
	}
	_, out, _ = run(t, "", "aggregate", "--format", "cisco", "10.0.0.0/24", "2001:db8::/32", "192.0.2.0/24")
	if !strings.Contains(out, "ip prefix-list AGGREGATE seq 10 permit 192.0.2.0/24") || !strings.Contains(out, "ipv6 prefix-list AGGREGATE seq 5 permit 2001:db8::/32") {
		t.Fatalf("cisco: %q", out)
	}
	code, out, _ = run(t, "", "aggregate", "--json", "--max", "1", "10.0.0.0/24", "10.0.3.0/24", "junk")
	var res struct {
		Prefixes []string `json:"prefixes"`
		Extra    int      `json:"extra_ipv4_addresses"`
		Exact    bool     `json:"exact"`
		Skipped  []string `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != ExitWarning || res.Exact || res.Extra != 512 || len(res.Skipped) != 1 {
		t.Fatalf("%d %v %+v", code, err, res)
	}
	if code, _, _ := run(t, "", "aggregate", "junk"); code != ExitUnknown {
		t.Error("only invalid input")
	}
}

func TestFree(t *testing.T) {
	used := write(t, "u.txt", "10.0.0.0/16\n10.0.0.0/22\n10.0.0.0/25\n10.0.1.0/24\n")
	code, out, _ := run(t, "", "free", "--parent", "10.0.0.0/22", "--used", used)
	if code != ExitOK || out != "10.0.0.128/25\n10.0.2.0/23\n" {
		t.Fatalf("%d %q", code, out)
	}
	_, out, _ = run(t, "", "free", "10.0.0.0/22", "10.0.1.0/24", "--split", "24")
	if out != "10.0.0.0/24\n10.0.2.0/24\n10.0.3.0/24\n" {
		t.Fatalf("split: %q", out)
	}
	_, out, errs := run(t, "", "free", "10.0.0.0/16", "--split", "24", "--limit", "2")
	if strings.Count(out, "\n") != 2 || !strings.Contains(errs, "limited to 2") {
		t.Fatalf("limit: %q %q", out, errs)
	}
	if code, _, _ := run(t, "", "free", "10.0.0.0/24", "10.0.0.0/24"); code != ExitWarning {
		t.Error("nothing free")
	}
	if code, _, _ := run(t, "", "free", "10.0.0.0/24", "--split", "8"); code != ExitUnknown {
		t.Error("bad split")
	}
}

func TestInfo(t *testing.T) {
	code, out, _ := run(t, "", "info", "192.168.10.37/26")
	if code != ExitOK {
		t.Fatal(code)
	}
	for _, want := range []string{"Address:       192.168.10.37", "Netmask:       255.255.255.192", "Broadcast:     192.168.10.63", "62 usable", "RFC 1918", "RFC 2317"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	_, out, _ = run(t, "", "info", "--json", "2001:db8::/32", "--split", "34")
	var res []infoResult
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res) != 1 || len(res[0].Subnets) != 4 || res[0].ReverseZones.Zones[0] != "8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatalf("%v %s", err, out)
	}
	if code, _, _ := run(t, "", "info", "nope"); code != ExitUnknown {
		t.Error("invalid")
	}
}

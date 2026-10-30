package inventory

import (
	"strings"
	"testing"
)

func load(t *testing.T, s string) Result {
	t.Helper()
	r, err := Load("test", strings.NewReader(s))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return r
}

func TestPlainList(t *testing.T) {
	r := load(t, "# comment\n10.0.0.0/24 users lan\n\n192.168.1.5 # host\n2001:db8::/32\nbogus\n10.1.2.3/255.255.255.0\n")
	if len(r.Entries) != 4 || len(r.Problems) != 1 {
		t.Fatalf("entries=%d problems=%v", len(r.Entries), r.Problems)
	}
	if r.Entries[0].Name != "users lan" || r.Entries[0].Line != 2 {
		t.Errorf("name/line: %+v", r.Entries[0])
	}
	if r.Entries[1].Prefix.String() != "192.168.1.5/32" {
		t.Errorf("bare address: %v", r.Entries[1].Prefix)
	}
	if e := r.Entries[3]; e.Prefix.String() != "10.1.2.0/24" || !e.HostBits {
		t.Errorf("dotted mask: %+v", e)
	}
	if r.Problems[0].Line != 6 {
		t.Errorf("problem line: %+v", r.Problems[0])
	}
}

func TestNetBoxCSV(t *testing.T) {
	// NetBox table export (display names) with a UTF-8 BOM and quoted cells.
	csv := "\xef\xbb\xbfPrefix,Status,VRF,Site,VLAN,Description\n" +
		"10.20.0.0/16,Container,,PAR1,,\"Paris, campus\"\n" +
		"10.20.0.0/24,Active,Global,PAR1,10,users\n" +
		"10.20.0.0/24,Active,CUST-A,,,cust\n"
	r := load(t, csv)
	if len(r.Entries) != 3 || !r.HasStatus {
		t.Fatalf("%+v", r)
	}
	e := r.Entries[0]
	if e.Status != "container" || e.Name != "Paris, campus" || e.Site != "PAR1" || e.Line != 2 {
		t.Errorf("row 1: %+v", e)
	}
	if r.Entries[1].VRF != "" || r.Entries[2].VRF != "CUST-A" || r.Entries[1].VLAN != "10" {
		t.Errorf("vrf/vlan: %+v %+v", r.Entries[1], r.Entries[2])
	}
}

func TestSemicolonCSVAndAddresses(t *testing.T) {
	r := load(t, "IP Address;vrf;Role;DNS name\n10.0.0.1/24;;VRRP;gw\n10.0.0.7;;;\n;;;\nx;;;\n")
	if len(r.Entries) != 2 || len(r.Problems) != 1 {
		t.Fatalf("%+v", r)
	}
	a := r.Entries[0]
	if a.Kind != KindAddress || a.Addr.String() != "10.0.0.1" || a.Prefix.String() != "10.0.0.0/24" || a.Role != "vrrp" || a.Name != "gw" {
		t.Errorf("address row: %+v", a)
	}
	if b := r.Entries[1]; !b.NoMask || b.Prefix.Bits() != 32 {
		t.Errorf("no mask: %+v", b)
	}
}

func TestSingleColumnCSV(t *testing.T) {
	r := load(t, "Address\n10.0.0.1/24\n10.0.0.2/24\n")
	if len(r.Entries) != 2 || len(r.Problems) != 0 || r.Entries[0].Kind != KindAddress {
		t.Fatalf("%+v", r)
	}
}

func TestHeaderlessCSV(t *testing.T) {
	r := load(t, "10.0.0.0/24,users\n10.0.1.0/24,voice\n")
	if len(r.Entries) != 2 || r.Entries[1].Name != "voice" {
		t.Fatalf("%+v", r)
	}
}

func TestCSVWithoutPrefixColumn(t *testing.T) {
	if _, err := Load("x", strings.NewReader("name,size\nusers,120\n")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNetBoxJSON(t *testing.T) {
	js := `{"count": 3, "results": [
	  {"prefix": "10.0.0.0/16", "status": {"value": "container", "label": "Container"}, "vrf": null, "description": ""},
	  {"prefix": "10.0.1.0/24", "status": {"value": "active"}, "vrf": {"id": 2, "name": "CUST-A"},
	   "vlan": {"vid": 101, "name": "users"}, "scope": {"name": "PAR1"}, "description": "users"},
	  {"address": "10.0.1.1/24", "role": {"value": "anycast", "label": "Anycast"}, "dns_name": "gw.example.net"}
	]}`
	r := load(t, js)
	if len(r.Entries) != 3 || !r.HasStatus {
		t.Fatalf("%+v", r)
	}
	if e := r.Entries[1]; e.VRF != "CUST-A" || e.VLAN != "101" || e.Site != "PAR1" || e.Status != "active" {
		t.Errorf("prefix: %+v", e)
	}
	if e := r.Entries[2]; e.Kind != KindAddress || e.Role != "anycast" || e.Name != "gw.example.net" {
		t.Errorf("address: %+v", e)
	}
}

func TestPlanJSONAndArrays(t *testing.T) {
	r := load(t, `{"allocations": [{"name": "users", "requested": "500 hosts", "prefix": "10.0.0.0/23"},
		{"name": "big", "requested": "/8", "error": "does not fit"}]}`)
	if len(r.Entries) != 1 || len(r.Problems) != 0 || r.Entries[0].Name != "users" {
		t.Fatalf("%+v", r)
	}
	r = load(t, `["10.0.0.0/8", "2001:db8::/32", 42]`)
	if len(r.Entries) != 2 || len(r.Problems) != 1 {
		t.Fatalf("%+v", r)
	}
	if _, err := Load("x", strings.NewReader(`{"foo": 1}`)); err == nil {
		t.Fatal("expected error for object without array")
	}
	if _, err := Load("x", strings.NewReader(`[1,`)); err == nil {
		t.Fatal("expected JSON syntax error")
	}
}

func TestParseVariants(t *testing.T) {
	ok := map[string]string{
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"fe80::1%eth0":        "fe80::1/128",
		" 10.0.0.0/8 ":        "10.0.0.0/8",
		"0.0.0.0/0":           "0.0.0.0/0",
	}
	for in, want := range ok {
		p, _, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("%q -> %v %v", in, p, err)
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "10.0.0.0/255.0.255.0", "2001:db8::/129", "10.0.0.0/", "10.0.0.0/1234", "::ffff:10.0.0.0/64"} {
		if _, _, err := ParsePrefix(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

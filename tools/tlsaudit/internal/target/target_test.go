package target

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Target
	}{
		{"Example.COM.", Target{Host: "example.com", Port: 443, ServerName: "example.com"}},
		{"example.com:8443", Target{Host: "example.com", Port: 8443, ServerName: "example.com"}},
		{"192.0.2.10", Target{Host: "192.0.2.10", Port: 443}},
		{"[2001:db8::1]:993", Target{Host: "2001:db8::1", Port: 993}},
		{"2001:db8::1", Target{Host: "2001:db8::1", Port: 443}},
		{"smtp://mx.example.com", Target{Host: "mx.example.com", Port: 25, ServerName: "mx.example.com", StartTLS: "smtp"}},
		{"submission://mx.example.com", Target{Host: "mx.example.com", Port: 587, ServerName: "mx.example.com", StartTLS: "smtp"}},
		{"ldaps://dc1.corp.example:3269/", Target{Host: "dc1.corp.example", Port: 3269, ServerName: "dc1.corp.example"}},
		{"www.example.com connect=10.0.0.5 sni=api.example.com",
			Target{Host: "www.example.com", Port: 443, ServerName: "api.example.com", Connect: "10.0.0.5"}},
		{"10.1.1.1:5432 starttls=postgres sni=db.example", Target{Host: "10.1.1.1", Port: 5432, ServerName: "db.example", StartTLS: "postgres"}},
		{"example.com sni=none", Target{Host: "example.com", Port: 443}},
		{"imap://mail.example starttls=none", Target{Host: "mail.example", Port: 143, ServerName: "mail.example"}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		got.Spec = ""
		if got != c.want {
			t.Errorf("%q:\n got %+v\nwant %+v", c.in, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"", "gopher://x", "example.com:0", "example.com:99999", "exa mple.com:x",
		"bad_host!", "x sni=bad!name", "x starttls=xmpp", "x foo=bar", "x connect=", "https://u@h/path",
		"[not-ip]:443", "x novalue",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q: accepted", in)
		}
	}
}

func TestParseList(t *testing.T) {
	in := "# fleet\nexample.com\n\n  smtp://mx.example.com  # mail\nexample.net:8443 sni=www.example.net\n"
	ts, err := ParseList(strings.NewReader(in), "targets.txt")
	if err != nil || len(ts) != 3 || ts[1].StartTLS != "smtp" || ts[2].ServerName != "www.example.net" {
		t.Fatalf("%+v %v", ts, err)
	}
	if ts[0].Name() != "example.com:443" || ts[0].VerifyName() != "example.com" {
		t.Errorf("name %q verify %q", ts[0].Name(), ts[0].VerifyName())
	}
	_, err = ParseList(strings.NewReader("ok.example\nbad host!\n"), "f")
	if err == nil || !strings.Contains(err.Error(), "f:2:") {
		t.Fatalf("want line number, got %v", err)
	}
	ip, _ := Parse("[2001:db8::1]:443")
	if ip.Name() != "[2001:db8::1]:443" || ip.VerifyName() != "2001:db8::1" {
		t.Errorf("%q %q", ip.Name(), ip.VerifyName())
	}
}

package mask

import (
	"strings"
	"testing"
)

func TestToken(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":                            IP,
		"192.0.2.1:443":                        IP,
		"[2001:db8::1]:22":                     IP,
		"2001:db8::1":                          IP,
		"fe80::1%eth0":                         IP,
		"10.0.0.0/8":                           CIDR,
		"2001:db8::/32,":                       CIDR + ",",
		"00:1a:2b:3c:4d:5e":                    MAC,
		"de:ad:be:ef:ca:fe":                    MAC,
		"00-1A-2B-3C-4D-5E":                    MAC,
		"001a.2b3c.4d5e":                       MAC,
		"123e4567-e89b-12d3-a456-426614174000": UUID,
		"0xdeadbeef":                           HEX,
		"a1b2c3d4e5f6":                         HEX,
		"12345":                                NUM,
		"-42":                                  NUM,
		"3.14":                                 NUM,
		"10:00:01":                             NUM,
		"2026-11-13":                           NUM,
		"250ms":                                NUM,
		"95%":                                  NUM,
		"[4242]:":                              "[" + NUM + "]:",
		"(10.0.0.5)":                           "(" + IP + ")",
		"port=22":                              "port=" + NUM,
		"src=192.0.2.1":                        "src=" + IP,
		"user=bob":                             "user=bob",
		"1,2,3":                                NUM,
		"ext4_find_entry:1455:":                "ext4_find_entry:" + NUM + ":",
		"#2:":                                  "#" + NUM + ":",
		"outside:192.0.2.1/1234":               "outside:" + IP + "/" + NUM,
		"inside:10.0.0.1":                      "inside:" + IP,
		"192.0.2.1,192.0.2.2":                  IP + "," + IP,
		// Kept intact: names, interfaces, paths, words.
		"eth0":                 "eth0",
		"GigabitEthernet1/0/1": "GigabitEthernet1/0/1",
		"ge-0/0/1.0":           "ge-0/0/1.0",
		"Vlan10":               "Vlan10",
		"/var/log/syslog":      "/var/log/syslog",
		"failed":               "failed",
		"ssh2":                 "ssh2",
		"decade":               "decade",
		"":                     "",
		"'admin'":              "'admin'",
	}
	for in, want := range cases {
		if got := Token(in); got != want {
			t.Errorf("Token(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTokens(t *testing.T) {
	got := Tokens("Failed password for root from 192.0.2.1 port 22 ssh2", 0)
	if strings.Join(got, " ") != "Failed password for root from <IP> port <NUM> ssh2" {
		t.Errorf("got %q", got)
	}
	got = Tokens("a b c d e", 3)
	if strings.Join(got, " ") != "a b <*>" {
		t.Errorf("max tokens: %q", got)
	}
	if len(Tokens("   ", 0)) != 0 {
		t.Error("blank message")
	}
	if !IsPlaceholder("[<NUM>]:") || IsPlaceholder("<html>") || IsPlaceholder("x") {
		t.Error("IsPlaceholder")
	}
}

func BenchmarkTokens(b *testing.B) {
	msg := "Accepted publickey for deploy from 198.51.100.23 port 51234 ssh2: ED25519 SHA256:Zm9vYmFy"
	for i := 0; i < b.N; i++ {
		Tokens(msg, 80)
	}
}

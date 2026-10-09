package dnssec

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

// RFC 4034 section 5.4 example.
func TestRFC4034DSVector(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString("AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==")
	if err != nil {
		t.Fatal(err)
	}
	k := &dnswire.DNSKEY{Flags: 256, Protocol: 3, Algorithm: 5, PublicKey: pub}
	if tag := KeyTag(k); tag != 60485 {
		t.Fatalf("key tag = %d, want 60485", tag)
	}
	ds, err := ComputeDS("dskey.example.com.", k, DigestSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ToUpper(hex.EncodeToString(ds.Digest)); got != "2BB183AF5F22588179A53B0A98631FAD1A292118" {
		t.Fatalf("digest = %s", got)
	}
	// Case-insensitive owner.
	ok, err := MatchDS("DSKEY.Example.COM", ds, k)
	if err != nil || !ok {
		t.Fatalf("MatchDS = %v, %v", ok, err)
	}
}

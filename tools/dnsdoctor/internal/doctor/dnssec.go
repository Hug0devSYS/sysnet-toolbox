package doctor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnssec"
	"github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/dnswire"
)

// RootAnchors are the IANA root zone trust anchors (RFC 9718,
// https://data.iana.org/root-anchors/root-anchors.xml): KSK-2017 (20326)
// and KSK-2024 (38696). Either one validating is sufficient, so the tool
// keeps working across the 2026 root KSK rollover.
var RootAnchors = []*dnswire.DS{
	mustDS(20326, 8, 2, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
	mustDS(38696, 8, 2, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
}

func mustDS(tag uint16, alg, dt uint8, digest string) *dnswire.DS {
	b, err := hex.DecodeString(digest)
	if err != nil {
		panic(err)
	}
	return &dnswire.DS{KeyTag: tag, Algorithm: alg, DigestType: dt, Digest: b}
}

// ParseTrustAnchors parses DS records in presentation format, one per line:
//
//	. IN DS 20326 8 2 E06D44B8...
//	20326 8 2 E06D44B8...
//
// Blank lines and lines starting with ';' or '#' are ignored. Only root
// ('.') anchors are accepted.
func ParseTrustAnchors(text string) ([]*dnswire.DS, error) {
	var out []*dnswire.DS
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		// Strip optional "owner [ttl] [class] DS" prefix.
		if idx := indexFold(f, "DS"); idx >= 0 {
			if idx > 0 && f[0] != "." {
				return nil, fmt.Errorf("line %d: only root (.) trust anchors are supported, got %q", i+1, f[0])
			}
			f = f[idx+1:]
		}
		if len(f) < 4 {
			return nil, fmt.Errorf("line %d: expected <keytag> <algorithm> <digest-type> <digest>", i+1)
		}
		var tag, alg, dt int
		if _, err := fmt.Sscanf(f[0]+" "+f[1]+" "+f[2], "%d %d %d", &tag, &alg, &dt); err != nil ||
			tag < 0 || tag > 0xffff || alg < 0 || alg > 255 || dt < 0 || dt > 255 {
			return nil, fmt.Errorf("line %d: invalid DS fields", i+1)
		}
		digest, err := hex.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(digest) == 0 {
			return nil, fmt.Errorf("line %d: invalid hex digest", i+1)
		}
		out = append(out, &dnswire.DS{KeyTag: uint16(tag), Algorithm: uint8(alg), DigestType: uint8(dt), Digest: digest})
	}
	if len(out) == 0 {
		return nil, errors.New("no trust anchors found")
	}
	return out, nil
}

func indexFold(f []string, s string) int {
	for i, x := range f {
		if strings.EqualFold(x, s) {
			return i
		}
	}
	return -1
}

type cut struct {
	zone          string
	servers       []netip.Addr
	parentServers []netip.Addr
}

// validateChain walks from the root to the target zone validating DS and
// DNSKEY RRsets at every zone cut observed during the delegation walk.
func (d *Doctor) validateChain(ctx context.Context, rep *Report, res *walkResult) *DNSSECReport {
	out := &DNSSECReport{Status: DNSSECSecure, Chain: []ChainLink{}}
	roots := d.R.FilterFamily(d.R.Roots)
	cuts := []cut{{zone: ".", servers: roots}}
	prev := roots
	for _, ref := range res.Referrals {
		cuts = append(cuts, cut{zone: ref.Child, servers: ref.Servers, parentServers: prev})
		prev = ref.Servers
	}
	if last := cuts[len(cuts)-1].zone; last != rep.Zone {
		// Zone co-hosted with its parent: no referral was observed.
		cuts = append(cuts, cut{zone: rep.Zone, servers: res.Servers, parentServers: res.Servers})
	}

	anchors := d.Opts.TrustAnchors
	if anchors == nil {
		anchors = RootAnchors
	}
	now := d.now()
	var parentKeys []*dnswire.DNSKEY
	for i, c := range cuts {
		isTarget := c.zone == rep.Zone
		link := ChainLink{Zone: c.zone}
		var dsSet []*dnswire.DS
		if i == 0 {
			dsSet = anchors
			link.Detail = "trust anchor"
		} else {
			resp, _, _, err := d.R.queryAny(ctx, c.parentServers, c.zone, dnswire.TypeDS, true)
			if err != nil {
				return finishChain(rep, out, link, DNSSECIndeterminate, fmt.Sprintf("DS query to parent failed: %v", err))
			}
			dsRRs, sigs := rrsetAndSigs(resp.Answer, c.zone, dnswire.TypeDS)
			if len(dsRRs) == 0 {
				detail := fmt.Sprintf("no DS for %s at parent (delegation is unsigned)", c.zone)
				if isTarget {
					if keys := d.fetchKeys(ctx, c); len(keys) > 0 {
						rep.add(CheckDNSSEC, SevWarning, "%s publishes %d DNSKEY(s) but its parent has no DS: island of security, resolvers treat it as insecure", c.zone, len(keys))
					} else {
						rep.add(CheckDNSSEC, SevInfo, "%s is not DNSSEC-signed (no DS at parent)", c.zone)
					}
				} else {
					rep.add(CheckDNSSEC, SevInfo, "chain of trust ends at %s (no DS); %s is insecure", c.zone, rep.Zone)
				}
				return finishChain(rep, out, link, DNSSECInsecure, detail)
			}
			sig, err := verifyRRset(dsRRs, sigs, parentKeys, now)
			if err != nil {
				rep.add(CheckDNSSEC, SevError, "DS RRset for %s does not validate with %s keys: %v", c.zone, dnswire.Parent(c.zone), err)
				return finishChain(rep, out, link, DNSSECBogus, "DS RRset signature invalid")
			}
			d.noteExpiry(rep, &link, c.zone, "DS", sig, now)
			for _, rr := range dsRRs {
				dsSet = append(dsSet, rr.Data.(*dnswire.DS))
			}
		}
		for _, ds := range dsSet {
			link.DS = append(link.DS, ds.String())
		}

		resp, _, _, err := d.R.queryAny(ctx, c.servers, c.zone, dnswire.TypeDNSKEY, true)
		if err != nil {
			return finishChain(rep, out, link, DNSSECIndeterminate, fmt.Sprintf("DNSKEY query failed: %v", err))
		}
		keyRRs, keySigs := rrsetAndSigs(resp.Answer, c.zone, dnswire.TypeDNSKEY)
		var keys []*dnswire.DNSKEY
		for _, rr := range keyRRs {
			k := rr.Data.(*dnswire.DNSKEY)
			keys = append(keys, k)
			link.DNSKEYs = append(link.DNSKEYs, keyInfo(k))
		}
		if len(keys) == 0 {
			rep.add(CheckDNSSEC, SevError, "%s has a DS at its parent but serves no DNSKEY: zone is bogus", c.zone)
			return finishChain(rep, out, link, DNSSECBogus, "DS present but no DNSKEY")
		}

		// RFC 4035 5.2: if no DS uses a supported algorithm and digest, the
		// zone is treated as insecure.
		usable := 0
		for _, ds := range dsSet {
			if dnssec.Supported(ds.Algorithm) && supportedDigest(ds.DigestType) {
				usable++
			}
		}
		if usable == 0 {
			rep.add(CheckDNSSEC, SevWarning, "no DS for %s uses a supported algorithm/digest; treated as insecure", c.zone)
			return finishChain(rep, out, link, DNSSECInsecure, "unsupported DS algorithms")
		}

		var sepKeys []*dnswire.DNSKEY
		var unmatched []string
		for _, ds := range dsSet {
			found := false
			for _, k := range keys {
				if ok, _ := dnssec.MatchDS(c.zone, ds, k); ok {
					sepKeys = append(sepKeys, k)
					found = true
				}
			}
			if !found {
				unmatched = append(unmatched, fmt.Sprintf("%d/%s", ds.KeyTag, dnssec.AlgorithmName(ds.Algorithm)))
			}
		}
		if len(sepKeys) == 0 {
			rep.add(CheckDNSSEC, SevError, "no DNSKEY of %s matches its DS record(s) [%s]: chain of trust broken (failed KSK rollover?)", c.zone, strings.Join(unmatched, " "))
			return finishChain(rep, out, link, DNSSECBogus, "DS does not match any DNSKEY")
		}
		if len(unmatched) > 0 && i > 0 {
			rep.add(CheckDNSSEC, SevWarning, "DS record(s) for %s reference no published DNSKEY: %s (stale DS after a rollover?)", c.zone, strings.Join(unmatched, " "))
		}
		sig, err := verifyRRset(keyRRs, keySigs, sepKeys, now)
		if err != nil {
			rep.add(CheckDNSSEC, SevError, "DNSKEY RRset of %s is not validly signed by a DS-referenced key: %v", c.zone, err)
			return finishChain(rep, out, link, DNSSECBogus, "DNSKEY RRset signature invalid")
		}
		d.noteExpiry(rep, &link, c.zone, "DNSKEY", sig, now)

		if isTarget {
			d.hygiene(rep, c.zone, dsSet, keys)
			for _, t := range []dnswire.Type{dnswire.TypeSOA, dnswire.TypeNS} {
				r, _, _, err := d.R.queryAny(ctx, c.servers, c.zone, t, true)
				if err != nil {
					return finishChain(rep, out, link, DNSSECIndeterminate, fmt.Sprintf("%s query failed: %v", t, err))
				}
				rrs, sigs := rrsetAndSigs(r.Answer, c.zone, t)
				if len(rrs) == 0 {
					continue
				}
				sig, err := verifyRRset(rrs, sigs, keys, now)
				if err != nil {
					rep.add(CheckDNSSEC, SevError, "%s RRset of %s does not validate: %v", t, c.zone, err)
					return finishChain(rep, out, link, DNSSECBogus, fmt.Sprintf("%s RRset signature invalid", t))
				}
				d.noteExpiry(rep, &link, c.zone, t.String(), sig, now)
			}
		}
		link.Status = DNSSECSecure
		out.Chain = append(out.Chain, link)
		parentKeys = keys
	}
	rep.add(CheckDNSSEC, SevInfo, "DNSSEC chain of trust validates from the root to %s", rep.Zone)
	return out
}

func finishChain(_ *Report, out *DNSSECReport, link ChainLink, status, detail string) *DNSSECReport {
	link.Status = status
	if link.Detail == "" {
		link.Detail = detail
	} else {
		link.Detail += "; " + detail
	}
	out.Chain = append(out.Chain, link)
	out.Status = status
	return out
}

func (d *Doctor) fetchKeys(ctx context.Context, c cut) []dnswire.RR {
	resp, _, _, err := d.R.queryAny(ctx, c.servers, c.zone, dnswire.TypeDNSKEY, true)
	if err != nil {
		return nil
	}
	rrs, _ := rrsetAndSigs(resp.Answer, c.zone, dnswire.TypeDNSKEY)
	return rrs
}

func (d *Doctor) noteExpiry(rep *Report, link *ChainLink, zone, what string, sig *dnswire.RRSIG, now time.Time) {
	_, exp := dnssec.Validity(sig, now)
	if link.SigExpires == nil || exp.Before(*link.SigExpires) {
		e := exp
		link.SigExpires = &e
	}
	if zone != rep.Zone || d.Opts.SigExpiryWarn <= 0 {
		return
	}
	if left := exp.Sub(now); left < d.Opts.SigExpiryWarn {
		rep.add(CheckDNSSEC, SevWarning, "RRSIG over %s %s expires in %s (%s): re-signing may be stalled",
			zone, what, left.Round(time.Minute), exp.Format(time.RFC3339))
	}
}

func (d *Doctor) hygiene(rep *Report, zone string, dsSet []*dnswire.DS, keys []*dnswire.DNSKEY) {
	sha1Only := true
	for _, ds := range dsSet {
		if ds.DigestType != dnssec.DigestSHA1 {
			sha1Only = false
		}
	}
	if sha1Only {
		rep.add(CheckDNSSEC, SevWarning, "all DS records for %s use SHA-1 (digest type 1); publish a SHA-256 DS (RFC 8624)", zone)
	}
	seen := map[uint8]bool{}
	for _, k := range keys {
		if dnssec.Deprecated(k.Algorithm) && !seen[k.Algorithm] {
			seen[k.Algorithm] = true
			rep.add(CheckDNSSEC, SevWarning, "%s uses deprecated DNSSEC algorithm %s (RFC 8624); plan an algorithm rollover", zone, dnssec.AlgorithmName(k.Algorithm))
		}
	}
}

func supportedDigest(t uint8) bool {
	return t == dnssec.DigestSHA1 || t == dnssec.DigestSHA256 || t == dnssec.DigestSHA384
}

func keyInfo(k *dnswire.DNSKEY) KeyInfo {
	role := "ZSK"
	if k.Flags&dnssec.FlagSEP != 0 {
		role = "KSK"
	}
	return KeyInfo{
		KeyTag:    dnssec.KeyTag(k),
		Algorithm: dnssec.AlgorithmName(k.Algorithm),
		Flags:     k.Flags,
		Role:      role,
		Revoked:   k.Flags&dnssec.FlagRevoke != 0,
	}
}

// rrsetAndSigs splits records owned by name into the RRset of type t and
// the RRSIGs covering it.
func rrsetAndSigs(rrs []dnswire.RR, name string, t dnswire.Type) ([]dnswire.RR, []*dnswire.RRSIG) {
	var set []dnswire.RR
	var sigs []*dnswire.RRSIG
	for _, rr := range rrs {
		if !dnswire.EqualNames(rr.Name, name) {
			continue
		}
		if rr.Type == t {
			set = append(set, rr)
		}
		if s, ok := rr.Data.(*dnswire.RRSIG); ok && s.TypeCovered == t {
			sigs = append(sigs, s)
		}
	}
	return set, sigs
}

// verifyRRset returns the first RRSIG that validates rrset with one of keys.
func verifyRRset(rrset []dnswire.RR, sigs []*dnswire.RRSIG, keys []*dnswire.DNSKEY, now time.Time) (*dnswire.RRSIG, error) {
	if len(sigs) == 0 {
		return nil, errors.New("no RRSIG covering the RRset")
	}
	var errs []string
	tried := 0
	for _, s := range sigs {
		for _, k := range keys {
			if k.Algorithm != s.Algorithm || dnssec.KeyTag(k) != s.KeyTag {
				continue
			}
			tried++
			if err := dnssec.Verify(rrset, s, k, now); err != nil {
				errs = append(errs, fmt.Sprintf("key %d: %v", s.KeyTag, err))
				continue
			}
			return s, nil
		}
	}
	if tried == 0 {
		tags := make([]string, 0, len(sigs))
		for _, s := range sigs {
			tags = append(tags, fmt.Sprintf("%d", s.KeyTag))
		}
		return nil, fmt.Errorf("no trusted key matches RRSIG key tag(s) %s", strings.Join(tags, ","))
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

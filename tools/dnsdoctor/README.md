# dnsdoctor

End-to-end health check of a DNS zone, from the root servers down to every
authoritative server address — in one static binary with no third-party
dependencies.

`dig +trace` shows you one path. `dnsdoctor` walks the delegation the way a
resolver does, then interrogates **every** name server address listed by the
parent *and* the child, and validates the DNSSEC chain of trust itself.

## What it checks

| Check | What is detected |
|-------|------------------|
| `delegation` | Iterative walk from the root (RD=0). NXDOMAIN, names that are not a zone apex, CNAMEs at the apex, broken referrals. |
| `ns-consistency` | Parent NS RRset vs child NS RRset; servers that serve a different NS RRset; fewer than 2 name servers. |
| `glue` | Missing glue for in-bailiwick name servers; glue that differs from the authoritative A/AAAA records. |
| `lame-delegation` | Per address: timeout, REFUSED/SERVFAIL/NOTAUTH, answer without the AA bit, AA answer without the zone's SOA, NS host names that do not resolve. |
| `soa-serial` | SOA serial drift between all addresses (RFC 1982 serial arithmetic), with the lag of each stale server. |
| `diversity` | All addresses inside a single /24 (IPv4) or /48 (IPv6); no IPv6 at all (info). |
| `dnssec` | Chain of trust from the IANA root anchors (KSK-2017 *and* KSK-2024): DS ↔ DNSKEY match, DNSKEY/DS/SOA/NS RRSIG verification, signatures expiring soon (default 7 days), expired or not-yet-valid signatures, island of security (DNSKEY without DS), stale DS records after a rollover, SHA-1-only DS, deprecated algorithms (RFC 8624). |

Supported DNSSEC algorithms: RSASHA1 (5, 7), RSASHA256 (8), RSASHA512 (10),
ECDSAP256SHA256 (13), ECDSAP384SHA384 (14), ED25519 (15). DS digests: SHA-1,
SHA-256, SHA-384.

## Installation

Requires Go 1.22+ to build. No cgo, no external modules.

```sh
go install github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor@latest

# or from a checkout
cd tools/dnsdoctor
go build -trimpath -ldflags "-s -w -X github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor/internal/cli.Version=0.1.1" -o dnsdoctor .

# static cross-compilation, e.g. for a jump host
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dnsdoctor-linux-arm64 .
```

## Usage

```
dnsdoctor [flags] <zone> [<zone>...]

  -json                 emit a JSON array of reports on stdout
  -timeout 3s           per-query timeout
  -retries 1            UDP retries after a timeout
  -4 / -6               use IPv4 / IPv6 transport only
  -no-dnssec            skip DNSSEC chain-of-trust validation
  -trust-anchor FILE    root DS trust anchors (replaces the built-in IANA anchors)
  -sig-warn 7d          warn when a zone RRSIG expires within this duration (0 disables)
  -max-time 90s         overall time budget per zone
  -roots LIST           comma-separated root server addresses (lab/private roots)
  -port 53              DNS server port
  -concurrency 8        parallel name server probes
  -v                    log every query to stderr
  -color auto           auto, always, never (NO_COLOR is honoured)
  -version              print version
```

Flags may appear before or after zone names; both `-json` and `--json` work.

### Exit codes (Nagios/Icinga compatible)

| Code | Meaning |
|------|---------|
| 0 | OK — no warnings or errors |
| 1 | WARNING — at least one warning (NS mismatch, serial drift, expiring signatures, ...) |
| 2 | CRITICAL — at least one error (lame server, bogus DNSSEC, NXDOMAIN, not a zone apex, ...) |
| 3 | UNKNOWN — usage error, or the diagnosis could not be completed (no network, all roots unreachable) |

With several zones the highest code wins.

### Examples

```sh
dnsdoctor example.com
dnsdoctor -4 --sig-warn 3d example.com example.net
dnsdoctor --json example.com | jq '.[0].findings[] | select(.severity != "info")'

# Monitoring (NRPE / Icinga command)
dnsdoctor --color never --max-time 50s example.com

# Lab or split-horizon environment with private roots and anchors
dnsdoctor --roots 10.0.0.53 --trust-anchor ./lab-root.ds corp.lab
```

The trust anchor file contains DS records in presentation format, one per
line (`. IN DS 20326 8 2 E06D…` or `20326 8 2 E06D…`); `;` and `#` start
comments.

### Sample output

Illustrative output for a zone with a stale secondary and an extra NS
record only present in the child zone:

```
Zone: example.test.
Checked at 2026-10-09T12:00:00Z in 184 ms (22 queries)

Delegation path
  .                        -> test.                        via 192.0.2.1         21.0 ms  [DS]  ns1.nic.test. ns2.nic.test.
  test.                    -> example.test.                via 198.51.100.1      18.4 ms  [DS]  ns1.example.test. ns2.example.test.

Name servers
  ns1.example.test.  (parent+child)
      203.0.113.1                              ok           serial=2026100901     12.1 ms
  ns2.example.test.  (parent+child)
      198.51.100.53                            ok           serial=2026100801     30.7 ms
  ns3.example.test.  (child)
      203.0.113.3                              ok           serial=2026100901     11.9 ms

DNSSEC: secure
  .                            secure        KSK 20326/RSASHA256, ZSK 61809/RSASHA256 sigs until 2026-10-23
  test.                        secure        KSK 26288/ED25519, ZSK 2025/ED25519 sigs until 2026-10-30
  example.test.                secure        KSK 15616/ED25519, ZSK 11449/ED25519 sigs until 2026-10-30

Findings
  WARN  [ns-consistency] NS set mismatch between parent test. and child: only at parent [none], only at child [ns3.example.test.]
  WARN  [soa-serial] SOA serial drift: ns2.example.test. (198.51.100.53) serves 2026100801, newest is 2026100901 (behind by 100)
  INFO  [diversity] no name server has an IPv6 address
  INFO  [dnssec] DNSSEC chain of trust validates from the root to example.test.

Result: WARNING (0 error(s), 2 warning(s))
```

JSON output (abridged):

```json
[
  {
    "zone": "example.test.",
    "parent_zone": "test.",
    "delegation": [{ "parent": ".", "child": "test.", "server": "192.0.2.1", "ns": ["ns1.nic.test.", "ns2.nic.test."], "has_ds": true }],
    "parent_ns": ["ns1.example.test.", "ns2.example.test."],
    "child_ns": ["ns1.example.test.", "ns2.example.test.", "ns3.example.test."],
    "nameservers": [
      { "name": "ns2.example.test.", "in_parent": true, "in_child": true,
        "addresses": [{ "address": "198.51.100.53", "status": "ok", "authoritative": true, "rcode": "NOERROR", "soa_serial": 2026100801, "rtt_ms": 30.7 }] }
    ],
    "dnssec": { "status": "secure", "chain": [{ "zone": "example.test.", "status": "secure", "ds": ["15616 15 2 …"], "sig_expires": "2026-10-30T12:00:00Z" }] },
    "findings": [{ "check": "soa-serial", "severity": "warning", "message": "SOA serial drift: …" }],
    "summary": { "status": "warning", "errors": 0, "warnings": 2, "infos": 2 }
  }
]
```

Address `status` is one of `ok`, `lame`, `unreachable`, `skipped` (no route
for that address family from the host running the check).

## How it works

1. Queries the root servers (or `--roots`) for `<zone> NS` with RD=0 and
   EDNS0 (DO bit, 1232-byte buffer), following referrals down to the zone.
   Glue is only accepted for names inside the referring zone; glueless name
   servers are resolved iteratively (bounded depth, CNAMEs followed).
2. Merges the NS host names seen at the parent and at the child, resolves
   them, and sends `SOA` and `NS` queries to every address concurrently.
3. Re-walks the zone cuts observed in step 1 for DNSSEC: DS from the parent
   (validated with the parent's keys), DNSKEY from the zone (must be signed
   by a key matching a DS), then the target's SOA and NS RRsets.

UDP responses are matched on ID and question (mismatched or malformed
packets are ignored), truncated answers are retried over TCP (a failed TCP
fallback is reported as such, since DNS over TCP is mandatory per RFC 7766),
and old servers that reject EDNS are retried without it.

The walk itself tolerates lame servers the way a resolver does: a server
that answers NOERROR without authority and without a usable downward
referral (for example an upward referral to the root) is skipped and the
zone's next server is asked. The same rule applies to the DNSSEC walk, so an
empty non-authoritative reply is never read as "no DS" (insecure) or "no
DNSKEY" (bogus). Lame servers of the *target* zone are still reported by the
`lame-delegation` check, which probes every address individually.

## Limitations

- Insecure delegations are reported from the absence of DS in the parent's
  answer; NSEC/NSEC3 denial-of-existence proofs are not validated.
- Only zone cuts that produce a referral are validated. A child zone hosted
  on the same servers as its parent is checked, but the parent-side NS set
  cannot be observed separately (reported as info).
- Glue consistency is only checked for in-bailiwick name servers.
- No DoT/DoH transport; checks are made against authoritative servers over
  classic DNS (UDP/TCP 53), so the host needs outbound port 53 access.
- RSA keys shorter than 1024 bits are rejected by the Go runtime and show up
  as validation failures.

## Security

- Read-only: only standard DNS queries are sent; nothing is modified.
- Runs unprivileged (no raw sockets).
- No credentials are needed or stored.
- Query IDs come from `crypto/rand`; responses whose ID or question does not
  match are dropped; compression pointer loops and forward pointers are
  rejected by the parser.
- The built-in trust anchors are the IANA root KSK-2017 and KSK-2024 DS
  records (RFC 9718). Use `--trust-anchor` to pin your own.

## Development

```sh
gofmt -l . && go vet ./... && go test -race ./...
```

Tests run entirely offline against an in-memory, DNSSEC-signed DNS hierarchy
(`internal/fakedns`) and include the RFC 4034 §5.4 key tag / DS test vector.

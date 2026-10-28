# nftlint

Static analysis for Linux firewall rulesets — **nftables** (`nft -j list ruleset`)
and **iptables-save / ip6tables-save** — that answers two questions:

1. *Is the ruleset doing what its author thinks?* Shadowed, redundant and
   unreachable rules, chains nothing jumps to, any-any accepts, permissive
   default policies, management ports open to the world, IPv4 filtered but
   IPv6 wide open.
2. *What is actually reachable on this host, and from where?* Given the
   output of `ss -tulnp`, every listening socket is run through the input
   path and classified as **open**, **restricted** (with the exact allowed
   source prefixes), **conditional**, **filtered** or **unfiltered**.

Pure Python (3.9+), standard library only, no root needed to analyse exported
files. nftlint **never modifies the firewall**.

## How it works

Rules from both formats are normalised into one model: every match is a set
of constraints over packet dimensions (nfproto, L4 protocol, source and
destination ports, IPv4/IPv6 source and destination addresses, conntrack
state, input/output interface) stored as exact integer interval sets. That
makes set algebra exact, including negations (`ip saddr != 10.0.0.0/8`),
ranges, prefixes, anonymous and named sets, and IPv6.

* **Shadowing** — a rule is dead if an earlier *terminal* rule in the same
  chain (accept, drop, reject, goto, return) matches a superset of its
  packets. A different verdict means the rule's intent is silently ignored
  (`NFT001`, high); the same verdict means it is merely redundant (`NFT002`).
* **Exposure** — a synthetic first packet (`ct state new`, non-loopback input
  interface, destined to the socket's address/port) is evaluated
  symbolically through every base chain on the `input` hook, in priority
  order, following `jump`/`goto`/`return` and verdict maps. The **source
  address stays symbolic**: each rule splits the remaining source space, so
  the result is the exact set of accepted sources.
* **Conservative by construction** — anything nftlint does not model (rate
  limits, marks, dynamic sets, `fib`, iptables-nft `xt` matches, unknown
  iptables modules, ...) is kept as an *opaque* condition. An opaque rule can
  never shadow another one, an opaque accept yields a *conditional* exposure,
  and an opaque drop is listed as a caveat rather than assumed to apply.

## Checks

| Code | Name | Severity | Detected |
|------|------|----------|----------|
| `NFT001` | shadowed-rule | high (medium for jumps) | Rule fully covered by an earlier rule with a different verdict — it never fires |
| `NFT002` | redundant-rule | low | Rule fully covered by an earlier rule with the same verdict class |
| `NFT003` | unreachable-rule | medium | Rules after a catch-all terminal rule; contradictory matches |
| `NFT004` | unreachable-chain | low | Regular chain not reachable from any base chain |
| `NFT005` | any-any-accept | high / low | Accept with no address, port or protocol restriction on `input`/`forward` (low when only an interface restricts it). `iif lo`, established/related and ICMP-only accepts are not reported |
| `NFT006` | permissive-policy | high (input) / medium (forward) | Policy accept with no catch-all deny, considering **all** base chains on the same hook and family |
| `NFT007` | sensitive-port-open | medium | Input accept for SSH, RDP, SMB, SNMP, databases, Redis, Docker, etcd, kubelet... from any (or almost any) source |
| `NFT008` | exposed-sensitive-service | high | A listening sensitive service is reachable from any (or almost any) source |
| `NFT009` | stale-opening | low | Input accept for TCP/UDP ports nothing listens on |
| `NFT010` | no-ipv6-filtering | medium | nftables ruleset filters IPv4 input but has no IPv6 input chain |
| `NFT011` | exposed-by-default | medium | A listening service is reachable only because of a default-accept policy |
| `NFT012` | iptables-nft-compat | info | `xt` compatibility expressions present (use `iptables-save` instead) |
| `NFT013` | undefined-chain | medium | jump/goto to a chain that does not exist |
| `NFT014` | family-not-analysed | medium | Sockets accept IPv6 (or IPv4) traffic but no ruleset for that family was given |
| `NFT000` | partial-analysis | info | Summary of opaque expressions; live socket listing unavailable |

Exposure statuses: `open` (any source), `restricted` (subset of sources,
shown as prefixes or "any except ..."), `conditional` (only via conditions
nftlint cannot evaluate), `filtered`, `unfiltered` (no input chain for the
family), `unknown` (family not analysed), `local` (loopback only).

## Installation

```sh
pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/nftlint"
# or, from a checkout
pip install ./tools/nftlint
# or without installing
PYTHONPATH=tools/nftlint/src python3 -m nftlint --help
```

## Usage

```sh
# Export on the host (root needed for the ruleset, not for ss)...
sudo nft -j list ruleset > rules.json
ss -tulnp > ss.txt            # sudo adds process names
# ...and analyse anywhere, no privileges needed.
nftlint rules.json --ss ss.txt

# iptables hosts: give both families
sudo iptables-save > v4.txt; sudo ip6tables-save > v6.txt
nftlint v4.txt -6 v6.txt --ss ss.txt

# Directly on the host (read-only: nft -j list ruleset, falling back to
# iptables-save/ip6tables-save, and ss -tulnpH)
sudo nftlint --live

# CI / monitoring
nftlint rules.json --json > report.json
nftlint rules.json --min-severity medium --ignore NFT002,NFT009
nftlint rules.json --sensitive-ports '22,3389,5432/postgres,6000-6010/x11'
```

| Option | Meaning |
|--------|---------|
| `RULESET...` | nft JSON or iptables-save files, `-` for stdin. iptables files are IPv6 when the name contains `ip6` or the content has IPv6 addresses |
| `-6, --ip6tables FILE` | ip6tables-save file (forces IPv6), repeatable |
| `-F, --format` | `auto` (default), `nft-json`, `iptables-save` |
| `--ss FILE` | `ss -tulnp` / `ss -tlnp` output, with or without header; numeric output (`-n`) is required and checked, scoped sockets such as `[fe80::1]%eth0:546` are supported |
| `--live` | Read the running ruleset and sockets when no file is given |
| `--timeout S` | Timeout of each `--live` command (default 15 s) |
| `--json` | Machine-readable report (findings + exposure) |
| `--min-severity` | Hide findings below a severity (also excluded from the exit code) |
| `--ignore CODE` | Suppress codes, repeatable or comma-separated |
| `--sensitive-ports` | Replace the built-in sensitive port list. The built-in list is protocol-aware (UDP only counts for rpcbind, SNMP, CLDAP, IPMI, NFS, RDP and memcached); a custom list applies to every protocol |
| `-v, --verbose` | Show the deciding rules in the exposure table |

### Exit codes

Nagios/Icinga compatible: `0` nothing above low, `1` at least one medium
finding, `2` at least one high finding, `3` input or usage error (unreadable
file, unknown format, `nft` failure in `--live` mode).

## Sample output

From [`tests/fixtures/server.nft`](tests/fixtures/server.nft) (exported as
JSON) and [`tests/fixtures/ss.txt`](tests/fixtures/ss.txt):

```
nftlint 0.1.0: server.json (nft-json, 1 table(s), 4 chain(s), 21 rule(s))

[HIGH  ] NFT008 exposed-sensitive-service  socket tcp/6379 0.0.0.0
         tcp/6379 (redis-server on 0.0.0.0) is reachable from any IPv4 source: an explicit rule accepts it from any source

[HIGH  ] NFT001 shadowed-rule  inet filter input #9 (handle 16)
         rule: tcp dport 8443 accept
         rule never matches: every packet it targets is already handled by #8 `tcp dport 8443 drop` with a different verdict (drop instead of accept)

[MEDIUM] NFT003 unreachable-rule  inet filter forward #2 (handle 30)
         rule: ip daddr 10.0.0.0/8 drop
         rule #2 is never evaluated: #1 `accept` matches every packet first

[LOW   ] NFT002 redundant-rule  inet filter input #7 (handle 14)
         rule: tcp dport 443 accept
         rule is redundant: fully covered by #6 `tcp dport { 80, 443 } accept` (accept), it can be removed

[INFO  ] NFT000 partial-analysis  ruleset
         server.json: 2 expression(s) are not modelled and are handled conservatively (e.g. `ip saddr @f2b`, `limit rate 5/second`)

Exposure of listening sockets (first packet, ct state new, non-loopback):
  PROTO  ADDRESS          PORT  PROCESS          STATUS      DETAIL
  tcp    0.0.0.0          6379  redis-server     open        IPv4: any source (1 unevaluated drop condition(s))
  tcp    *                9100  node_exporter    open        IPv4: from 10.0.0.0/8 (1 unevaluated drop condition(s)); IPv6: any source
  tcp    0.0.0.0          22    sshd             restricted  IPv4: from 10.10.0.0/16, 192.0.2.10/32 (1 unevaluated drop condition(s))
  tcp    0.0.0.0          5432  postgres         restricted  IPv4: from 10.20.0.0/16 (1 unevaluated drop condition(s))
  tcp    [::]             22    sshd             filtered    IPv6: dropped
  tcp    127.0.0.1        3306  mariadbd         local       loopback only

Summary: 4 high, 4 medium, 2 low, 1 info -> CRITICAL (exit 2)
```

(The "unevaluated drop condition" is `ip saddr @f2b drop`: a fail2ban-style
set with timeouts whose content changes at runtime.)

`--json` produces `{tool, version, sources, summary, status, exit_code,
findings[], exposure[]}`; each finding carries its code, severity, location
(source, family, table, chain, rule index, nft handle or iptables-save line),
the rule text and, for shadowing, the covering rule.

## Limitations

* **nftables text syntax is not parsed** — export with `nft -j list ruleset`
  (the JSON is the stable, fully-resolved representation).
* Shadowing is **pairwise**: a rule covered only by the *union* of several
  earlier rules is not reported (no false positives, some false negatives).
* Named sets are evaluated with their **current elements**; sets flagged
  `dynamic` or `timeout` are treated as opaque. Concatenations, maps other
  than verdict maps, `fib`, marks, meters, rate limits and ICMP types are
  opaque.
* The exposure model covers the `input` hook of `filter` chains. Traffic
  dropped earlier (e.g. iptables `raw`/`mangle` tables, `netdev` ingress,
  `prerouting` filter chains) or redirected by DNAT is not modelled; the
  `forward` path is only checked statically.
* Unknown input interfaces and unknown local addresses (wildcard sockets) are
  handled as "maybe": rules depending on them make the result conditional or
  add a caveat. Multicast/broadcast/loopback destination matches are
  recognised as never matching unicast traffic to a wildcard socket.
* `ss` semantics: `*:port` is a dual-stack socket, `[::]:port` an IPv6-only
  (`IPV6_V6ONLY`) socket, `0.0.0.0:port` IPv4 only. `ss` without root does
  not show process names; the analysis is unaffected.
* When both iptables-legacy and nftables rulesets are loaded in the kernel,
  analyse both exports together — nftlint merges all given sources.

## Security

* Read-only: nftlint reads files or runs `nft -j list ruleset`,
  `iptables-save`, `ip6tables-save` and `ss -tulnpH` (no shell, fixed
  arguments, `LC_ALL=C`, timeout). It never calls `nft -f`, `iptables`
  or anything that changes state.
* Listing the ruleset needs `CAP_NET_ADMIN` (root); the analysis itself does
  not. The recommended pattern is to export on the host and analyse
  elsewhere — exported rulesets reveal your network layout, so treat them as
  sensitive files.
* No network access, no third-party dependencies.

## Development

```sh
cd tools/nftlint
pip install -e ".[test]" ruff
ruff check . && ruff format --check . && pytest -q
```

The JSON fixtures in `tests/fixtures/` are real `nft -j list ruleset` output
generated from the `.nft` files next to them, e.g.
`unshare -rn sh -c 'nft -f server.nft && nft -j list ruleset'`.

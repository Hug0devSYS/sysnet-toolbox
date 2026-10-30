# subnet-planner

IPv4/IPv6 address planning and IPAM hygiene in one static binary:

- **`plan`** — VLSM allocation inside a parent prefix from host counts or
  prefix lengths, around the space already in use (NetBox export, CSV,
  JSON, plain list). Largest first, best fit, so the free space stays as
  contiguous as possible. Text, JSON, CSV or a NetBox prefix-import CSV.
- **`check`** — duplicates and overlaps in prefix and IP address
  inventories: duplicate prefixes and addresses per VRF, prefixes nested in
  non-container prefixes, host bits set, addresses outside every documented
  prefix, address masks that disagree with their subnet, network/broadcast
  addresses assigned to hosts, optional cross-VRF overlaps.
- **`aggregate`** — route summarisation: the exact minimal prefix list, or
  at most *N* prefixes per family with the fewest extra addresses
  (`--max`), as a plain list or a Cisco / Junos prefix-list.
- **`free`** — the unallocated space of a parent prefix, optionally split
  into subnets of a given size.
- **`info`** — subnet calculator: mask, wildcard, ranges, sizes, address
  type from the IANA special-purpose registries (RFC 6890 and updates),
  reverse DNS zones (with RFC 2317 / nibble-boundary notes), subnet listing.

Everything is offline and read-only: the tool only reads files (or stdin)
and prints results. No dependencies outside the Go standard library; exact
128-bit arithmetic for IPv6.

## Installation

```sh
go install github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner@latest
# or, from a checkout
cd tools/subnet-planner && go build -trimpath -ldflags "-s -w" -o subnet-planner .
```

Any OS supported by Go; no privileges needed.

## Usage

```
subnet-planner plan      --parent PREFIX [flags] NAME=SIZE... | -f requests.csv
subnet-planner check     [flags] FILE...
subnet-planner aggregate [flags] [PREFIX...] [-f FILE]
subnet-planner free      --parent PREFIX [--used FILE] [--exclude PREFIX] [--split N]
subnet-planner info      [--split N] PREFIX|ADDRESS...
```

`subnet-planner COMMAND --help` lists every flag. Flags may appear before
or after the positional arguments.

### Input formats

Every command that reads an inventory (`check`, `plan --used`,
`free --used`, `aggregate -f`) auto-detects:

| Format | Detection | Notes |
|--------|-----------|-------|
| CSV with a header | first line contains `,` `;` tab or `\|` | Column names are matched case-insensitively, ignoring spaces, `_`, `-`: prefix = `prefix`/`network`/`subnet`/`cidr`; address = `address`/`ip address`/`ip`; plus `vrf`, `status`, `role`, `name`/`description`/`dns name`, `vlan`/`vid`, `site`/`scope`. NetBox table exports and "all data" exports work as is; a UTF-8 BOM (Excel) is skipped. |
| CSV without header | first cell is a prefix | column 1 = prefix, column 2 = name |
| JSON | starts with `{` or `[` | NetBox API responses (`{"results": [...]}`, nested `vrf`/`status`/`role`/`vlan` objects), `subnet-planner plan --json` output, or an array of prefix strings |
| Plain list | anything else | one prefix per line, rest of the line = name, `#` comments |

Prefixes may be written `10.1.0.0/16`, `10.1.0.0/255.255.0.0` or as a bare
address (host route); IPv4-mapped IPv6 is converted to IPv4. VRF values
`Global`, `-`, `default` or empty all mean the global table. Invalid rows
are reported with file and line and never abort the run.

## `plan` — VLSM allocation

```sh
subnet-planner plan --parent 10.20.0.0/16 --used netbox-prefixes.csv \
  -f subnets.csv --allow-31 --growth 20
```

`subnets.csv` (header optional; `name size [vlan] [note]` separated by
spaces also works):

```
name,size,vlan,note
users,500,10,floor 1-3
voice,120,20
wifi-guest,1000,30
printers,30,40
mgmt,/26,99,out of band
transit-fw,/31
```

`netbox-prefixes.csv` (exported from NetBox; the `/16` container itself is
recognised as the parent's own record and ignored):

```
Prefix,Status,VRF,Site,VLAN,Description
10.20.0.0/16,Container,,PAR1,,Paris campus
10.20.0.0/22,Active,,PAR1,,legacy servers
10.20.8.0/24,Reserved,,PAR1,,lab
```

Output:

```
Parent 10.20.0.0/16 (65536 addresses)
In use: 2 prefixes excluded

NAME                  REQUESTED   PREFIX           USABLE RANGE                 GATEWAY      USABLE  USE
users (vlan 10)       500 hosts   10.20.4.0/22     10.20.4.1 - 10.20.7.254      10.20.4.1    1022    49%
voice (vlan 20)       120 hosts   10.20.9.0/24     10.20.9.1 - 10.20.9.254      10.20.9.1    254     47%
wifi-guest (vlan 30)  1000 hosts  10.20.16.0/21    10.20.16.1 - 10.20.23.254    10.20.16.1   2046    49%
printers (vlan 40)    30 hosts    10.20.10.0/26    10.20.10.1 - 10.20.10.62     10.20.10.1   62      48%
mgmt (vlan 99)        /26         10.20.10.64/26   10.20.10.65 - 10.20.10.126   10.20.10.65  62
transit-fw            /31         10.20.10.128/31  10.20.10.128 - 10.20.10.129  -            2

Allocated 3458 of 65536 addresses; 60798 free in 12 block(s)
  free 10.20.10.130/31
  ...
  free 10.20.128.0/17
```

`voice` lands in `10.20.9.0/24` next to the reserved lab `/24` rather than
in the untouched `10.20.12.0/22`: best fit keeps large blocks intact.

| Flag | Default | Meaning |
|------|---------|---------|
| `--parent` | required | Prefix to carve. |
| `NAME=SIZE`, `-f FILE` | | Requests: `SIZE` is a usable host count (`120`) or a prefix length (`/26`). `-f -` reads stdin. |
| `--used FILE` | | Inventory of prefixes/addresses already in use (repeatable). Rows equal to or containing the parent are ignored. |
| `--exclude PREFIX` | | Extra prefix never to allocate (repeatable). |
| `--vrf NAME` | all | Only `--used` rows of this VRF consume space; also written in `--format netbox`. |
| `--growth PCT` | `0` | Add a percentage to every host count. |
| `--reserve N` | `0` | Add N addresses to every host count (gateway, FHRP peers, ...). |
| `--allow-31` | off | `/31` (RFC 3021) for 2 hosts, `/32` for 1 host. Without it a 2-host request gets a `/30`. |
| `--v6-len` | `64` | Longest IPv6 prefix for host-count requests (SLAAC needs a `/64`); `0` = exact size. |
| `--order` | `size` | `size` (largest first, best packing) or `input` (allocate in the given order). |
| `--gateway` | `first` | Gateway convention shown: `first`, `last`, `none`. |
| `--format` | `text` | `text`, `json`, `csv`, `netbox` (columns `prefix,status,description[,vrf]` for NetBox *Import*; status from `--netbox-status`, default `reserved`). |
| `--json` | | Same as `--format json`. |

Sizing rules: an IPv4 subnet for *H* hosts has at least *H* usable
addresses (network and broadcast excluded). IPv6 host counts are rounded up
to `--v6-len`; explicit IPv6 lengths longer than `/64` (other than `/127`
and `/128`) produce a WARNING. When requests do not fit, the summary gives
the smallest empty parent that would hold all of them (largest-first
power-of-two packing is optimal, so this bound is exact).

Exit codes: `0` all allocated, `1` warnings, `2` at least one request not
allocated, `3` usage or input error.

## `check` — inventory conflicts

```sh
subnet-planner check netbox-prefixes.csv netbox-ip-addresses.csv
curl -s -H "Authorization: Token $NETBOX_TOKEN" -H "Accept: application/json" \
  "https://netbox.example.net/api/ipam/prefixes/?limit=0" | subnet-planner check -
```

```
CRITICAL duplicate-prefix [vrf global]: 10.20.0.0/24 is declared 2 times in VRF global
    prefixes.csv:3  10.20.0.0/24 (users, vlan 10, site PAR1; status active)
    prefixes.csv:6  10.20.0.0/24 (users duplicate, site PAR1; status reserved)
CRITICAL duplicate-address [vrf global]: 10.20.0.1 is assigned 2 times in VRF global (set a shared role such as anycast/vrrp if intended)
    ips.csv:2  10.20.0.1/24 (gw1; status active)
    ips.csv:3  10.20.0.1/24 (gw1-dup; status active)
WARNING nested-in-assigned [vrf global]: 10.20.1.128/25 is nested inside 10.20.1.0/24, whose status is "active" (only containers should hold child prefixes)
    prefixes.csv:5  10.20.1.128/25 (printers (oops), site PAR1; status active)
    prefixes.csv:4  10.20.1.0/24 (voice, vlan 20, site PAR1; status active)
WARNING reserved-address [vrf global]: 10.20.0.0 is the network address of 10.20.0.0/24
    ips.csv:6  10.20.0.0/24 (network-addr; status active)
WARNING mask-mismatch [vrf global]: 10.20.1.5/16 has a shorter mask than its subnet 10.20.1.0/24: hosts configured this way see a wrong on-link range
    ips.csv:7  10.20.1.5/16 (bad-mask; status active)
    prefixes.csv:4  10.20.1.0/24 (voice, vlan 20, site PAR1; status active)
WARNING orphan-address [vrf global]: 10.99.0.1/24 is not inside any documented prefix of VRF global
    ips.csv:8  10.99.0.1/24 (orphan; status active)

CRITICAL - 15 entries checked, 2 critical, 6 warning(s) | global: 6 prefixes, 8 addresses; CUST-A: 1 prefixes, 0 addresses
```

| Code | Severity | Meaning |
|------|----------|---------|
| `duplicate-prefix` | CRITICAL | Same prefix more than once in one VRF. |
| `overlap` | WARNING (CRITICAL with `--nesting deny`) | Prefix nested in another whose status is unknown (plain lists, missing status). |
| `nested-in-assigned` | WARNING | Prefix nested in an `active`/`reserved`/`deprecated` prefix; nesting under `container` is normal and not reported. |
| `host-bits-set` | WARNING | Prefix written with host bits (`10.0.0.5/24`): an address in the prefix list. |
| `duplicate-address` | CRITICAL | Same IP twice in one VRF, unless every occurrence has a shared role (`--shared-roles`, default `anycast,vip,vrrp,hsrp,glbp,carp`). |
| `orphan-address` | WARNING | Address outside every documented prefix of its VRF (only when prefixes were loaded). |
| `mask-mismatch` | WARNING | Address mask shorter than its subnet, or longer than a non-container subnet. Host masks (`/32`, `/128`: loopbacks, VIPs) are accepted. |
| `reserved-address` | WARNING | IPv4 network or broadcast address, or IPv6 subnet-router anycast address (RFC 4291), assigned to a host. |
| `cross-vrf-overlap` | WARNING | With `--cross-vrf`: overlap between VRFs (a conflict once routes leak). |
| `invalid-entry` | WARNING | Unparseable row. |

Flags: `--nesting auto|allow|deny`, `--ignore-vrf` (one routing table),
`--cross-vrf`, `--shared-roles LIST`, `-q` (summary only), `--json`.

Exit codes: `0` clean, `1` warnings, `2` critical findings, `3` input
error — usable directly as a Nagios/Icinga check or a CI gate on an IPAM
export.

## `aggregate` — route summarisation

```sh
$ subnet-planner aggregate --max 3 10.1.0.0/24 10.1.1.0/24 10.1.2.0/24 10.1.4.0/24 \
    10.1.5.0/24 10.1.200.0/24 10.1.201.0/24 192.0.2.0/25
10.1.0.0/21
10.1.200.0/23
192.0.2.0/25
subnet-planner aggregate: 8 prefixes in, 3 out (lossy: +768 IPv4 and +0 IPv6 addresses not in the input)

$ subnet-planner aggregate -f customer-routes.txt --format cisco --name CUST-IN
ip prefix-list CUST-IN seq 5 permit 10.1.0.0/22
...
```

Without `--max` the result covers exactly the input addresses with the
fewest prefixes. With `--max N` each address family is reduced to at most
N prefixes by repeatedly merging neighbours into their common supernet,
choosing at each step the merge that adds the fewest addresses not in the
input; the total extra space is reported (stderr, or JSON). Each step is
optimal, the whole is a greedy approximation. Summary lines go to stderr so
stdout can be pasted into a device configuration.

Formats: `plain`, `cisco` (`ip prefix-list` / `ipv6 prefix-list`),
`junos` (`set policy-options prefix-list`), `json`.

## `free` and `info`

```sh
$ subnet-planner free --parent 10.0.0.0/22 --used prefixes.txt
10.0.0.128/25
10.0.2.0/23
subnet-planner free: 640 of 1024 addresses free in 10.0.0.0/22

$ subnet-planner info 192.168.10.37/26
Address:       192.168.10.37
Prefix:        192.168.10.0/26
Netmask:       255.255.255.192
Wildcard:      0.0.0.63
Network:       192.168.10.0
Broadcast:     192.168.10.63
Usable range:  192.168.10.1 - 192.168.10.62
Addresses:     64 total, 62 usable
Type:          private-use (RFC 1918), not globally routable
Reverse DNS:   10.168.192.in-addr.arpa
               smaller than a /24: delegate with RFC 2317 classless CNAMEs inside 10.168.192.in-addr.arpa
```

`free --split 24` lists the free space as `/24`s (smaller fragments are
omitted, `--limit` caps the output); `info --split N` lists the subnets of
a prefix. Both support `--json`.

## JSON output

Every command has `--json`. Address counts that do not fit a JSON number
exactly (above 2^53, i.e. most IPv6 sizes) are encoded as decimal strings.
`plan --json` output can be fed back to `check` or used as `--used` for a
later plan.

## Limitations

- `check` reads exports; it does not query NetBox itself. Use the API with
  `?limit=0` (or paginate) and pipe the JSON, or export CSV from the UI.
- NetBox accepts duplicate prefixes in the global table and in VRFs
  without `enforce_unique`; `check` reports them anyway because they are
  usually mistakes. Intentional duplicates (e.g. per-site NAT ranges)
  belong in separate VRFs.
- `plan` does not align allocations beyond their own size (no "start each
  site on a /20 boundary" rule); plan the site blocks first, then each site.
- `aggregate --max` is greedy, not globally optimal, and may return fewer
  than N prefixes when a merge lets siblings collapse.
- Input files are limited to 256 MiB.

## Security

Offline and read-only: no network access, no writes, no privileges. NetBox
API tokens are never handled by the tool (the `curl` examples keep them in
your shell environment). Inventory exports may be sensitive; the tool does
not log or transmit them.

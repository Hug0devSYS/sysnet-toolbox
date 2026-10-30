<p align="center"><img src="assets/logo-512.png" alt="sysnet-toolbox logo" width="128"></p>

# sysnet-toolbox

A collection of focused, production-grade command-line tools for systems and
network engineers: DNS/TLS/MTU diagnostics, firewall and network-config
auditing, topology discovery, inventory and lightweight monitoring.

Every tool in this repository follows the same rules:

- **Defensive scope only** — diagnostics, auditing, administration and
  automation. No offensive tooling.
- **Read-only by default.** Anything that could change a system requires an
  explicit flag (`--apply` or equivalent).
- **Scriptable.** `--help`, a `--json` output mode and meaningful exit codes
  (Nagios/Icinga-compatible `0/1/2/3` where it makes sense).
- **Robust networking.** Timeouts and retries on every network call, no
  hard-coded secrets, unprivileged operation whenever possible.
- **Tested.** Unit tests mock the network and the system; CI runs lint and
  tests for every language present.

## Tools

| Tool | Language | Description | Status |
|------|----------|-------------|--------|
| [dnsdoctor](tools/dnsdoctor/) | Go | End-to-end DNS zone diagnostics: iterative walk from the root, parent/child NS consistency, glue, lame delegations, SOA serial drift, DNSSEC chain of trust. | Beta (v0.1.1) |
| [tlsaudit](tools/tlsaudit/) | Go | TLS fleet audit: expiry, incomplete/untrusted chains, SAN mismatch, SSLv3–TLS 1.3, full cipher suite enumeration, DHE strength, OCSP stapling, STARTTLS; text/JSON/summary output and Prometheus textfile metrics. | Beta (v0.1.1) |
| [nftlint](tools/nftlint/) | Python | nftables / iptables-save static analysis: shadowed, redundant and unreachable rules, any-any accepts, permissive policies, missing IPv6 filtering; correlates `ss` listening sockets with the input path to show what is really reachable and from which sources. | Beta (v0.1.1) |
| [netcfg-diff](tools/netcfg-diff/) | Python | Semantic diff of Cisco IOS/IOS-XE/NX-OS/IOS-XR/EOS, Junos (brace or set) and FortiOS configurations: hierarchical, order-aware (ACLs, firewall policies, policy chains), modifications instead of remove+add, secrets masked; text/JSON/summary and Junos set/delete/insert output, directory mode for backup trees. | Beta (v0.1.1) |
| [pmtud-probe](tools/pmtud-probe/) | Go | Path MTU discovery for IPv4/IPv6 without privileges: PMTUD black-hole detection (silent drops vs ICMP fragmentation-needed / packet-too-big), broken ICMP, TCP MSS clamping check; text/JSON output, Nagios exit codes. | Beta (v0.1.0) |
| [lldp-mapper](tools/lldp-mapper/) | Python | Layer-2 topology discovery over SNMP (LLDP-MIB, CISCO-CDP-MIB) into text, JSON, Mermaid or Graphviz; flags duplex, speed, auto-negotiation and native VLAN mismatches, one-way adjacencies and miscabled ports; scoped crawling, SNMPv1/v2c built in, SNMPv3 via net-snmp. | Beta (v0.1.0) |
| [subnet-planner](tools/subnet-planner/) | Go | IPv4/IPv6 VLSM planning around the space already used in a NetBox/CSV export (NetBox-importable output), IPAM conflict checks (duplicate/nested prefixes, duplicate/orphan addresses, mask mismatches per VRF), exact or bounded route aggregation with Cisco/Junos prefix-lists, free space, subnet calculator. | Beta (v0.1.0) |
| [sysnet-presence](tools/discord-presence/) | Python | Optional Discord Rich Presence for the toolbox: `sysnet-presence -- <tool> ...` shows the running tool with the toolbox logo on your Discord profile (local IPC only, arguments never shown). | Beta (v0.1.0) |

Planned tools and their priority are tracked in [ROADMAP.md](ROADMAP.md).

## Layout

```
tools/<tool-name>/   code, tests, README and dependency file for one tool
.github/workflows/   CI (only runs jobs for languages that are present)
.toolbox/state.json  maintenance metadata (versions, run history)
assets/              logo (SVG source, 512 and 1024 px PNG)
```

Each tool is self-contained: it has its own dependency manifest (`go.mod`,
`pyproject.toml`, ...) and can be built or installed independently.

## Quick start

```sh
# Go tools
go install github.com/Hug0devSYS/sysnet-toolbox/tools/dnsdoctor@latest
dnsdoctor example.com

go install github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit@latest
tlsaudit --summary www.example.com smtp://mx.example.com

go install github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe@latest
pmtud-probe --tcp 443 vpn-peer.example.net

go install github.com/Hug0devSYS/sysnet-toolbox/tools/subnet-planner@latest
subnet-planner plan --parent 10.20.0.0/16 --used netbox-prefixes.csv users=500 voice=120 transit=/31
subnet-planner check netbox-prefixes.csv netbox-ip-addresses.csv

# Python tools
pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/nftlint"
sudo nft -j list ruleset > rules.json && ss -tulnp > ss.txt
nftlint rules.json --ss ss.txt

pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/netcfg-diff"
netcfg-diff edge-r1.2026-10-20.cfg edge-r1.2026-10-21.cfg

pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/lldp-mapper"
SNMP_COMMUNITY=... lldp-mapper --crawl --scope 10.10.0.0/16 core1 --graph topology.mmd

# Optional: show the running tool on your Discord profile (see tools/discord-presence)
sysnet-presence -- netcfg-diff old.cfg new.cfg
```

See each tool's README for installation, usage, sample output, limitations
and security notes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are tracked in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © Hug0devSYS

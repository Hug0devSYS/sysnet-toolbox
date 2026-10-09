# Roadmap

Ideas are built in priority order. The initial backlog (items 1–13) was
validated by the repository owner and is worked through in order before newer
ideas, unless a new idea is clearly more valuable.

Effort scale: **S** (< 1 day), **M** (1–3 days), **L** (> 3 days).

## Backlog

### P1

| # | Tool | Language | Problem solved | Effort |
|---|------|----------|----------------|--------|
| 2 | `tlsaudit` | Go | Scan a fleet of TLS endpoints: certificate expiry, incomplete chains, SAN mismatch, weak protocols/ciphers, OCSP stapling. JSON output plus a Prometheus textfile-collector file. | M |
| 3 | `nftlint` | Python | Analyse nftables / `iptables-save` rulesets: shadowed rules, unreachable rules, any-any rules, exposed ports compared with `ss -tlnp`. | M |
| 4 | `netcfg-diff` | Python | Semantic diff of Cisco IOS/NX-OS, Junos and FortiOS configurations (hierarchical comparison, ignores non-significant ordering). | L |

### P2

| # | Tool | Language | Problem solved | Effort |
|---|------|----------|----------------|--------|
| 5 | `pmtud-probe` | Go | Path MTU discovery and PMTUD black-hole detection, MSS clamping verification, IPv4/IPv6. | M |
| 6 | `lldp-mapper` | Python | Topology discovery via SNMP LLDP-MIB/CDP into Mermaid/Graphviz/JSON; duplex and native VLAN mismatch detection. | M |
| 7 | `subnet-planner` | Go | VLSM planning for IPv4/IPv6, overlap detection in a CSV/NetBox export, route aggregation. | M |
| 8 | `syslog-triage` | Go | Ingest syslog/journald, cluster messages by pattern (Drain algorithm), detect spikes. | L |
| 9 | `cert-inventory` | PowerShell | Inventory certificate stores across a Windows fleet over WinRM: expirations, ADCS templates, exportable private keys. | M |

### P3

| # | Tool | Language | Problem solved | Effort |
|---|------|----------|----------------|--------|
| 10 | `ntp-skew` | Go | Offset/stratum of several NTP sources, falseticker detection. | S |
| 11 | `rogue-dhcp` | Python | Passive listening for DHCP offers, alert on any unauthorised server. | S |
| 12 | `disk-forecast` | Bash | Forecast filesystem saturation by regression over `df` history; cron/Nagios output. | S |
| 13 | `bgp-sanity` | Python | RPKI/ROA validity, IRR consistency and global visibility of announced prefixes via RIPEstat. | M |

### New ideas (after the initial backlog)

| Tool | Language | Priority | Problem solved | Effort |
|------|----------|----------|----------------|--------|
| `mail-dns-audit` | Go | P2 | Audit a domain's mail-related DNS in one pass: SPF (syntax, 10-lookup limit, `+all`), DKIM selectors, DMARC policy/alignment, MTA-STS policy fetch and TLS-RPT, DANE TLSA vs the live MX certificate. Reuses dnsdoctor's resolver and DNSSEC validation. | M |
| `ssh-hostkey-audit` | Go | P2 | Inventory SSH host keys and negotiated algorithms across a fleet (pre-auth handshake only): weak KEX/ciphers/MACs, RSA keys < 3072 bits, DSA keys, and host-key drift against a stored baseline or `known_hosts`. | M |
| `conntrack-watch` | Bash | P3 | Watch Linux conntrack table usage (`nf_conntrack_count` vs `_max`), forecast exhaustion, report top source/destination tuples and per-state counts; Nagios/Prometheus textfile output. | S |

## Done

| # | Tool | Language | Version | Date |
|---|------|----------|---------|------|
| 1 | [`dnsdoctor`](tools/dnsdoctor/) | Go | 0.1.0 | 2026-10-09 |

`dnsdoctor` — end-to-end DNS diagnostics: iterative resolution from the root,
lame delegations, parent/child NS consistency, SOA serial drift between
secondaries, DNSSEC chain validation.

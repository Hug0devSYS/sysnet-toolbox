# Roadmap

Ideas are built in priority order. The initial backlog (items 1–13) was
validated by the repository owner and is worked through in order before newer
ideas, unless a new idea is clearly more valuable.

Effort scale: **S** (< 1 day), **M** (1–3 days), **L** (> 3 days).

## Backlog

### P1

| # | Tool | Language | Problem solved | Effort |
|---|------|----------|----------------|--------|
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
| `ct-watch` | Go | P2 | Watch Certificate Transparency for certificates issued for your own domains (crt.sh / CT log APIs): alert on unexpected issuers (compared with CAA records and an allow-list), unknown SANs and certificates not seen by `tlsaudit` in production. | M |
| `cfg-vault` | Python | P2 | Scheduled configuration backup of network devices (SSH/NETCONF, Netmiko-compatible device types) into a git repository, with secret redaction (passwords, SNMP communities, keys), per-device diffs and a change report; read-only towards devices. | M |
| `l2-guard` | Python | P3 | Passive ARP/NDP monitoring on a segment: duplicate IP addresses, default-gateway MAC changes, unexpected IPv6 router advertisements (rogue RA), flip-flopping hosts; syslog/JSON alerts. Complements `rogue-dhcp`. | S |
| `wg-audit` | Python | P2 | Audit WireGuard configurations and live state (`wg show all dump`, `wg-quick` / systemd-networkd files): overlapping or over-broad `AllowedIPs` between peers (silent traffic hijack), duplicate/reused keys, peers without recent handshake, missing `PersistentKeepalive` behind NAT, world-readable private keys, and whether the listen port is actually allowed by the firewall (reuses nftlint's exposure engine). | M |
| `zonelint` | Go | P2 | Offline lint of RFC 1035 zone files before they are deployed (CI-friendly, complements the live checks of `dnsdoctor`): CNAME at apex or next to other data, out-of-zone and missing glue, dangling CNAME/MX/SRV targets inside the zone, A/AAAA vs PTR consistency across forward and reverse zones, SOA timer sanity (RFC 1912), TTL outliers, serial not incremented compared with the previous git revision. | M |
| `bond-check` | Bash | P3 | Health check for Linux bonding/LACP and teaming without dependencies: parses `/proc/net/bonding/*` and `ip -d link` to detect inactive or flapping slaves, LACP partner MAC/key/aggregator mismatches (one switch port in a different LAG), speed/duplex mismatches between members, `miimon` disabled; Nagios output and exit codes. | S |

## Done

| # | Tool | Language | Version | Date |
|---|------|----------|---------|------|
| 1 | [`dnsdoctor`](tools/dnsdoctor/) | Go | 0.1.0 | 2026-10-09 |
| 2 | [`tlsaudit`](tools/tlsaudit/) | Go | 0.1.0 | 2026-10-14 |
| 3 | [`nftlint`](tools/nftlint/) | Python | 0.1.0 | 2026-10-16 |

`dnsdoctor` — end-to-end DNS diagnostics: iterative resolution from the root,
lame delegations, parent/child NS consistency, SOA serial drift between
secondaries, DNSSEC chain validation.

`tlsaudit` — TLS fleet audit: expiry, incomplete/untrusted chains, SAN
mismatch, protocol versions (SSLv3–TLS 1.3), raw-ClientHello cipher suite
enumeration, DHE group size, secure renegotiation, TLS_FALLBACK_SCSV, OCSP
stapling with signature verification, STARTTLS; JSON and Prometheus output.

`nftlint` — nftables (`nft -j`) and iptables-save static analysis with an
exact interval-set model: shadowed/redundant/unreachable rules, unreachable
and undefined chains, any-any accepts, permissive policies across all base
chains of a hook, sensitive ports open to the world, missing IPv6 filtering;
symbolic evaluation of the input path against `ss -tulnp` to report which
sockets are open, restricted (exact source prefixes) or conditional.

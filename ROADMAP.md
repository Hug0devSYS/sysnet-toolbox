# Roadmap

Ideas are built in priority order. The initial backlog (items 1–13) was
validated by the repository owner and is worked through in order before newer
ideas, unless a new idea is clearly more valuable.

Effort scale: **S** (< 1 day), **M** (1–3 days), **L** (> 3 days).

## Backlog

### P1

All P1 items of the initial backlog are done.

### P2

| # | Tool | Language | Problem solved | Effort |
|---|------|----------|----------------|--------|
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
| `netcfg-audit` | Python | P2 | Policy-as-code compliance of network configurations, reusing `netcfg-diff`'s parsers (IOS/NX-OS/IOS-XR/EOS, Junos, FortiOS): YAML rules such as "every access port has BPDU guard", "no `ip http server`", "SSH v2 only, telnet disabled on every VTY", "NTP/AAA/syslog servers equal the golden list", "every Junos filter ends with an explicit discard term", "no FortiOS policy with `srcaddr all` + `service ALL` + accept"; per-device and per-rule report, JSON and JUnit output for CI. | M |
| `dns-cutover-check` | Go | P2 | Pre-flight check before moving a zone to a new DNS provider or primary: queries every name and type from a zone file or AXFR against the old and the new authoritative servers and compares RRsets, TTLs, SOA/NS, wildcard and CNAME behaviour, DNSSEC state (DS at the parent vs keys served by the new provider); reports what would break when the delegation is switched. Reuses dnsdoctor's wire format and transport. | M |
| `pki-health` | Go | P3 | Health of an internal PKI's revocation infrastructure: fetch every CRL Distribution Point and AIA URL (HTTP and LDAP) found in a CA chain or a set of certificates, check reachability, CRL signature, `nextUpdate` margin, delta CRLs, OCSP responder signature and freshness; Nagios/Prometheus output. Complements `tlsaudit` (endpoints) and `cert-inventory` (stores). | M |
| `bond-check` | Bash | P3 | Health check for Linux bonding/LACP and teaming without dependencies: parses `/proc/net/bonding/*` and `ip -d link` to detect inactive or flapping slaves, LACP partner MAC/key/aggregator mismatches (one switch port in a different LAG), speed/duplex mismatches between members, `miimon` disabled; Nagios output and exit codes. | S |
| `flowtrace` | Go | P2 | ECMP-aware path tracing without privileges (Paris/Dublin-traceroute style, IP_RECVERR like `tracepath`): varies the 5-tuple to enumerate the parallel paths of a load-balanced network, reports per-path hops, loss and RTT, and locates which ECMP member or hop silently drops oversized packets (reuses `pmtud-probe`'s probe engine, whose black-hole verdict cannot tell which hop is at fault). | M |
| `ipam-drift` | Python | P2 | Reconcile IPAM with reality: NetBox (API or CSV export) against live ARP/ND tables (SNMP `ipNetToPhysicalTable` or `ip neigh` dumps) and DNS PTR records; reports undocumented addresses in use, stale reservations never seen, MAC changes on documented hosts, PTR records that disagree with NetBox `dns_name`, and duplicate addresses across VRFs. Read-only towards NetBox and the network. | M |
| `fhrp-watch` | Python | P3 | Passive VRRP v2/v3, HSRP v1/v2 and CARP advertisement monitoring on a segment: several masters for one group (split brain), unexpected master changes, priority/preempt/timer mismatches between peers, VRID/group collisions, plaintext or missing authentication; JSON/syslog alerts and Nagios exit codes. Needs CAP_NET_RAW (documented), listens only. | S |
| `stp-audit` | Python | P2 | Spanning-tree health over SNMP (BRIDGE-MIB, RSTP-MIB, IEEE8021-MSTP-MIB, Cisco PVST via `community@vlan` contexts): every switch agrees on the same root bridge and it is the intended one (priority plan), unexpected root or secondary root, topology-change counters and recent TCs (flapping edge ports), blocked/alternate ports drawn on the `lldp-mapper` graph, edge ports without BPDU guard where the MIB exposes it, mismatched STP modes between neighbours. Reuses lldp-mapper's SNMP client and topology. | M |
| `ipsec-audit` | Python | P2 | Audit strongSwan / libreswan site-to-site VPNs from `swanctl --list-sas --list-conns` (or `ipsec status` / `ipsec trafficstatus`) and their config files: configured tunnels that are not up, CHILD_SAs missing for configured traffic selectors, weak proposals (3DES, SHA-1, MD5, MODP-1024/1536, IKEv1 aggressive mode), PFS disabled, lifetime/rekey mismatches, PSKs shorter than 20 characters or shared between peers, certificates close to expiry; read-only, JSON and Nagios output. Complements `wg-audit` for IPsec. | M |
| `dhcp-pool-watch` | Python | P3 | DHCP pool utilisation and exhaustion forecast for ISC Kea (control-agent `stat-lease4-get`/`statistic-get-all`), ISC dhcpd `dhcpd.leases` and dnsmasq lease files: per-subnet usage, regression-based days-to-exhaustion, static reservations inside dynamic ranges, duplicate MAC/hostname reservations, abandoned/declined leases (address conflicts); Prometheus textfile and Nagios output. | S |
| `route-diff` | Python | P2 | Before/after comparison of routing tables around a change window: parses `show ip route` / `show ipv6 route` (IOS/IOS-XE/NX-OS/EOS), `show route` (Junos, text or `display json`), `ip -j route`/`ip -6 route` and `vtysh show ip route json`; reports lost and new prefixes per VRF, next-hop and outgoing-interface changes, ECMP width changes, protocol/AD/metric changes and default-route moves, with a summary per protocol. Offline, read-only; Nagios and JSON output for automated post-change checks. | M |
| `ad-dns-audit` | PowerShell | P2 | Health of Active Directory-integrated DNS through the DnsServer module (read-only): aging/scavenging settings per zone and server (scavenging enabled nowhere, or on several servers), stale dynamic records past the refresh window, A records without matching PTR and PTRs pointing to missing names, duplicate addresses held by several hostnames, missing `_msdcs`/SRV records per domain controller, forwarders and conditional forwarders that do not answer, zone replication scope consistency; CSV/JSON report. | M |
| `resolv-audit` | Bash | P3 | Linux client resolver sanity check without dependencies: `/etc/resolv.conf` provenance (systemd-resolved stub, NetworkManager, static, broken symlink), effective per-link DNS servers and routing domains (`resolvectl`), search list and `ndots` pitfalls (container/Kubernetes `ndots:5`), unreachable or non-recursive nameservers, `nsswitch.conf` order, DNSSEC/DoT settings and stale `/etc/hosts` overrides of names that also exist in DNS; Nagios output. | S |

## Done

| # | Tool | Language | Version | Date |
|---|------|----------|---------|------|
| 1 | [`dnsdoctor`](tools/dnsdoctor/) | Go | 0.1.0 | 2026-10-09 |
| 2 | [`tlsaudit`](tools/tlsaudit/) | Go | 0.1.0 | 2026-10-14 |
| 3 | [`nftlint`](tools/nftlint/) | Python | 0.1.0 | 2026-10-16 |
| 4 | [`netcfg-diff`](tools/netcfg-diff/) | Python | 0.1.0 | 2026-10-21 |
| – | [`sysnet-presence`](tools/discord-presence/) | Python | 0.1.0 | 2026-10-21 |
| 5 | [`pmtud-probe`](tools/pmtud-probe/) | Go | 0.1.0 | 2026-10-23 |
| 6 | [`lldp-mapper`](tools/lldp-mapper/) | Python | 0.1.0 | 2026-10-28 |
| 7 | [`subnet-planner`](tools/subnet-planner/) | Go | 0.1.0 | 2026-10-30 |

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

`netcfg-diff` — semantic diff of network configurations (IOS/IOS-XE, NX-OS,
IOS-XR, EOS, Junos brace and set formats, FortiOS): hierarchical comparison,
order ignored where the device ignores it and moves reported where it
matters (ACLs, Junos terms and policy chains, FortiOS policy tables),
single-valued commands as modifications, VLAN and list attributes as sets,
secrets masked at parse time; text, JSON, summary and Junos
set/delete/insert output; directory mode for backup trees.

`pmtud-probe` — path MTU discovery for IPv4/IPv6 without privileges
(UDP or ICMP ping sockets, `IP_PMTUDISC_PROBE` + `IP_RECVERR`): working
PMTUD vs black hole vs rejected oversize packets, broken ICMP contents,
IPv6 below 1280, TCP MSS clamping check from the target's SYN-ACK.

`lldp-mapper` — layer-2 topology discovery over SNMP (LLDP-MIB with the
802.1/802.3 extensions, CISCO-CDP-MIB, IF-MIB, EtherLike-MIB, Q-BRIDGE and
Cisco VLAN MIBs): neighbour identity by chassis ID, LLDP and CDP sightings
merged per cable, duplex/speed/auto-negotiation/native VLAN mismatches with
the source of every fact, one-way adjacencies, miscabling; scoped crawl;
text, JSON, Mermaid and DOT output; built-in SNMPv1/v2c client, SNMPv3 via
net-snmp; offline mode on saved walks.

`subnet-planner` — IPv4/IPv6 address planning and IPAM hygiene: VLSM
allocation (largest first, best fit) around the space already used in a
NetBox/CSV/JSON export, NetBox-importable output; duplicate and nested
prefixes, duplicate/orphan addresses, mask mismatches and reserved
addresses per VRF; exact and bounded-lossy route aggregation with Cisco and
Junos prefix-list output; free-space listing; subnet calculator with
special-purpose registry and reverse DNS zones.

`sysnet-presence` — out-of-backlog addition requested by the owner: Discord
Rich Presence wrapper showing the running toolbox tool with the logo.

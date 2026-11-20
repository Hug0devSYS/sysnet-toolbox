# Changelog

All notable changes to this repository are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and each tool is versioned independently following
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 2026-11-20

### Added

- **ntp-skew 0.1.0** (Go, standard library only): NTP source comparison and
  falseticker detection.
  - NTPv4 client-mode requests carrying only a random 64-bit transmit
    cookie (RFC 9109 data minimisation) on a connected socket; answers must
    echo it, spoofed/replayed/late datagrams are ignored and counted; round
    trip measured on the monotonic clock; NTP era handling (2036 rollover).
  - Several exchanges per server, lowest-delay sample kept (clock filter),
    jitter, dispersion and root distance as in RFC 5905.
  - Intersection algorithm as implemented by ntpd 4.2.8 (the RFC 5905
    pseudo-code's midpoint test wrongly rejects correct servers with narrow
    intervals), weighted consensus, local clock offset with `--warn` /
    `--crit`, optional `--max-skew` per truechimer.
  - Kiss-o'-death handling (stop at the first one; RATE vs DENY/RSTR),
    stratum 0 without kiss code / INIT / STEP and leap indicator 3 reported
    as unsynchronised, root distance above 1.5 s, stale reference
    timestamps, undisciplined local clocks (refid 127.127.1.1), processing
    time longer than the round trip, servers synchronised to each other or
    to this host (IPv4 and MD5-based IPv6 refids), every source behind one
    upstream, leap indicator disagreement, partial answers (rate limiting
    or loss).
  - Servers from arguments, lists, `--config` (chrony, ntpd, ntpsec,
    systemd-timesyncd, `w32tm /query /peers`, `NtpServer` registry value)
    or `--system`; pools expand to every address, other names to one.
  - Text (escaped server strings), JSON, Prometheus textfile (atomic, left
    untouched on interruption); Nagios exit codes.
  - `lab/chrony-lab.sh`: interoperability run against real chronyd
    instances (one shifted with libfaketime, one rate-limiting, one
    unsynchronised), never touching the system clock.

### Fixed

- **tlsaudit 0.1.2**: the lifetime check for publicly trusted certificates
  used a fixed 398-day limit; it now applies the CA/Browser Forum ballot
  SC-081 schedule by issuance date (200 days from 2026-03-15, 100 from
  2027-03-15, 47 from 2029-03-15).
- **tlsaudit 0.1.2**: certificates expiring or expired within a day were
  reported as "0 day(s)"; the remaining hours and the UTC time are shown.
- **tlsaudit 0.1.2**: an unwritable `--prom-file` directory was only
  detected after the whole audit; it is checked before any connection.

### Changed

- **tlsaudit 0.1.2**: `sni=` rejects wildcard names.
- **sysnet-presence 0.1.3**: description for `ntp-skew`.

## 2026-11-18

### Added

- **cert-inventory 0.1.0** (PowerShell, no module dependencies): inventory
  and audit of Windows machine certificate stores.
  - Collector sent with `Invoke-Command -FilePath` (Windows PowerShell 5.1
    compatible, read-only): LocalMachine stores opened `ReadOnly |
    OpenExistingOnly`, built-in DER parser for SubjectAltName (DNS, IP, UPN),
    ADCS v1/v2 template extensions, ECC curves and DSA sizes; private key
    export policy read from CNG `ExportPolicy` or CAPI `CspKeyContainerInfo`
    with TPM, smart card and third-party KSP storage recognised;
    `-SkipKeyInspection` to never open keys.
  - Bindings from HTTP.sys IP and SNI registry keys, the RDP listener (CIM)
    and WinRM HTTPS listeners, so expiry is judged on use: renewed but not
    rebound, expired but still bound, superseded, missing or keyless bound
    certificates.
  - Weak keys (RSA, DSA, small curves), MD5/SHA-1 signatures, server
    certificates without SAN, exportable keys (`-AllowExportable` patterns),
    self-signed certificates on HTTP.sys/WinRM, expired trust anchors
    summarised per store, the same certificate and key on several hosts,
    per-template counts.
  - WinRM fan-out with throttling, timeouts, HTTPS, explicit credentials and
    per-host error attribution; host lists as text or AD CSV exports;
    `-CollectOnly` / `-InputPath` for offline analysis on any OS with
    PowerShell 7, with stale-collection detection.
  - Text (control characters escaped), JSON (ISO 8601 dates on 5.1 and 7)
    and CSV (formula-injection safe) output; Nagios exit codes.

### Fixed

- **dnsdoctor 0.1.2**: SIGINT/SIGTERM killed the process without output; the
  current zone is now reported as incomplete, remaining zones are listed on
  stderr, `--json` still emits a valid document and the exit code is 3.
- **dnsdoctor 0.1.2**: `--sig-warn` accepted `NaNd`, `Infd` and values that
  overflowed the duration type.
- **dnsdoctor 0.1.2**: an invalid `--color` value was silently treated as
  `never`; it is now a usage error.
- **dnsdoctor 0.1.2**: `--json` printed `null` instead of `[]` when no zone
  was checked.

### Changed

- **dnsdoctor 0.1.2**: a zone given several times (any case, with or without
  the trailing dot) is checked once.
- **sysnet-presence 0.1.2**: description for `cert-inventory`, and the tool
  name is recognised through `pwsh`/`powershell` (`pwsh -File
  ./cert-inventory.ps1`) without revealing other script names.

## 2026-11-13

### Added

- **syslog-triage 0.1.0** (Go, standard library only): syslog/journald
  pattern mining and spike detection.
  - Per-line format detection: RFC 3164 with or without `<PRI>` (year
    inferred from the file time with New Year roll-over, `--year`, `--tz`),
    RFC 3339 high-precision lines (rsyslog, syslog-ng, `journalctl -o
    short-iso`), RFC 5424 with structured data, Cisco IOS/NX-OS/ASA
    `%FAC-SEV-MNEMONIC` messages with or without a relay header, and
    `journalctl -o json` (binary `MESSAGE` arrays included); gzip detected by
    magic bytes; `--journal` runs `journalctl` with a timeout; `--raw` for
    application logs.
  - Drain template mining (fixed-depth prefix tree, similarity threshold,
    bounded fan-out, one partition per program) after typed masking of IPv4/
    IPv6 addresses and ports, prefixes, MAC addresses (three notations),
    UUIDs, hex identifiers and numbers with units; interface names and paths
    kept intact.
  - Spike detection per pattern and on the overall volume: robust trailing
    baseline (median + K x scaled MAD with a Poisson floor), minimum count
    and ratio, burst buckets excluded from the baseline, bursts lasting a
    whole window reported as sustained level shifts.
  - New patterns against a persistent model (`--model`, written only with
    `--update-model`, atomic, mode 0600, `--model-max-age`), or first seen
    within `--recent` of a longer input.
  - Filters (`--since`/`--until` absolute or relative, `--min-severity`,
    program and host regular expressions); text output with control
    characters neutralised, `--json`; Nagios exit codes with
    `--alert-severity` and `--crit-severity`.

### Fixed

- **sysnet-presence 0.1.1**: `--hold --duration` could crash with
  `ValueError` when the deadline passed between the loop test and the sleep
  (negative sleep).
- **sysnet-presence 0.1.1**: `--duration` and `--timeout` accepted `inf` and
  `nan` (hold forever, or exit immediately).
- **sysnet-presence 0.1.1**: SIGTERM/SIGHUP/SIGQUIT sent to the wrapper left
  the wrapped command running; they are now forwarded to it and the wrapper
  waits for it. Ctrl-C during the Discord handshake no longer abandons the
  child.

### Changed

- **sysnet-presence 0.1.1**: descriptions for every toolbox tool
  (`pmtud-probe`, `lldp-mapper`, `subnet-planner`, `syslog-triage` were
  shown without one), checked by a test against the `tools/` directory.
- **sysnet-presence 0.1.1**: the tool name is found through launchers
  (`sudo`, `doas`, `env`, `nice`, `ionice`, `timeout`, `time`, `nohup`,
  `stdbuf`) and, for interpreters (`python3 -m`, `uv run`, `pipx run`,
  `go run`), only a known toolbox tool is named, so script names and `-c`
  code stay private; unusual executable names are shown as "command".

## 2026-10-30

### Added

- **subnet-planner 0.1.0** (Go, standard library only): IPv4/IPv6 address
  planning, IPAM conflict checks and route aggregation.
  - `plan`: VLSM allocation inside a parent prefix from host counts or
    prefix lengths, largest first and best fit, avoiding prefixes and
    addresses already in use (`--used` inventories, `--exclude`); rows equal
    to or containing the parent are recognised as its own record; growth
    percentage, per-subnet reserve, `/31` (RFC 3021), `/64` minimum for
    IPv6 host counts with a warning on non-/64 LANs; exact minimum parent
    size when requests do not fit; text, JSON, CSV and NetBox import CSV.
  - `check`: per-VRF duplicate prefixes, nesting under non-container
    prefixes (or any nesting for lists without status), host bits set,
    duplicate addresses (shared roles such as anycast/VRRP exempted),
    orphan addresses, address/subnet mask mismatches, network/broadcast and
    IPv6 subnet-router anycast addresses assigned to hosts, optional
    cross-VRF overlaps; file:line references; Nagios exit codes.
  - `aggregate`: exact minimal prefix list, or at most N prefixes per
    family with the fewest extra addresses (`--max`, extra space reported);
    plain, Cisco and Junos prefix-list or JSON output.
  - `free` (unallocated space, optional split into fixed-size subnets) and
    `info` (subnet calculator with IANA special-purpose registry
    classification and reverse DNS zones, RFC 2317 and nibble notes).
  - Inputs auto-detected: NetBox CSV exports (`,` `;` tab, BOM), NetBox
    API JSON, plan JSON, plain lists; exact 128-bit arithmetic for IPv6.
  - Tests include property checks against a bitmap model (aggregation),
    exhaustive-packing checks (allocation) and lossy-aggregation invariants.

### Fixed

- **netcfg-diff 0.1.1**: a corrupt `.gz` input crashed with a `zlib.error`
  traceback instead of a clean error (exit code 2).
- **netcfg-diff 0.1.1**: files that are not valid UTF-8 (legacy
  Windows-1252/Latin-1 backups with accented descriptions or banners) were
  decoded with replacement characters, so they never compared equal to a
  UTF-8 export of the same configuration; they are now decoded as
  Windows-1252 (Latin-1 for undefined bytes), and a UTF-8 BOM is skipped.

### Changed

- **netcfg-diff 0.1.1**: `netcfg-diff FILE DIR` (or `DIR FILE`) compares
  FILE with `DIR/basename(FILE)`, like diff(1), instead of failing.

## 2026-10-28

### Added

- **lldp-mapper 0.1.0** (Python, standard library only): layer-2 topology
  discovery over SNMP with link consistency checks.
  - Built-in read-only SNMPv1/v2c client (BER codec, GetBulk/GetNext walks,
    retries, automatic `tooBig` back-off, per-device time budget,
    non-increasing OID detection), cross-validated against net-snmp;
    SNMPv3 (USM auth/priv) through `snmpbulkwalk`, credentials passed in a
    private temporary `snmp.conf`, never on the command line.
  - Reads LLDP-MIB (local, remote, management addresses), LLDP-EXT-DOT1
    (PVID), LLDP-EXT-DOT3 (auto-negotiation, MAU type), CISCO-CDP-MIB,
    IF-MIB, EtherLike-MIB duplex, Q-BRIDGE `dot1qPvid`, CISCO-VTP-MIB trunk
    native VLAN and CISCO-VLAN-MEMBERSHIP-MIB access VLAN.
  - LLDP local port numbers mapped to ifIndex (port ID, description, Junos
    convention, then assumed equality); neighbours matched by chassis ID,
    name (NX-OS serial suffix, domain) or management address, never merging
    different chassis IDs; LLDP and CDP sightings of one cable merged.
  - Findings: `duplex-mismatch` (critical), `speed-mismatch`,
    `autoneg-mismatch`, `native-vlan-mismatch`, `one-way-adjacency`,
    `neighbor-mismatch`, `shared-port`, `poll-failed`, `partial-data`,
    `no-discovery-data`, `duplicate-device`; every link fact carries its
    source (own MIB vs neighbour advertisement).
  - Scoped crawl through advertised management addresses (`--crawl` requires
    `--scope`, depth/device/capability limits), parallel polls.
  - Text, JSON, Mermaid and Graphviz DOT output (`--graph` files), Nagios
    exit codes, `--save-walks` / `--from-walks` offline mode accepting
    `snmpbulkwalk -On` output.
  - 108 tests: fake UDP agent, typed net-snmp walk fixture, reference lab.

### Fixed

- **nftlint 0.1.1**: sockets printed by `ss` as `[fe80::1]%eth0:546`
  (DHCPv6 clients and other scoped IPv6 sockets) were silently dropped from
  the exposure analysis.
- **nftlint 0.1.1**: `ss` output produced without `-n` (service or host
  names) was silently skipped, so the exposure table looked clean; it is now
  rejected with a hint.
- **nftlint 0.1.1**: NFT007/NFT008 reported TCP-only services (mssql,
  oracle, mysql, ...) for accepted UDP ports; the built-in sensitive port
  list is now protocol-aware (custom `--sensitive-ports` lists still apply
  to every protocol).

## 2026-10-23

### Added

- **pmtud-probe 0.1.0** (Go, standard library only): path MTU discovery and
  PMTUD black-hole detection for IPv4 and IPv6, no privileges required.
  - Probes on fresh connected sockets with `IP_PMTUDISC_PROBE` (DF set,
    cached PMTU ignored) / `IPV6_DONTFRAG`; ICMP errors and the offending
    router read from the `IP_RECVERR` / `IPV6_RECVERR` error queue. UDP
    probes to a closed port or unprivileged ICMP ping sockets, `auto`
    choosing ICMP when allowed and answered and falling back to UDP.
  - Bisection between a control probe and the interface MTU that jumps to
    an advertised MTU and confirms it (4 probes when PMTUD works); silent
    drops only accepted after retries, a successful control probe and a
    final attempt, so loss and ICMP rate limiting do not fake a black hole.
  - Verdicts: `not-needed`, `working`, `black-hole`, `filtered`, `local`;
    findings for ICMP without next-hop MTU, inconsistent or bogus MTU
    values, IPv6 path MTU below 1280, cached/route PMTU, `--expect-mtu`.
  - `--tcp PORT` MSS check run before the probes: the target's MSS as
    received here (after any clamping), exact or lower bound, against the
    discovered path; CRITICAL when unclamped on a black-holed path.
  - Text and `--json` output, one report per target and family (dual-stack
    by default), `-f` target lists, Nagios exit codes.
  - Unit tests (error-queue and `tcp_info` decoding, loopback sockets,
    simulated paths with loss/rate limiting/400 random topologies, CLI) and
    `lab/netns-lab.sh`, a 14-scenario end-to-end lab on three network
    namespaces with nftables (black hole, MSS clamping, rejections).

### Fixed

- **tlsaudit 0.1.1**: targets audited with `connect=` (several nodes behind
  one name) produced duplicate Prometheus series, which makes
  node_exporter's textfile collector reject the whole file; a `connect`
  label is now added for those targets (other series are unchanged).
- **tlsaudit 0.1.1**: an interrupted run (SIGINT/SIGTERM) reported every
  unreached target as a CRITICAL connection error and overwrote the
  `--prom-file`; it now exits UNKNOWN and leaves the metrics file untouched.
- **tlsaudit 0.1.1**: repeated targets are audited once (note on stderr).
- **tlsaudit 0.1.1**: the text report highlighted certificate expiry with a
  hard-coded 30-day threshold; it now follows `--warn-days`/`--crit-days`
  (new `expiry_status` field on the leaf certificate in JSON).

## 2026-10-21

### Added

- **netcfg-diff 0.1.0** (Python, standard library only): semantic diff of
  network device configurations.
  - Parsers for indentation-based configurations (Cisco IOS / IOS-XE,
    NX-OS, IOS-XR, Arista EOS; banners, `exit-*`/`end-*` terminators,
    duplicate contexts merged), Junos (curly-brace and `display set`
    formats parsed to the same token tree, `inactive:`/`deactivate`,
    `[ ]` lists, comments) and FortiOS (`config`/`edit`/`set`/`unset`/
    `append`/`unselect`, VDOMs, multi-line quoted values); vendor
    auto-detection.
  - Order-aware comparison: order ignored where the device ignores it;
    checked for ACL entries (named, numbered, ASA-style), prefix/as-path/
    community lists, policy-maps, route-policies, banners, Junos filter and
    policy-statement terms, security policies, NAT rules, import/export
    chains, `apply-groups`, `name-server`, FortiOS policy tables and router
    list rules. Minimal moves computed with a longest increasing
    subsequence; ACL/prefix-list sequence numbers are not significant.
  - Single-valued commands, `no X` vs `X`, FortiOS attributes and Junos
    leaves reported as modifications; `switchport trunk allowed vlan`
    (`add`/`remove`/`except`/`all`/`none`) and FortiOS list attributes
    compared as sets with added/removed members.
  - Secrets (hashes, type-7, SNMP communities and v3 keys, TACACS/RADIUS,
    IKE PSK, routing-protocol keys, Junos `$9$`, FortiOS `ENC`, private
    keys) masked at parse time with per-run HMAC fingerprints;
    `--secrets presence|show`.
  - Text (annotated, coloured), `--json`, per-section `summary` and Junos
    `set` (set/delete/insert/activate/deactivate commands) output;
    `--section`, `--ignore`, `--ignore-file`, `--ignore-order`, `--brief`,
    built-in volatile-line filter; directory mode for backup trees; stdin
    and `.gz` inputs; `diff(1)` exit codes.
- **sysnet-presence 0.1.0** (Python, standard library only, requested by the
  owner): Discord Rich Presence wrapper. `sysnet-presence -- <command>`
  shows "Running <tool>" with the toolbox logo, elapsed time and a GitHub
  button while the command runs, through the local Discord IPC socket
  (Linux/macOS incl. Flatpak/Snap, Windows named pipes); `--hold`,
  `--check`; arguments are never published; the command's exit code is
  preserved and a missing Discord client never affects the command.
- Repository logo (`assets/logo.svg`, 512 and 1024 px PNG), shown in the
  README and used as the Discord art asset.
- Roadmap: new ideas `netcfg-audit`, `dns-cutover-check` and `pki-health`.

### Fixed

- **dnsdoctor 0.1.1**: a lame server answering NOERROR without authority
  and without a usable referral (e.g. an upward referral) no longer aborts
  the iterative walk; the zone's other servers are tried. The DNSSEC walk
  rejects such empty non-authoritative replies instead of reporting a false
  insecure (no DS) or bogus (no DNSKEY) chain. A failed TCP fallback after a
  truncated UDP response is now reported explicitly.

## 2026-10-16

### Added

- **nftlint 0.1.0** (Python, standard library only): static analysis of
  nftables (`nft -j list ruleset`) and `iptables-save` / `ip6tables-save`
  rulesets.
  - Common rule model with exact interval sets for nfproto, L4 protocol,
    ports, IPv4/IPv6 addresses and conntrack state (negations, ranges,
    prefixes, anonymous and named sets), interface patterns, verdict maps,
    jump/goto/return; unmodelled expressions kept as opaque conditions so the
    analysis stays conservative.
  - Checks: shadowed rules with conflicting verdicts, redundant rules,
    rules after catch-all rules, unreachable and undefined chains, any-any
    accepts, permissive default policies (evaluated across every base chain
    of the hook, including catch-all rules reached via jumps), sensitive
    management/database ports open to any source, IPv4-only filtering.
  - Socket exposure: `ss -tulnp` parsing (dual-stack, scoped and IPv4-mapped
    addresses) and symbolic evaluation of a first packet through all input
    base chains in priority order with a symbolic source address, reporting
    open / restricted (exact allowed prefixes) / conditional / filtered /
    unfiltered sockets, services exposed only by a default-accept policy,
    stale openings and families without an analysed ruleset.
  - Text and `--json` output, Nagios-compatible exit codes, `--min-severity`,
    `--ignore`, `--sensitive-ports`, read-only `--live` mode (`nft`, with
    `iptables-save`/`ip6tables-save` fallback, and `ss`, with timeouts).
- Roadmap: new ideas `wg-audit`, `zonelint` and `bond-check`.

## 2026-10-14

### Added

- **tlsaudit 0.1.0** (Go): TLS endpoint fleet audit, zero third-party
  dependencies.
  - Certificate checks: expiry thresholds (`--warn-days`, `--crit-days`) for
    leaf and chain, key size, SHA-1/MD5 signatures, missing SAN, lifetime
    above 398 days, SAN/hostname match (SNI, wildcards, IP SANs).
  - Independent chain validation (system roots or `--ca-file`/`--ca-only`):
    trusted / incomplete / untrusted / expired / invalid, optional AIA
    download (`--fetch-aia`) to confirm missing intermediates, out-of-order,
    superfluous and root certificates in the served chain.
  - Raw ClientHello engine: SSLv3, TLS 1.0, 1.1 and 1.2 detection and full
    cipher suite enumeration over ~140 IANA suites (including export, NULL,
    anonymous, RC4, DES, 3DES and DHE), graded insecure/weak/legacy/good;
    DHE group size (Logjam); ECDHE curve; RFC 5746 secure renegotiation;
    RFC 7507 TLS_FALLBACK_SCSV; RFC 7685 padding. TLS 1.3 via crypto/tls.
  - Stapled OCSP parsing and signature verification (issuer or delegated
    responder): Must-Staple, revoked, unknown, stale staples.
  - STARTTLS for SMTP, IMAP, POP3, FTP, LDAP and PostgreSQL; URL-style
    targets (`smtp://`, `ldaps://`, ...) and per-target `sni=`, `connect=`,
    `starttls=` options; target files (`-f`, stdin).
  - Text, `--json` and `--summary` output, Nagios-compatible exit codes,
    Prometheus textfile metrics written atomically (`--prom-file`), parallel
    audits (`--concurrency`), per-connection and per-target time budgets.
- Roadmap: new ideas `ct-watch`, `cfg-vault` and `l2-guard`.

## 2026-10-09

### Added

- Repository scaffolding: README with tool index, MIT license, contributing
  guide, roadmap with the initial backlog, maintenance state file and a
  language-aware CI workflow (Go, Python, Bash, PowerShell).
- **dnsdoctor 0.1.0** (Go): end-to-end DNS zone diagnostics.
  - Iterative delegation walk from the root servers (RD=0), with glueless
    name server resolution and out-of-bailiwick glue filtering.
  - Parent vs child NS RRset comparison and per-server NS consistency.
  - Missing/stale glue detection for in-bailiwick name servers.
  - Lame delegation detection (timeouts, REFUSED/SERVFAIL, missing AA bit,
    missing SOA) on every IPv4/IPv6 address of every name server.
  - SOA serial drift between all server addresses (RFC 1982 arithmetic).
  - Network diversity check (single /24 or /48).
  - DNSSEC chain-of-trust validation from the IANA root anchors (KSK-2017
    and KSK-2024): DS/DNSKEY matching, RRSIG verification (RSA/SHA-1/256/512,
    ECDSA P-256/P-384, Ed25519), signature expiry warnings, island-of-security
    and stale-DS detection, deprecated algorithm/digest warnings.
  - Text and JSON output, Nagios-compatible exit codes, zero third-party
    dependencies.

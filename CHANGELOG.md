# Changelog

All notable changes to this repository are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and each tool is versioned independently following
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

# Changelog

All notable changes to this repository are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and each tool is versioned independently following
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

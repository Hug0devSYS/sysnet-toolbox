# sysnet-toolbox

A collection of focused, production-grade command-line tools for systems and
network engineers: DNS/TLS/MTU diagnostics, firewall and network-config
auditing, inventory and lightweight monitoring.

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
| [dnsdoctor](tools/dnsdoctor/) | Go | End-to-end DNS zone diagnostics: iterative walk from the root, parent/child NS consistency, glue, lame delegations, SOA serial drift, DNSSEC chain of trust. | Beta (v0.1.0) |
| [tlsaudit](tools/tlsaudit/) | Go | TLS fleet audit: expiry, incomplete/untrusted chains, SAN mismatch, SSLv3–TLS 1.3, full cipher suite enumeration, DHE strength, OCSP stapling, STARTTLS; text/JSON/summary output and Prometheus textfile metrics. | Beta (v0.1.0) |
| [nftlint](tools/nftlint/) | Python | nftables / iptables-save static analysis: shadowed, redundant and unreachable rules, any-any accepts, permissive policies, missing IPv6 filtering; correlates `ss` listening sockets with the input path to show what is really reachable and from which sources. | Beta (v0.1.0) |

Planned tools and their priority are tracked in [ROADMAP.md](ROADMAP.md).

## Layout

```
tools/<tool-name>/   code, tests, README and dependency file for one tool
.github/workflows/   CI (only runs jobs for languages that are present)
.toolbox/state.json  maintenance metadata (versions, run history)
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

# Python tools
pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/nftlint"
sudo nft -j list ruleset > rules.json && ss -tulnp > ss.txt
nftlint rules.json --ss ss.txt
```

See each tool's README for installation, usage, sample output, limitations
and security notes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are tracked in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © Hug0devSYS

# pmtud-probe

Path MTU discovery and **PMTUD black-hole detection** for IPv4 and IPv6,
with a TCP **MSS clamping** check. One static binary, no privileges, no
dependencies outside the Go standard library.

PMTUD black holes are the classic "ping works, SSH logs in, then the
session freezes" problem: something on the path (a tunnel, a PPPoE link,
an IPsec or GRE/VXLAN overlay) has a smaller MTU, and a firewall filters
the ICMP "fragmentation needed" / ICMPv6 "packet too big" messages that
would tell the sender. `pmtud-probe` tells you, per target:

- the **path MTU** (largest packet that reaches the target unfragmented),
  plus the matching UDP payload and TCP MSS;
- whether the constriction is **signalled** (PMTUD works, with the router
  that answered and the MTU it advertised), **silent** (black hole),
  **rejected** with another ICMP error, or **local** (interface/route);
- broken ICMP: messages without the next-hop MTU (pre-RFC 1191), MTU values
  that do not match what the path carries, values not smaller than the
  packet, IPv6 paths below the 1280-byte minimum;
- with `--tcp PORT`: the MSS the target's SYN-ACK carries **as received
  here** (after any clamping on the way), and whether full-size segments
  fit the path. An unclamped MSS on a black-holed path is CRITICAL: TCP
  transfers will stall.

## Installation

```sh
go install github.com/Hug0devSYS/sysnet-toolbox/tools/pmtud-probe@latest
# or, from a checkout
cd tools/pmtud-probe && go build -trimpath -ldflags "-s -w" -o pmtud-probe .
```

Linux only (it relies on `IP_RECVERR` socket error queues). It builds on
other platforms but exits with UNKNOWN.

## Usage

```
pmtud-probe [flags] <host|address> [<host|address>...]
pmtud-probe [flags] -f targets.txt
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-4`, `-6` | both | Address family. Without them, one IPv4 and one IPv6 address of each name are probed; a family without a local route is skipped (noted on stderr). |
| `--method` | `auto` | `icmp` (echo requests), `udp` (datagrams to a closed port, the target answers ICMP port unreachable) or `auto` (ICMP when allowed and answered, otherwise UDP). |
| `--port` | `33434` | Destination port of UDP probes. |
| `--tcp PORT` | off | MSS check against this TCP port (handshake only, no data sent). |
| `--max` | interface MTU | Largest packet to try (e.g. `9000` to test jumbo frames end to end). |
| `--expect-mtu N` | off | WARNING when the path MTU is not `N` (monitoring of a known tunnel MTU). |
| `--timeout` | `1s` | Wait time for each probe's answer. |
| `--retries` | `1` | Extra attempts before a size counts as unanswered. |
| `--max-time` | `2m` | Time budget per target and family. |
| `--concurrency` | `4` | Targets probed in parallel. |
| `--json` | | JSON array of reports on stdout. |
| `-v` | | Log every probe to stderr. |
| `-f FILE` | | Targets from a file (`-` = stdin, `#` comments). |
| `--color` | `auto` | `auto`, `always`, `never` (`NO_COLOR` is honoured). |

### Exit codes (Nagios/Icinga compatible)

| Code | Meaning |
|------|---------|
| 0 | OK: the full MTU passes, or the constriction is signalled by ICMP |
| 1 | WARNING: MSS not clamped (PMTUD still works), unexpected MTU, oversize packets rejected, broken ICMP contents |
| 2 | CRITICAL: PMTUD black hole, IPv6 path MTU below 1280, unclamped MSS on a black-holed path |
| 3 | UNKNOWN: target does not answer probes, resolution failure, usage error, unsupported platform |

The worst status across all targets and families wins.

## Examples

A tunnel whose router signals its MTU correctly:

```
$ pmtud-probe 10.99.2.2
10.99.2.2 (IPv4, icmp)  OK
  local      10.99.1.2 via c0, interface MTU 1500
  path MTU   1400 bytes  (max UDP payload 1372, TCP MSS 1360; tried up to 1500)
  PMTUD      working
  ICMP       10.99.1.1 says MTU 1400 (probe 1500)
  probes     4 in 0.0s
  [INFO] pmtud-working: path MTU 1400: 10.99.1.1 reports the constriction with ICMP (ICMP Fragmentation Needed, MTU 1400), so PMTUD works
```

The same tunnel once a firewall drops ICMP type 3 code 4, checked together
with the HTTPS port:

```
$ pmtud-probe --tcp 8443 10.99.2.2
10.99.2.2 (IPv4, icmp)  CRITICAL
  local      10.99.1.2 via c0, interface MTU 1500
  path MTU   1400 bytes  (max UDP payload 1372, TCP MSS 1360; tried up to 1500)
  PMTUD      black-hole
  ICMP       no fragmentation-needed / packet-too-big message received
  TCP/8443   peer MSS >= 1460 (1500-byte segments) -> too-large
  probes     25 in 3.6s
  [CRIT] pmtud-black-hole: PMTUD black hole: packets larger than 1400 bytes towards 10.99.2.2 are dropped silently, without ICMP Fragmentation Needed. TCP sessions that rely on PMTUD will hang after the handshake. Allow ICMP type 3 code 4 through the firewalls on the path (never filter it) or clamp the TCP MSS to 1360 on the tunnel/edge router
  [CRIT] mss-not-clamped: MSS not clamped: the target's MSS arrives as at least 1460, so full segments are 1500-byte packets but the path carries 1400; PMTUD is broken on this path, so TCP transfers will stall after the handshake. Clamp the MSS to 1360 (e.g. nftables: tcp flags syn tcp option maxseg size set rt mtu)
```

After adding `tcp flags syn tcp option maxseg size set rt mtu` on the
router, the MSS check reports `peer MSS 1360 (1400-byte segments) -> fits`
(the black hole itself is still reported: UDP and ICMP traffic remain
affected).

Monitoring a known IPsec MTU from cron or Icinga, JSON for a dashboard:

```sh
pmtud-probe -4 --expect-mtu 1438 --tcp 443 vpn-peer.example.net
pmtud-probe --json -f edge-targets.txt > /var/lib/pmtud/report.json
```

### JSON

One object per target and family:

```json
{
  "target": "10.99.2.2", "address": "10.99.2.2", "family": "ipv4", "method": "icmp",
  "route": {"local_address": "10.99.1.2", "interface": "c0", "interface_mtu": 1500, "route_mtu": 1500},
  "upper_bound": 1500, "path_mtu": 1400, "max_udp_payload": 1372, "tcp_mss_for_path": 1360,
  "pmtud": "working",
  "ptb": [{"from": "10.99.1.1", "mtu": 1400, "probe_size": 1500}],
  "tcp": {"port": 8443, "snd_mss": 1448, "option_bytes": 12, "peer_mss": 1460, "peer_mss_lower_bound": true,
          "kernel_pmtu": 1500, "segment_size": 1500, "verdict": "too-large", "verdict_text": "..."},
  "findings": [{"code": "pmtud-working", "severity": "info", "message": "..."}],
  "status": "warning",
  "probes": [{"size": 36, "outcome": "reply", "from": "10.99.2.2", "rtt_ms": 0.1, "detail": "echo reply"}],
  "duration_ms": 12
}
```

`pmtud` is one of `not-needed`, `working`, `black-hole`, `filtered`,
`local`, `unknown`. `status` is `ok`, `info`, `warning`, `critical` or
`unknown`. Finding codes: `no-constriction`, `pmtud-working`,
`pmtud-black-hole`, `ptb-no-mtu`, `ptb-inconsistent`, `ptb-bogus`,
`oversize-rejected`, `local-route-mtu`, `kernel-pmtu-cache`,
`ipv6-below-minimum`, `unexpected-mtu`, `mss-fits`, `mss-not-clamped`,
`mss-inconclusive`, `tcp-connect`, `method-fallback`, `unreachable`,
`path-lost`, `probe-error`, `resolve`, `interrupted`.

## How it works

- Each probe is one datagram of an exact size on a fresh connected socket
  with `IP_MTU_DISCOVER=IP_PMTUDISC_PROBE` (DF set, the kernel's cached
  path MTU ignored, so earlier ICMP messages cannot bias the result) and
  `IPV6_DONTFRAG` for IPv6. ICMP errors come back through `IP_RECVERR` /
  `IPV6_RECVERR` with the address of the router that sent them; answers
  are matched to probes with a random nonce.
- The search bisects between a minimal control probe and the interface MTU.
  An MTU advertised by a router is tried next and then confirmed with one
  byte more, so a working PMTUD converges in four probes.
- A size only counts as **silently dropped** after `1 + --retries`
  unanswered attempts, a successful minimal control probe, and one more
  unanswered attempt. Random loss and ICMP rate limiting on the target
  (Linux sends 6 errors then 1/s) therefore do not fake a black hole.
- The MSS check runs **before** the probes: Linux's sending MSS is
  `min(peer MSS, cached PMTU − headers) − option bytes`, so it reveals the
  MSS the target advertised (after any clamping on the path) unless a
  cached path MTU already caps it, in which case the result is a lower
  bound and the verdict may be `inconclusive` (flush with
  `ip route flush cache` and re-run).

## Testing

```sh
go vet ./... && go test -race ./...
sudo lab/netns-lab.sh        # 14 end-to-end scenarios, PMTULAB_SHOW=1 prints the reports
```

Unit tests cover the error-queue and `tcp_info` decoding, the probe
sockets against loopback (UDP, ICMP, timeouts, cancellation), the search
against a simulated path (signalling and silent routers, several
constrictions, bogus or MTU-less ICMP, loss, rate limiting, IPv6, 400
randomised paths) and the CLI. `lab/netns-lab.sh` builds a real
three-namespace topology (client, router, server) and checks working
PMTUD, a black hole created with an nftables rule on the router, MSS
clamping with `maxseg size set rt mtu`, rejected oversize packets, route
MTUs and an unanswered target, with both probe methods.

## Limitations

- Linux only. Measures the path in one direction (this host → target); run
  it from the other end for the return path, which can differ.
- The MSS check sees the target's SYN-ACK, i.e. the segments **this host**
  will send. Whether *your* SYN is clamped on its way to the target is only
  visible from the target side.
- `--method icmp` needs unprivileged ping sockets
  (`sysctl net.ipv4.ping_group_range`, enabled by default on most current
  distributions); `auto` falls back to UDP otherwise. UDP probes need the
  target to answer ICMP port unreachable on `--port`; many hosts filter
  both, in which case the result is UNKNOWN rather than a guess.
- Probes that exceed the local interface MTU are refused by the kernel, so
  the upper bound is the interface MTU unless `--max` is lower. A lower
  route MTU (`ip route ... mtu`) is reported but bypassed by the probes.
- Equal-cost multipath with different MTUs per path can give a different
  answer per flow (each probe uses a new source port in UDP mode).
- No per-hop trace: the router that sends ICMP is reported, but a silent
  hop is not located (use `tracepath -n` for that).

## Security

- Read-only: it sends probe datagrams and TCP handshakes (closed right
  after `TCP_INFO` is read), never application data, and never changes
  the system. No privileges required, no secrets handled.
- Probe rate is low (one outstanding probe per target, typically 4 to 30
  probes) and every network call has a timeout. Only probe hosts you are
  responsible for or allowed to test.

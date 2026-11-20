# ntp-skew

Compare several NTP servers at once, find the **falsetickers** (servers
serving the wrong time), and measure the **local clock offset** against the
consensus of the others. One static binary, no privileges, no dependencies
outside the Go standard library.

`ntpq -p` and `chronyc sources` only show the sources a daemon is already
configured with, from the point of view of that daemon. `ntp-skew` answers
the questions you have before and around that:

- do the NTP servers of this site (or the ones in a client config) agree
  with each other, and which one is wrong?
- is this host's clock right, according to a majority of independent
  sources rather than the one its daemon happens to prefer?
- are the servers healthy from the outside: answering, synchronised, not
  rate-limiting or refusing clients, not free-running on a stale reference,
  not synchronised to each other in a loop, not all hanging off one single
  upstream?

## How it works

1. Every server is queried `--samples` times (default 4, 2 s apart). The
   request is a plain NTPv4 client-mode packet with a **random transmit
   timestamp** and every other field zero (RFC 9109 data minimisation: the
   local time is not disclosed), from a random source port. Answers must
   echo that cookie in their origin timestamp; anything else (late
   duplicates, spoofed or replayed packets) is ignored and counted.
2. Each exchange gives the offset θ = ((T2−T1) + (T3−T4)) / 2 and the delay
   δ = (T4−T1) − (T3−T2). The round trip T4−T1 is measured on the
   **monotonic clock**, so a clock step during the run cannot distort it.
   The exchange with the lowest delay is kept (RFC 5905 clock filter); the
   RMS spread of the others is the jitter.
3. The **root distance** λ = max(10 ms, root delay + δ)/2 + root dispersion
   + dispersion + jitter bounds the error of each server: if it is correct,
   the true time lies in [θ − λ, θ + λ].
4. The **intersection algorithm** (Marzullo's algorithm as implemented by
   ntpd 4.2.8) looks for the interval shared by a majority of those
   correctness intervals, tolerating f falsetickers with 2f < n. Servers
   whose interval does not reach it are **falsetickers**; the others are
   **truechimers**. (The RFC 5905 pseudo-code additionally counts interval
   midpoints and wrongly rejects correct servers with narrow intervals;
   ntpd dropped that test and so does `ntp-skew`.)
5. The truechimers' offsets, weighted by 1/λ, give the **consensus**; the
   local clock offset is reported against it.

Servers that cannot take part are reported with the reason: unreachable,
ICMP port unreachable, kiss-o'-death (`RATE`, `DENY`, `RSTR`, …; querying
stops at the first one, as RFC 5905 requires), not synchronised (leap
indicator 3, stratum 0 without kiss code, stratum 16), root distance above
`--max-distance` (1.5 s, RFC 5905 MAXDIST), or invalid answers.

## Checks

| Code | Severity | Meaning |
|------|----------|---------|
| `falseticker` | CRITICAL | Server's correctness interval does not overlap the majority's: it serves the wrong time. |
| `no-majority` | CRITICAL | No majority of sources agrees (with two sources, any disagreement): the true time cannot be established. |
| `local-offset` | WARNING / CRITICAL | Local clock further from the consensus than `--warn` (100 ms) / `--crit` (1 s). |
| `min-sources` | CRITICAL | Fewer usable sources than `--min-sources`. |
| `no-source` | UNKNOWN | No usable source at all. |
| `unreachable`, `unresolved`, `bogus` | WARNING | No answer / ICMP unreachable, name does not resolve, only invalid answers. |
| `kod-rate`, `kod-deny`, `kod` | WARNING | Kiss-o'-death: rate limited, or access refused by the server's ACL. |
| `unsynchronised` | WARNING | Server answers but has no synchronised clock; clients ignore it. |
| `too-far` | WARNING | Root distance above `--max-distance`; clients ignore it. |
| `stale-reference` | WARNING | Server last updated from its own upstream longer ago than `--max-ref-age` (24 h): probably free-running. |
| `reference-in-future` | WARNING | Reference timestamp later than the server's own clock. |
| `local-reference` | WARNING | Stratum ≥ 2 with refid 127.127.1.1: serving its own undisciplined clock (chrony `local`, ntpd LOCAL driver). |
| `inconsistent-timestamps` | WARNING | Server processing time (T3−T2) longer than the whole round trip: its two timestamps come from different clocks, or something on the path rewrites them. |
| `sync-loop` | WARNING | Two measured servers are synchronised to each other (refids point at each other). |
| `sync-from-this-host` | WARNING | A server is synchronised to this host: a loop if this host also uses it. |
| `common-upstream` | WARNING | Every source is synchronised to the same upstream: a fault there moves them all together and no falseticker can be detected (`--allow-common-upstream` turns it into a note). |
| `leap-disagreement` | WARNING | Sources disagree on the leap second warning (stale leap file, or smearing servers mixed with non-smearing ones). |
| `skew` | WARNING | A truechimer further than `--max-skew` from the consensus (off by default; use it for sub-millisecond requirements). |
| `stratum` | WARNING | Stratum above `--max-stratum` (off by default). |

Refids are resolved against the measured servers (IPv4 addresses, and the
MD5-based refid of IPv6 upstreams) and this host's addresses, so the table
shows who synchronises from whom.

## Installation

```sh
go install github.com/Hug0devSYS/sysnet-toolbox/tools/ntp-skew@latest
# or, from a checkout
cd tools/ntp-skew && go build -trimpath -ldflags "-s -w" -o ntp-skew .
```

Linux, macOS, Windows and the BSDs (plain UDP sockets).

## Usage

```
ntp-skew [flags] <server> [<server>...]
ntp-skew [flags] -f servers.txt
ntp-skew [flags] --config /etc/chrony.conf
ntp-skew [flags] --system
```

Targets: `host`, `host:port`, `[2001:db8::1]:123`, and w32time entries
(`time.example,0x9`). A name contributes one address (one server, one
vote) unless it comes from a `pool` directive or `--all-addresses` is
given; the same address is never measured twice.

`--config` reads the servers of an NTP client configuration: chrony and
ntpd (`server`, `pool`, `peer`, with `port`; reference clocks are skipped),
systemd-timesyncd (`NTP=`, else `FallbackNTP=`), and Windows peer lists
(output of `w32tm /query /peers`, or the `NtpServer` registry value).
`--system` reads every one of `/etc/chrony.conf`, `/etc/chrony/chrony.conf`,
`/etc/ntp.conf`, `/etc/ntpsec/ntp.conf`, `/etc/openntpd/ntpd.conf` and
`/etc/systemd/timesyncd.conf` that exists.

| Flag | Default | Meaning |
|------|---------|---------|
| `-4`, `-6` | both | Address family. |
| `--all-addresses` | | Measure every address of every name, not only of pools. |
| `--samples` | `4` | Exchanges per server (lowest delay wins). |
| `--interval` | `2s` | Spacing between exchanges with one server. Public servers rate-limit below about 2 s. |
| `--timeout` | `2s` | Wait time for each answer. |
| `--concurrency` | `16` | Servers measured in parallel. |
| `--warn`, `--crit` | `100ms`, `1s` | Local clock offset thresholds (`0` disables). |
| `--max-skew` | off | WARNING for a truechimer further than this from the consensus. |
| `--max-distance` | `1.5s` | Root distance above which a source is not selectable. |
| `--max-stratum` | off | WARNING above this stratum. |
| `--max-ref-age` | `24h` | WARNING when a server's reference is older (`0` disables). |
| `--min-sources` | `1` | CRITICAL when fewer sources are usable. |
| `--allow-common-upstream` | | Sources sharing one upstream is a note, not a WARNING. |
| `--json` | | JSON report on stdout. |
| `--prom-file FILE` | | Prometheus textfile-collector metrics, written atomically. |
| `-f FILE` | | Servers from a file (`-` = stdin, `#` comments). |
| `-v` | | Log every exchange to stderr. |
| `--color` | `auto` | `auto`, `always`, `never` (`NO_COLOR` is honoured). |

Exit codes: `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN (no usable
source, usage error, interruption). On SIGINT/SIGTERM the run stops at
once, `--json` still prints a valid document and `--prom-file` is left
untouched.

## Examples

Check the site's NTP servers and this host's clock:

```
$ ntp-skew ntp1.corp.example ntp2.corp.example ntp3.corp.example ntp4.corp.example
SERVER             ADDRESS     ST  REFID                           OFFSET    VS CONSENSUS  DELAY    JITTER  ROOT DIST  STATE
ntp1.corp.example  192.0.2.11  1   GPS                             -0.214ms  -0.051ms      0.402ms  31.0us  5.230ms    truechimer
ntp2.corp.example  192.0.2.12  1   PPS                             -0.137ms  +0.026ms      0.388ms  24.2us  5.201ms    truechimer
ntp3.corp.example  192.0.2.13  2   192.0.2.11 <ntp1.corp.example>  -0.140ms  +0.023ms      0.511ms  45.7us  5.792ms    truechimer
ntp4.corp.example  192.0.2.14  2   198.51.100.4                    +1.212s   +1.212s       0.497ms  38.1us  14.882ms   falseticker

Selection: 4 candidate(s), 3 truechimer(s), 1 falseticker(s); intersection [-5.012ms, +4.981ms]
Local clock: +0.163ms from the consensus (truechimer spread 0.077ms)

CRITICAL ntp4.corp.example (192.0.2.14): falseticker: +1.212s from the consensus; its correctness interval (+/- 14.882ms) does not overlap the one shared by the majority (3 of 4 sources)

NTP-SKEW CRITICAL - 1 falseticker(s), local clock +0.163ms from consensus of 3
```

Check what this host's daemon is configured with, as a Nagios/Icinga
check, and require at least three usable sources:

```sh
ntp-skew --system --min-sources 3 --samples 2 --interval 1s
```

Windows domain: compare the PDC emulator's peers with the domain
controllers themselves:

```powershell
w32tm /query /peers > peers.txt
ntp-skew --config peers.txt dc01.corp.example dc02.corp.example dc03.corp.example
```

Prometheus (node_exporter textfile collector), every 5 minutes:

```sh
*/5 * * * * ntp-skew --system --samples 3 --prom-file /var/lib/node_exporter/textfile/ntp_skew.prom >/dev/null
```

Metrics: `ntp_skew_server_up`, `ntp_skew_server_falseticker`,
`ntp_skew_server_offset_seconds`, `ntp_skew_server_consensus_offset_seconds`,
`ntp_skew_server_delay_seconds`, `ntp_skew_server_jitter_seconds`,
`ntp_skew_server_root_distance_seconds`,
`ntp_skew_server_reference_age_seconds`, `ntp_skew_server_stratum`
(labels `server`, `address`), `ntp_skew_truechimers`, `ntp_skew_majority`,
`ntp_skew_local_offset_seconds`, `ntp_skew_status`,
`ntp_skew_last_run_timestamp_seconds`.

## Limits

- Offsets use userspace timestamps around the socket calls: expect a few
  tens of microseconds of noise. This is a diagnostic tool, not a
  replacement for chrony's kernel/hardware timestamping; for PTP-grade
  requirements use the daemon's own statistics.
- An asymmetric path (different delays out and back) biases the offset by
  up to half the delay. A server far away can therefore look "skewed"
  without being wrong; the root distance (and so the falseticker test)
  accounts for it, `--max-skew` does not.
- Falsetickers can only be identified with at least three usable sources;
  with two that disagree, the result is "no majority".
- During a leap second, servers that **smear** it (Google, AWS, Meta
  public NTP) and servers that do not differ by up to 0.5 s; never mix
  both kinds in one client configuration, and expect `ntp-skew` to flag
  the minority as falsetickers.
- Authenticated NTP (symmetric keys, NTS) is not used: the tool measures
  what an unauthenticated client sees. NTS-only servers that refuse plain
  NTP show as unreachable or kiss-o'-death.
- Control queries (mode 6, `ntpq`) and monlist-style mode 7 queries are
  never sent.

## Security

- Read-only: client-mode requests only, the local clock is never touched,
  no privileges are needed (unprivileged UDP source port).
- Nothing about this host is disclosed in the requests (no local time, no
  refid, no stratum).
- Answers are only accepted from the queried address and port (connected
  socket) and only when they echo the random 64-bit cookie.
- Server-provided strings (refids, kiss codes) and names are escaped
  before they reach the terminal; Prometheus label values are escaped.

## Tests

```sh
go vet ./... && go test -race ./...
```

Unit tests cover the wire format (including the 2036 era rollover and the
IPv6 MD5 refid), the clock filter, spoofed and malformed answers, kiss
codes, the selection algorithm (with a randomised property test), the
analysis rules and the CLI end to end against scriptable NTP servers on
loopback UDP sockets. `lab/chrony-lab.sh` runs the binary against real
`chronyd` instances (one shifted with libfaketime, one rate-limiting, one
unsynchronised) without touching the system clock.

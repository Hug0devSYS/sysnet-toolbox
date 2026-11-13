# syslog-triage

Turn a pile of syslog or journald messages into a short list of **patterns**,
then tell what changed: which patterns suddenly **spiked**, and which ones
were **never seen before**.

- **Pattern mining with Drain** (He et al., ICWS 2017, with the Drain3
  refinements): messages are tokenized, obviously variable tokens are
  masked (`<IP>`, `<CIDR>`, `<MAC>`, `<UUID>`, `<HEX>`, `<NUM>`), and a
  fixed-depth prefix tree groups them into templates such as
  `Failed password for invalid user <*> from <IP> port <NUM> ssh2`.
  Interface names (`Gi1/0/1`, `ge-0/0/1.0`, `eth0`), paths and keywords
  are kept. One partition per program by default, so `sshd` and `nginx`
  never share a template.
- **Spike detection** per pattern and for the overall volume: counts per
  time bucket (5 minutes by default) compared with a robust trailing
  baseline (median + K × scaled MAD, floored by the Poisson deviation);
  burst buckets are excluded from the baseline, and a burst that lasts a
  whole window is reported as a *sustained* level shift.
- **New patterns**: either against a persistent **model** of known
  templates (`--model`, ideal for cron), or patterns that appeared within
  the `--recent` window of an otherwise longer input.
- **Formats detected per line**: RFC 3164 (with or without `<PRI>`,
  space- or zero-padded days, year inferred from the file time, New Year
  roll-over), RFC 3339 "high precision" lines (rsyslog, syslog-ng,
  `journalctl -o short-iso`), RFC 5424 with structured data, Cisco
  IOS/IOS-XE/NX-OS/ASA `%FAC-SEV-MNEMONIC` messages (with or without a
  relay header; the facility-mnemonic becomes the program and the
  mnemonic's severity is used) and `journalctl -o json` exports
  (including binary `MESSAGE` fields). Gzip-compressed rotated files are
  read transparently.
- Nagios/Icinga **exit codes**, text or **JSON** output.

Read-only: the tool only reads logs. The only file it can write is the
model, and only with `--update-model`. No dependencies outside the Go
standard library; about 400k lines/s on one core.

## Installation

```sh
go install github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage@latest
# or, from a checkout
cd tools/syslog-triage && go build -trimpath -ldflags "-s -w" -o syslog-triage .
```

Any OS supported by Go. No privileges are needed to analyse files you can
read. `--journal` runs `journalctl`, which shows the whole system journal
only to root and members of the `systemd-journal` (or `adm`/`wheel`,
depending on the distribution) group; other users see their own journal.

## Usage

```
syslog-triage [flags] [FILE...]            files may be gzip-compressed; "-" is stdin
journalctl -o json --since -2h | syslog-triage [flags]
syslog-triage --journal --since -2h [--unit UNIT]...
```

Flags may appear before or after the files. Main flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `--journal` | | read the local journal (`journalctl -o json`); `--unit` (repeatable) and `--journal-dir` (e.g. `/var/log/journal/remote`, a rescued disk) narrow it |
| `--since`, `--until` | | time window: RFC 3339, `2006-01-02 15:04[:05]`, `2006-01-02`, or relative `-2h`, `90m`, `7d` |
| `--min-severity LEVEL` | | drop less severe messages (messages without severity are kept) |
| `--app`, `--exclude-app`, `--host` | | regular expressions on program and host |
| `--tz ZONE` | `Local` | zone of timestamps without offset (RFC 3164) and of the text output |
| `--year N` | file mtime | year of RFC 3164 timestamps |
| `--raw` | | no header parsing: every line is a message (application logs; no spikes without timestamps) |
| `--sim` | `0.4` | Drain similarity threshold: higher gives more, finer patterns |
| `--depth`, `--max-children` | `4`, `100` | Drain tree depth and fan-out |
| `--max-tokens` | `80` | tokens compared per message; the rest is folded into `<*>` |
| `--no-app-split` | | cluster all programs together |
| `--model FILE` | | known patterns; anything else is **new** |
| `--update-model` | | write the updated model back (created on the first run, mode 0600, atomic) |
| `--model-max-age` | `90d` | forget patterns not seen for that long when saving |
| `--bucket` | `5m` | time bucket |
| `--window`, `--min-baseline` | `24`, `6` | baseline buckets, and history required before evaluating a bucket |
| `--threshold` | `5` | spike if count > median + threshold × robust sigma ... |
| `--min-ratio`, `--min-count` | `3`, `10` | ... and count ≥ min-ratio × median and ≥ min-count |
| `--recent DUR` | | only alert on spikes and new patterns within DUR of the last message |
| `--alert-severity LEVEL` | `debug` | spikes/new patterns of patterns less severe than LEVEL are listed but do not raise the status |
| `--crit-severity LEVEL` | `err` | at LEVEL or worse the status is CRITICAL |
| `--json`, `--top N`, `--sort` | text, `20`, `count` | output; sort by `count`, `severity`, `first`, `last`, `hosts`; `--top 0` lists all |
| `--examples`, `--wide`, `--quiet` | | text: example message per pattern, no truncation, alerts only |

The severity of a pattern is the most severe level among its messages.
Plain `/var/log/syslog` files written by rsyslog's default template carry
no severity; their patterns show `-` and always count as alerting.

## Examples

```sh
# What is this log made of, and did anything burst?
syslog-triage /var/log/syslog /var/log/syslog.1 /var/log/syslog.2.gz

# Last 2 hours of the local journal, errors and worse only.
syslog-triage --journal --since -2h --min-severity err

# Central syslog server, only the network devices, 1-minute buckets.
syslog-triage --host '^(sw|rtr|fw)-' --bucket 1m /var/log/remote/network.log

# Cron / Nagios: page on new or bursting error patterns of the last 15 minutes.
journalctl -o json --since -6h | \
  syslog-triage --model /var/lib/syslog-triage/model.json --update-model \
                --recent 15m --alert-severity warning --quiet
```

### Sample output

```
$ syslog-triage --tz UTC --top 6 syslog
syslog-triage CRITICAL: 57,624 messages, 8 patterns, 9 hosts, 6 programs
  range    2026-11-13 04:00:00 .. 2026-11-13 15:59:58 (UTC), bucket 5m

SPIKES (3)
  15:45-15:50  #8    err      kernel           peak 11/5m at 15:45, x11.0 over baseline 0.0, 11 msgs
      nf_conntrack: nf_conntrack: table full, dropping packet
  10:00-10:15  #7    info     sshd             peak 900/5m at 10:00, x450.0 over baseline 2.0, 2,700 msgs
      Failed password for invalid user <*> from <IP> port <NUM> ssh2
  10:00-10:15  ALL   -        *                peak 1,281/5m at 10:10, x3.3 over baseline 387.5, 3,805 msgs

NEW PATTERNS (0)
  not evaluated: use --model FILE or --recent DURATION

PATTERNS (6 of 8, by count)
      ID      COUNT      %  SEV      HOSTS  PROGRAM          TEMPLATE
       1     21,763  37.8%  info         8  sshd             Accepted publickey for <*> from <IP> port <NUM> ssh2: ED25519 <*>
       3     10,807  18.8%  info         8  systemd          Started Session <NUM> of User <*>
       2     10,707  18.6%  info         8  CRON             (root) CMD (/usr/local/bin/backup.sh --level <NUM>)
       4      8,205  14.2%  info         8  nginx            upstream response time <NUM> for <*>
       7      2,914   5.1%  info         1  sshd             Failed password for invalid user <*> from <IP> port <NUM> ssh2
       5      2,760   4.8%  warning      8  kernel           [<NUM>] eth0: link speed changed to <NUM>

$ syslog-triage --tz UTC --recent 1h --quiet syslog
syslog-triage CRITICAL: 57,624 messages, 8 patterns, 9 hosts, 6 programs
  range    2026-11-13 04:00:00 .. 2026-11-13 15:59:58 (UTC), bucket 5m
  alerts   since 2026-11-13 14:59:58 (--recent)

SPIKES (1)
  15:45-15:50  #8    err      kernel           peak 11/5m at 15:45, x11.0 over baseline 0.0, 11 msgs
      nf_conntrack: nf_conntrack: table full, dropping packet

NEW PATTERNS (1)
  #8     err      kernel           50 msgs, 1 host, first 2026-11-13 15:21:16
      nf_conntrack: nf_conntrack: table full, dropping packet
```

`--json` prints `summary`, `spikes`, `new_patterns`, `patterns` (with
severity counts, top hosts, first/last seen, an example message and
whether the pattern was known in the model), `status` and `exit_code`.
Pattern 0 in `spikes` is the overall volume.

## The model

The model is a JSON file holding the Drain parameters and the known
templates (with their tree path, total count and first/last seen). On
each run the tree is restored from it, so the same message lands in the
same pattern with the same ID across runs. When a model is loaded, its
clustering parameters (`--sim`, `--depth`, `--max-children`,
`--no-app-split`) take precedence over the flags. The first run with
`--update-model` creates the file and reports nothing as new. Run it on a
representative period first (for example a week of logs) so that normal
patterns are known. Delete the file to start over.

## Exit codes

| Code | Status | Meaning |
|------|--------|---------|
| 0 | OK | no spike and no new pattern (within `--recent`) |
| 1 | WARNING | spikes or new patterns |
| 2 | CRITICAL | spikes or new patterns of a pattern at `--crit-severity` or worse |
| 3 | UNKNOWN | usage error, unreadable input, invalid model, `journalctl` failure or timeout |

## Limitations

- Drain only merges messages with the same number of tokens, and routes
  on the first `depth-2` tokens: a variable first word that is not masked
  (a user name, for instance) can split a template. Raising `--depth`
  makes templates more specific; `--max-children` caps the fan-out.
- Multi-line messages (stack traces) in plain files are read line by
  line; journald keeps them together.
- RFC 3164 has no year and usually no time zone: use `--tz` and, for old
  files whose modification time is misleading, `--year`.
- Does not listen on the network: feed it files, stdin or the journal.
- Spike detection needs history: a bucket is evaluated only after
  `--min-baseline` buckets, so analyse a window several times longer than
  the period you care about (for example `--since -6h --recent 15m`).

## Security

- Read-only; the model is written only with `--update-model`, through a
  temporary file and a rename, with mode 0600 (templates can contain user
  or host names).
- Control characters in log messages are replaced before printing, so a
  hostile log line cannot inject terminal escape sequences.
- Lines longer than 64 KiB are truncated; the time series is capped
  (500,000 buckets) so a bogus timestamp cannot exhaust memory.
- `journalctl` is run without a shell, with a timeout (`--timeout`).

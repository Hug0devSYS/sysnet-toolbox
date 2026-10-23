# tlsaudit

Audit a fleet of TLS endpoints in one pass — certificate expiry, broken or
incomplete chains, SAN mismatches, legacy protocols, weak cipher suites, weak
DHE groups and OCSP stapling — with output for humans, for scripts (JSON),
for Nagios/Icinga (exit codes) and for Prometheus (textfile collector).

One static binary, no third-party Go modules, no OpenSSL dependency.

## Why another TLS scanner?

`openssl s_client` shows one handshake; `testssl.sh` and `sslyze` are
excellent but heavy for a cron job across hundreds of endpoints. `tlsaudit`
is built for the fleet use case:

- runs many targets in parallel and returns **one exit code**;
- a **one-line-per-target summary** and a **Prometheus file** for alerting on
  expiry and regressions;
- it **validates the chain itself** (instead of trusting a single client's
  behaviour) and tells an *incomplete chain* apart from an *untrusted CA*;
- it speaks **STARTTLS** (SMTP, IMAP, POP3, FTP, LDAP, PostgreSQL), so mail
  and directory servers are first-class targets;
- it enumerates suites with **hand-built ClientHellos**, so it detects
  SSLv3, export, NULL, anonymous, RC4, DES and DHE suites that Go's own TLS
  stack (and many modern clients) cannot even offer.

## What it checks

| Check | Detected | Severity |
|-------|----------|----------|
| `connect` | DNS failure, refused/timed-out TCP, STARTTLS refused, no TLS handshake possible | error |
| `expiry` | Leaf or chain certificate expired / not yet valid / expiring within `--crit-days` | error |
| | Expiring within `--warn-days` | warning |
| `hostname` | Certificate does not cover the SNI / target name (wildcards and IP SANs handled) | error |
| `chain` | Incomplete chain (missing intermediate, confirmed via AIA with `--fetch-aia`), untrusted root, self-signed leaf, invalid chain (EKU, name constraints, CA flags), SHA-1 signed intermediates | error |
| | Served chain out of order, extra certificates not on the validated path | warning |
| | Root certificate sent (useless bytes) | info |
| `certificate` | RSA key < 2048 bits, ECDSA < P-256, SHA-1/MD5 signature | error |
| | No subjectAltName | warning |
| | Lifetime > 398 days (public CA limit) | info |
| `protocol` | SSLv3 enabled; neither TLS 1.2 nor TLS 1.3 | error |
| | TLS 1.0 / TLS 1.1 enabled (RFC 8996) | warning |
| | TLS 1.3 not supported | info |
| `cipher` | Insecure suites accepted: NULL, export, anonymous, RC4, DES, RC2, MD5 | error |
| | Weak suites: 3DES/IDEA (SWEET32), no forward secrecy (static RSA/DH/ECDH) | warning |
| | Legacy CBC suites (count only) | info |
| `key-exchange` | DHE group < 1024 bits (Logjam) | error |
| | DHE group < 2048 bits | warning |
| `ocsp` | Must-Staple certificate without staple; revoked; invalid or mis-signed staple; stale staple (`nextUpdate` passed) | error |
| | Status `unknown`; `thisUpdate` in the future; old staple without `nextUpdate` | warning |
| | No staple although the certificate has an OCSP URL | info |
| `renegotiation` | No RFC 5746 secure renegotiation (TLS ≤ 1.2) | warning |
| `fallback-scsv` | Legacy versions enabled and `TLS_FALLBACK_SCSV` (RFC 7507) not honoured | warning |

The stapled OCSP response is fully parsed and its signature is verified
against the issuer (or a delegated responder certificate carrying the
OCSPSigning EKU and signed by the issuer).

## Installation

Requires Go 1.22+ to build. No cgo, no external modules.

```sh
go install github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit@latest

# or from a checkout
cd tools/tlsaudit
go build -trimpath -ldflags "-s -w -X github.com/Hug0devSYS/sysnet-toolbox/tools/tlsaudit/internal/cli.Version=0.1.1" -o tlsaudit .

# static cross-compilation, e.g. for a monitoring host
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o tlsaudit-linux-arm64 .
```

## Usage

```
tlsaudit [flags] <target> [<target>...]
tlsaudit [flags] -f targets.txt

  -json               JSON array of reports on stdout
  -summary            one line per target instead of full reports
  -prom-file PATH     also write Prometheus metrics (atomic write)
  -f FILE             read targets from FILE ('-' = stdin, '#' comments)
  -timeout 5s         per connection (dial + STARTTLS + handshake)
  -max-time 2m        overall budget per target
  -concurrency 8      targets audited in parallel
  -warn-days 30       WARNING threshold for certificate expiry
  -crit-days 7        CRITICAL threshold for certificate expiry
  -ca-file PEM        extra trusted roots (private PKI)
  -ca-only            trust only -ca-file, not the system store
  -no-ciphers         skip suite enumeration (~6 connections per target)
  -fetch-aia          download missing intermediates from AIA URLs
  -4 / -6             IPv4 / IPv6 only
  -v                  log every connection to stderr
  -color auto         auto, always, never (NO_COLOR is honoured)
  -version            print version
```

Flags may appear before or after targets; `-json` and `--json` both work.
Repeated targets (same endpoint, SNI, `connect=` and STARTTLS) are audited
once, with a note on stderr. An interrupted run (SIGINT/SIGTERM) exits 3
(UNKNOWN) and leaves an existing `--prom-file` untouched, so endpoints that
were never reached are not published as failures.

### Target syntax

```
example.com                         port 443, SNI example.com
example.com:8443
192.0.2.10                          IP target: no SNI, IP SAN verified
[2001:db8::10]:443
smtp://mx.example.com               STARTTLS on 25 (submission:// = 587)
imap://mail.example.com             STARTTLS on 143 (imaps:// = 993)
ldap://dc1.corp.example             LDAP StartTLS on 389 (ldaps:// = 636)
postgres://db1.example.com          SSLRequest on 5432
'www.example.com connect=10.0.0.5'  audit one backend behind a VIP / LB
'10.0.0.5 sni=www.example.com'      same, addressed by IP
'example.com sni=none'              see the default certificate
'db1:6432 starttls=postgres'        STARTTLS on a non-standard port
```

Options: `sni=NAME|none`, `connect=IP|HOST[:PORT]`, `starttls=smtp|imap|pop3|ftp|ldap|postgres|none`.
Supported schemes: `https`, `tls`, `smtps`, `imaps`, `pop3s`, `ftps`,
`ldaps` (implicit TLS) and `smtp`, `submission`, `imap`, `pop3`, `ftp`,
`ldap`, `postgres` (STARTTLS).

### Exit codes (Nagios/Icinga compatible)

| Code | Meaning |
|------|---------|
| 0 | OK — no warnings or errors on any target |
| 1 | WARNING — at least one warning |
| 2 | CRITICAL — at least one error (expired, untrusted chain, mismatch, unreachable, ...) |
| 3 | UNKNOWN — usage error, unreadable target file or CA file, metrics file not writable |

With several targets the highest code wins. An unreachable endpoint is
CRITICAL (like `check_http`), not UNKNOWN.

### Examples

```sh
# One endpoint, full report
tlsaudit www.example.com

# Fleet audit from cron, metrics for node_exporter, quick mode
tlsaudit -f /etc/tlsaudit/targets.txt --no-ciphers --summary \
  --prom-file /var/lib/node_exporter/textfile/tlsaudit.prom

# Internal services signed by a private CA
tlsaudit --ca-file /etc/pki/corp-root.pem --ca-only ldap://dc1.corp.example 'pg.corp.example:5432 starttls=postgres'

# Mail servers, JSON for further processing
tlsaudit --json smtp://mx1.example.com smtp://mx2.example.com | jq '.[] | {name, summary}'

# Every node behind a load balancer
for ip in 10.0.0.11 10.0.0.12 10.0.0.13; do echo "www.example.com connect=$ip"; done | tlsaudit -f - --summary
```

### Sample output

```
Target: legacy.example.net:443
Address 203.0.113.20:443, SNI legacy.example.net, checked at 2026-10-14T16:10:02Z in 412 ms (31 connections)
Negotiated TLS1.2 with TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Certificate
  Subject     CN=legacy.example.net
  Issuer      CN=Example Issuing CA 2,O=Example
  SANs        legacy.example.net, www.legacy.example.net  [matches]
  Key         RSA 2048 bits, signed with SHA256-RSA
  Validity    2026-08-01 -> 2026-10-30 (15 days left)
  Serial      4C1F...
  SHA-256     5e0b...

Chain: incomplete (1 served)
  #0 CN=legacy.example.net                            expires 2026-10-30

OCSP: not stapled

Protocols:  SSLv3 no  TLS1.0 yes  TLS1.1 yes  TLS1.2 yes  TLS1.3 no
  secure renegotiation yes, TLS_FALLBACK_SCSV yes

Cipher suites (TLS <= 1.2)
  TLS1.2  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256          good     x25519
  TLS1.2  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA             legacy   x25519
  TLS1.2  TLS_RSA_WITH_AES_128_CBC_SHA                   weak
  TLS1.2  TLS_RSA_WITH_3DES_EDE_CBC_SHA                  weak
  ...

Findings
  WARN  [expiry] certificate expires in 15 day(s) on 2026-10-30
  ERROR [chain] issuer "CN=Example Issuing CA 2,O=Example" of CN=legacy.example.net was not sent by the server and is not a trusted root (AIA caIssuers: http://pki.example.net/ca2.crt): incomplete chain or untrusted CA (use --fetch-aia to confirm, or --ca-file for a private CA)
  INFO  [ocsp] no OCSP staple (clients must query http://ocsp.example.net themselves)
  WARN  [protocol] TLS 1.0 is enabled (deprecated by RFC 8996)
  WARN  [protocol] TLS 1.1 is enabled (deprecated by RFC 8996)
  INFO  [protocol] TLS 1.3 is not supported
  WARN  [cipher] TLS1.2 accepts 2 weak cipher suite(s): TLS_RSA_WITH_AES_128_CBC_SHA (no forward secrecy (static RSA key exchange)), TLS_RSA_WITH_3DES_EDE_CBC_SHA (64-bit block cipher (SWEET32))
  ...

Result: ERROR (1 error(s), 7 warning(s))
```

`--summary`:

```
STATUS   TARGET                                   DAYS   CHAIN       BEST       TOP FINDING
OK       www.example.com:443                      61     trusted     TLS1.3
WARNING  mx1.example.com:25                       12     trusted     TLS1.3     [expiry] certificate expires in 12 day(s) on 2026-10-26
ERROR    legacy.example.net:443                   15     incomplete  TLS1.2     [chain] issuer "CN=Example Issuing CA 2,O=Example" of ...
```

### Prometheus metrics

All per-endpoint metrics carry `target` (host:port) and `servername` labels,
plus `connect` for targets audited with `connect=` (several nodes behind one
name each get their own series; targets without `connect=` keep exactly the
same series as before 0.1.1).

| Metric | Meaning |
|--------|---------|
| `tlsaudit_probe_success` | 1 if a handshake succeeded and a certificate was retrieved |
| `tlsaudit_cert_not_after_timestamp_seconds` | Leaf `notAfter` (Unix time) |
| `tlsaudit_cert_expiry_seconds` | Seconds until expiry (negative once expired) |
| `tlsaudit_chain_trusted` | 1 if the chain validates |
| `tlsaudit_hostname_match` | 1 if the certificate covers the name |
| `tlsaudit_protocol_enabled{protocol}` | 1 per accepted version (SSLv3 … TLS1.3) |
| `tlsaudit_cipher_suites{grade}` | Accepted TLS ≤ 1.2 suites by grade |
| `tlsaudit_ocsp_stapled`, `tlsaudit_ocsp_status{status}` | Stapling and stapled status |
| `tlsaudit_findings{severity}` | Number of findings |
| `tlsaudit_scan_duration_seconds` | Audit duration per endpoint |
| `tlsaudit_last_run_timestamp_seconds` | Time of the run (alert on staleness) |

Example alert: `tlsaudit_cert_expiry_seconds < 14*86400` or
`tlsaudit_protocol_enabled{protocol=~"SSLv3|TLS1.0"} == 1`.

## How it works

1. A reference handshake with Go's `crypto/tls` (TLS 1.0–1.3, every suite Go
   implements) retrieves the chain, the stapled OCSP response and the
   parameters a modern client negotiates. Certificate verification is
   disabled for this handshake only; `tlsaudit` then validates the chain
   itself with `x509.Verify` (system roots or `--ca-file`, `serverAuth` EKU).
2. Raw ClientHellos for SSLv3, TLS 1.0, 1.1 and 1.2 offering ~140 suites
   determine which versions are accepted. The server's first flight
   (ServerHello, Certificate, CertificateStatus, ServerKeyExchange) is parsed
   in clear text; the handshake is then abandoned — no key exchange is ever
   completed.
3. Suite enumeration repeats the raw ClientHello, removing the server's
   choice each time, until the server refuses (≈ one connection per
   accepted suite and version).
4. A TLS 1.1/1.0 hello carrying `TLS_FALLBACK_SCSV` checks downgrade
   protection when both legacy and modern versions are enabled.

ClientHellos are padded (RFC 7685) to avoid the 256–511-byte hang of some
load balancers. Finite-field groups are deliberately not offered, so RFC 7919
servers still reveal their legacy DHE parameters.

## Limitations

- TLS 1.3 suites are not enumerated (Go offers the three mandatory ones;
  all TLS 1.3 suites are AEAD and forward secret). TLS 1.3 support and the
  negotiated suite are reported.
- SSLv2 is not probed. Suites outside the built-in list (PSK, SRP, GOST,
  ARIA, …) are not detected.
- Only the first resolved address of a name is audited; use `connect=` to
  audit each node of a pool explicitly.
- Revocation is checked through the stapled OCSP response only; `tlsaudit`
  does not query OCSP responders or download CRLs. Certificate Transparency
  (SCTs), HSTS and client-certificate authentication are out of scope.
- `--fetch-aia` understands DER and PEM, not PKCS#7 (`.p7c`) bundles.
- Full enumeration opens up to ~150 short connections per target; an IPS or
  `fail2ban` may rate-limit you — use `--no-ciphers` for routine monitoring
  and full scans less often.

## Security

- **Read-only.** `tlsaudit` performs TLS handshakes and STARTTLS upgrades
  only. It never sends application data, credentials or client
  certificates, and never completes a key exchange in raw mode.
- No privileges required; no files are written except `--prom-file`
  (atomically, mode 0644).
- `--fetch-aia` makes HTTP requests to the URLs found in the certificates
  (bounded to 1 MiB, `--timeout`); it is off by default so that `tlsaudit`
  only talks to the endpoints you list.
- Only audit endpoints you own or are authorised to assess: cipher
  enumeration is visible in server logs and may trip intrusion detection.

# cert-inventory

Inventory and audit of the **machine certificate stores of a Windows fleet**
over WinRM — and of the services that actually *use* those certificates.

Expiry monitoring that only looks at certificates misses the classic outage:
the certificate *was* renewed (autoenrollment did its job), but IIS, ADFS or
the WinRM listener is still bound to the old one. `cert-inventory` reads the
stores **and** the bindings, so it can tell these cases apart:

| Situation | Code | Severity |
|-----------|------|----------|
| Bound certificate expires within `-CriticalDays` / `-WarningDays`, and a renewed certificate exists but is **not bound** | `RENEWED_NOT_REBOUND` | critical / warning |
| Certificate with a private key expires soon, no renewal found | `EXPIRING` | critical / warning |
| Expired certificate still bound to a service | `EXPIRED_BOUND` | critical |
| Expired certificate with no renewal | `EXPIRED` | warning |
| Expired certificate already replaced (clean-up candidate) | `SUPERSEDED` | info |
| Expiring certificate already renewed, old one not bound | `RENEWED` | info |
| Binding points to a thumbprint that is not in the store | `BINDING_CERT_MISSING` | critical |
| Binding uses a certificate without a private key | `BINDING_NO_PRIVATE_KEY` | critical |
| Private key **exportable** (CNG export policy / CAPI container flag), plaintext export mentioned | `EXPORTABLE_KEY` | warning (info with `-AllowExportable`) |
| RSA < 2048 bits (critical if bound or < 1024), DSA, ECC < 256 | `WEAK_KEY` | warning / critical |
| MD5 or SHA-1 signature on an issued certificate | `WEAK_SIGNATURE` | warning |
| Server certificate without SubjectAltName (browsers ignore the CN) | `NO_SAN` | warning if bound to HTTP.sys/WinRM, else info |
| Self-signed certificate bound to HTTP.sys or WinRM | `SELF_SIGNED_BOUND` | info |
| Same certificate and private key on several hosts (wildcard sprawl) | `SHARED_KEY` | info |
| Expired certificates in trust stores (one line per store) | `TRUST_EXPIRED` | info |
| Private key not readable (permissions) | `KEY_UNREADABLE` | info |
| Store or binding source not readable on a host | `COLLECTION_PARTIAL` | warning |
| Host unreachable (WinRM, authentication, timeout) | `HOST_FAILED` | unknown |
| Offline collection older than `-MaxCollectionAgeDays` | `STALE_COLLECTION` | warning |

A renewal is a certificate in the same store with the same subject (and the
same ADCS template when both carry one), a private key, valid now and
expiring later.

Every certificate is also inventoried with its **ADCS template** (name for v1
templates; OID, major/minor version and — on domain members — the name
resolved by Windows for v2+ templates), SubjectAltName (DNS, IP, UPN), EKUs,
key algorithm/size/curve, signature algorithm, key provider and key storage
(software, **TPM**, smart card, third-party KSP/HSM). A per-template count is
printed at the end of the report.

### Bindings discovered

| Service | Source |
|---------|--------|
| HTTP.sys (IIS, ADFS, WAP, WinRM over HTTP.sys, Exchange, custom services) — IP:port and SNI bindings | `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo`, `SslSniBindingInfo` |
| Remote Desktop listener | CIM `root\cimv2\TerminalServices` `Win32_TSGeneralSetting` |
| WinRM HTTPS listeners | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener` |

The registry is read directly, so the result does not depend on the
language of `netsh` output.

## Installation

No module to install on the audited hosts: the collector
(`src/Collector.ps1`, Windows PowerShell 5.1 compatible, no dependencies) is
sent by `Invoke-Command -FilePath` at run time.

On the administration host (Windows, PowerShell 5.1 or 7.x):

```powershell
git clone https://github.com/Hug0devSYS/sysnet-toolbox.git
cd sysnet-toolbox/tools/cert-inventory
./cert-inventory.ps1 -?            # full help: Get-Help ./cert-inventory.ps1 -Full
```

or import the module (`Import-Module ./CertInventory.psd1`) to use the
functions from your own scripts (`Invoke-CertInventoryCollection`,
`New-CertInventoryReport`, `ConvertTo-CertInventoryCsvRow`, ...).

Offline analysis (`-InputPath`) runs anywhere PowerShell 7 runs, including
Linux and macOS.

## Usage

```
./cert-inventory.ps1 [[-ComputerName] <host[]>] [-ComputerListPath <file>]
                     [-Credential <pscredential>] [-UseSSL] [-Port <n>]
                     [-Authentication Default|Kerberos|Negotiate]
                     [-ThrottleLimit 32] [-TimeoutSeconds 60]
                     [-StoreName <store[]>] [-SkipKeyInspection] [-CollectOnly]
                     [-WarningDays 30] [-CriticalDays 14] [-MinRsaKeySize 2048]
                     [-AllowExportable <pattern[]>]
                     [-Json] [-CsvPath <file>] [-OutFile <file>] [-ShowInfo] [-Inventory]

./cert-inventory.ps1 -InputPath <file-or-dir[]> [-MaxCollectionAgeDays 7] [analysis and output options]
```

Without `-ComputerName`/`-ComputerListPath`, the local computer is audited
(no WinRM involved). `-ComputerListPath` takes one host per line (`#`
comments allowed) or a CSV with a `DNSHostName`, `ComputerName`, `Name`,
`Host` or `Hostname` column, so an AD export works as is:

```powershell
Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties DNSHostName |
    Select-Object DNSHostName | Export-Csv servers.csv -NoTypeInformation
./cert-inventory.ps1 -ComputerListPath servers.csv -CsvPath certs.csv
```

Default stores: `My`, `WebHosting`, `Remote Desktop`, `Root`, `CA`,
`TrustedPeople`, `TrustedPublisher` (all `LocalMachine`). Stores that do not
exist on a host (e.g. `WebHosting` without IIS) are skipped silently.

### Examples

```powershell
# Whole web tier, Kerberos, 64 parallel connections
./cert-inventory.ps1 -ComputerListPath web-servers.txt -ThrottleLimit 64

# DMZ hosts over WinRM HTTPS with explicit credentials, JSON for a pipeline
./cert-inventory.ps1 dmz-web01.example.com, dmz-web02.example.com -UseSSL -Credential (Get-Credential) -Json -OutFile dmz.json

# Exportable keys are expected for one template
./cert-inventory.ps1 -ComputerListPath servers.txt -AllowExportable 'CorpWebServer-Exportable'

# Hosts that WinRM cannot reach: collect locally (RMM, GPO scheduled task,
# SCCM script) to a share, then analyse centrally — from any OS
./cert-inventory.ps1 -CollectOnly -OutFile "\\fs01\certs$\$env:COMPUTERNAME.json"
pwsh ./cert-inventory.ps1 -InputPath /mnt/certs -CsvPath inventory.csv
```

### Sample output

```
cert-inventory 0.1.0: CRITICAL - 3 host(s), 0 failed, 6 certificate(s); 2 critical, 5 warning, 0 unknown, 1 info

app02.corp.example.com  (Microsoft Windows Server 2022 Datacenter, collected 2026-11-18T17:07:45Z)
  CRITICAL BINDING_CERT_MISSING   http.sys 0.0.0.0:8443 references certificate 9999AAAABBBBCCCCDDDDEEEEFFFF000011112222, which is not in the MY store
  WARNING  EXPIRING               [My] CN=legacy-app.corp.example.com 0D1E2F3A4B5C  expires in 24 day(s) (2026-12-13)
  WARNING  EXPORTABLE_KEY         [My] CN=*.corp.example.com 5C9E0F1A2B3C  private key is exportable in plaintext (Microsoft Software Key Storage Provider)
  WARNING  WEAK_KEY               [My] CN=legacy-app.corp.example.com 0D1E2F3A4B5C  RSA 1024 bits (< 2048)
  WARNING  WEAK_SIGNATURE         [My] CN=legacy-app.corp.example.com 0D1E2F3A4B5C  signed with sha1RSA

web01.corp.example.com  (Microsoft Windows Server 2022 Datacenter, collected 2026-11-18T17:07:45Z)
  CRITICAL RENEWED_NOT_REBOUND    [My] CN=web01.corp.example.com 3F2A9C1D0B7E  expires in 8 day(s) (2026-11-27), bound to http.sys 0.0.0.0:443; renewed certificate A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 is not bound

app03.corp.example.com  (Microsoft Windows Server 2022 Datacenter, collected 2026-11-18T17:07:45Z)
  WARNING  EXPORTABLE_KEY         [My] CN=*.corp.example.com 5C9E0F1A2B3C  private key is exportable in plaintext (Microsoft Software Key Storage Provider)

1 informational finding(s) hidden; use -ShowInfo to list them.

Certificates per ADCS template:
       2  CorpWebServer
       2  CorpWebServer-Exportable
       1  WebServer
```

`-ShowInfo` adds the informational findings (here `SHARED_KEY`: the wildcard
certificate and its key live on app02 and app03). `-Inventory` appends a
table of every certificate with a private key or a binding (host, store, days
left, key, exportability, template, subject).

### Output formats

- **Text** (default): findings grouped per host, most severe hosts first,
  control characters in certificate fields escaped.
- **`-Json`**: the complete report — summary, findings, and for every host
  its bindings and certificates with all extracted fields; dates are ISO 8601
  UTC strings on both PowerShell 5.1 and 7.
- **`-CsvPath`**: one row per certificate per host (host, store, subject,
  issuer, thumbprint, serial, validity, days left, DNS names, template, key,
  signature, exportability, storage, provider, bindings, finding codes) for
  Excel or a CMDB import. Cells starting with `=`, `+`, `-` or `@` are
  prefixed with `'` (formula injection).
- **`-CollectOnly`**: the raw per-host collections as JSON, input for a
  later `-InputPath` run.

### Exit codes (Nagios/Icinga compatible)

| Code | Meaning |
|------|---------|
| 0 | OK — no warning or critical finding |
| 1 | WARNING — at least one warning |
| 2 | CRITICAL — at least one critical finding |
| 3 | UNKNOWN — a host could not be audited (and nothing is critical), or a usage/input error |

## Required rights

- **Remote collection**: WinRM enabled on the targets and an account allowed
  to connect (member of the local *Administrators* or *Remote Management
  Users* group). Reading certificates needs no privilege; reading the
  **export policy** of machine private keys needs read access to the key,
  which in practice means local administrator. Without it the certificate is
  still inventoried and `KEY_UNREADABLE` is reported (info).
- **Local collection** (`-ComputerName localhost` or no target): run
  elevated for the same reason.
- **Offline analysis**: no rights, any OS with PowerShell 7.

## Limitations

- Only `LocalMachine` stores. User stores and service-account stores
  (`Services\<name>\My`) are not collected.
- Bindings cover HTTP.sys, RDP and WinRM. Other consumers (SQL Server
  `Certificate` registry value, LDAPS on domain controllers, Exchange
  services, ADFS service-communication certificate stored in its database,
  Hyper-V replica, custom services) are not detected: their certificates are
  still checked for expiry, but a renewed-but-not-rebound case is only
  visible as `RENEWED` (info).
- IIS Central Certificate Store bindings (`SslCcsBindingInfo`) carry no
  thumbprint and are not checked.
- ADCS template **names** for v2+ templates are those Windows resolves on the
  audited host (domain members); otherwise only the OID is shown.
- Chain building and revocation (CRL/OCSP) are not checked: use `tlsaudit`
  for the endpoints and the planned `pki-health` for revocation
  infrastructure.
- WinRM collection requires Windows on the administration host;
  `-InputPath` analysis works everywhere.

## Security

- **Read-only.** Stores are opened with `ReadOnly | OpenExistingOnly`;
  nothing is imported, removed or modified. Private keys are opened only to
  read their export policy (CNG `ExportPolicy`, CAPI `CspKeyContainerInfo`)
  and are disposed immediately — never exported, never used to sign. Use
  `-SkipKeyInspection` to not open keys at all.
- Credentials come from `-Credential` (a `PSCredential`, e.g.
  `Get-Credential` or a SecretManagement vault) or the current Kerberos
  identity; nothing is stored. CredSSP is deliberately not offered (it
  delegates reusable credentials to the target).
- The collection contains no secret material (public certificate fields and
  key metadata only), but it is an inventory of your PKI: protect report
  files and collection shares accordingly.
- Certificate fields are untrusted input: control characters are escaped in
  the text report and CSV cells are protected against formula injection.

## Development

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error
Invoke-Pester -Path ./tests -Output Detailed
```

The unit tests run on any OS: certificates are generated with
`CertificateRequest` (SAN, EKU, basic constraints, v1/v2 template
extensions), the registry, CIM and WinRM are mocked, and the CLI is tested
end to end on JSON collections. `tests/Windows.Tests.ps1` runs on Windows
only (CI `windows-latest`): it creates exportable and non-exportable test
certificates in `LocalMachine\My`, runs the collector under PowerShell 7
**and Windows PowerShell 5.1** (the runtime used on remote hosts), and
removes them.

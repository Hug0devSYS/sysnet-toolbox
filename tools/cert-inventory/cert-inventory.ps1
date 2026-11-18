<#
.SYNOPSIS
    Inventory and audit the machine certificate stores of a Windows fleet over WinRM.

.DESCRIPTION
    cert-inventory collects every certificate of the LocalMachine stores
    (My, WebHosting, Remote Desktop, Root, CA, TrustedPeople, TrustedPublisher
    by default), the certificates bound to HTTP.sys (IIS, ADFS, WAP, custom
    services), RDP and WinRM HTTPS listeners, and reports:

      - expired and expiring certificates, with renewal awareness: a renewed
        certificate that was never bound (RENEWED_NOT_REBOUND) or an expired
        certificate still bound to a service (EXPIRED_BOUND);
      - bindings that point to a missing certificate or one without a
        private key;
      - exportable private keys (CNG export policy / CAPI container flag),
        with TPM and smart card keys recognised;
      - weak keys (RSA < 2048, DSA, ECC < 256) and MD5/SHA-1 signatures;
      - server certificates without SubjectAltName;
      - ADCS template (name, OID, version) of every certificate;
      - the same certificate and private key deployed on several hosts.

    Read-only: stores are opened read-only, private keys are only opened to
    read their export policy and are never exported or used.

    Targets are reached with Invoke-Command (WinRM). The local computer is
    collected without WinRM. Collections can be saved with -CollectOnly and
    analysed later or elsewhere with -InputPath (any OS with PowerShell 7).

.PARAMETER ComputerName
    Hosts to audit. '.', 'localhost' or the local name collect the local
    computer without WinRM. Defaults to the local computer.

.PARAMETER ComputerListPath
    File with one host per line ('#' comments allowed) or a CSV export with a
    DNSHostName, ComputerName, Name, Host or Hostname column (for example
    Get-ADComputer ... | Export-Csv).

.PARAMETER InputPath
    Analyse collections saved with -CollectOnly (JSON files, or directories
    containing them) instead of contacting hosts.

.PARAMETER Credential
    Credential for WinRM. Without it, the current identity is used
    (Kerberos in a domain).

.PARAMETER UseSSL
    Use WinRM over HTTPS (port 5986 unless -Port is given).

.PARAMETER Port
    WinRM port.

.PARAMETER Authentication
    Default, Kerberos or Negotiate. CredSSP is intentionally not offered.

.PARAMETER ThrottleLimit
    Maximum number of concurrent WinRM connections (default 32).

.PARAMETER TimeoutSeconds
    WinRM open and operation timeout per host (default 60).

.PARAMETER StoreName
    LocalMachine stores to collect.

.PARAMETER SkipKeyInspection
    Do not open private keys (no export policy, no key storage detection).

.PARAMETER CollectOnly
    Only collect: write the raw collections as JSON (to -OutFile or stdout)
    for a later -InputPath run. Exit code 0 if every host was collected, 3
    otherwise.

.PARAMETER WarningDays
    Warn when a certificate in use expires within this many days (default 30).

.PARAMETER CriticalDays
    Critical when a certificate in use expires within this many days (default 14).

.PARAMETER MinRsaKeySize
    Minimum acceptable RSA key size (default 2048).

.PARAMETER AllowExportable
    Wildcard patterns (template name or OID, subject, thumbprint) for which
    an exportable private key is expected; reported as info instead of
    warning.

.PARAMETER MaxCollectionAgeDays
    With -InputPath, warn when a collection is older than this (default 7,
    0 disables).

.PARAMETER Json
    Write the full report as JSON to stdout.

.PARAMETER CsvPath
    Also write the certificate inventory (one row per certificate per host) to this CSV file.

.PARAMETER OutFile
    Write the report (or the raw collections with -CollectOnly) to this file instead of stdout.

.PARAMETER ShowInfo
    Include informational findings in the text report.

.PARAMETER Inventory
    Append a table of every certificate with a private key or a binding to the text report.

.PARAMETER Version
    Print the version and exit.

.EXAMPLE
    ./cert-inventory.ps1 -ComputerListPath servers.txt

.EXAMPLE
    ./cert-inventory.ps1 web01, web02 -Credential (Get-Credential) -UseSSL -Json > report.json

.EXAMPLE
    ./cert-inventory.ps1 -CollectOnly -OutFile \\share\certs\$env:COMPUTERNAME.json
    ./cert-inventory.ps1 -InputPath \\share\certs -CsvPath inventory.csv

.NOTES
    Exit codes (Nagios/Icinga): 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (a
    host could not be audited, or usage error).
#>
[CmdletBinding(DefaultParameterSetName = 'Remote')]
param(
    [Parameter(ParameterSetName = 'Remote', Position = 0)]
    [string[]] $ComputerName,

    [Parameter(ParameterSetName = 'Remote')]
    [string] $ComputerListPath,

    [Parameter(ParameterSetName = 'Offline', Mandatory = $true)]
    [string[]] $InputPath,

    [Parameter(ParameterSetName = 'Remote')]
    [System.Management.Automation.PSCredential] $Credential,

    [Parameter(ParameterSetName = 'Remote')]
    [switch] $UseSSL,

    [Parameter(ParameterSetName = 'Remote')]
    [ValidateRange(1, 65535)] [int] $Port,

    [Parameter(ParameterSetName = 'Remote')]
    [ValidateSet('Default', 'Kerberos', 'Negotiate')] [string] $Authentication = 'Default',

    [Parameter(ParameterSetName = 'Remote')]
    [ValidateRange(1, 1024)] [int] $ThrottleLimit = 32,

    [Parameter(ParameterSetName = 'Remote')]
    [ValidateRange(5, 3600)] [int] $TimeoutSeconds = 60,

    [Parameter(ParameterSetName = 'Remote')]
    [string[]] $StoreName,

    [Parameter(ParameterSetName = 'Remote')]
    [switch] $SkipKeyInspection,

    [Parameter(ParameterSetName = 'Remote')]
    [switch] $CollectOnly,

    [ValidateRange(0, 3650)] [int] $WarningDays = 30,
    [ValidateRange(0, 3650)] [int] $CriticalDays = 14,
    [ValidateRange(512, 16384)] [int] $MinRsaKeySize = 2048,
    [string[]] $AllowExportable,
    [ValidateRange(0, 3650)] [int] $MaxCollectionAgeDays = 7,
    [switch] $Json,
    [string] $CsvPath,
    [string] $OutFile,
    [switch] $ShowInfo,
    [switch] $Inventory,
    [switch] $Version
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Write-Out {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [string] $Path)
    if ($Path) {
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Path), $Text + [Environment]::NewLine, $enc)
    }
    else {
        [Console]::Out.WriteLine($Text)
    }
}

try {
    Import-Module (Join-Path $PSScriptRoot 'src/CertInventory.psm1') -Force
    if ($Version) {
        [Console]::Out.WriteLine('cert-inventory ' + (Get-CertInventoryVersion))
        exit 0
    }
    if ($CriticalDays -gt $WarningDays) { throw '-CriticalDays must not be greater than -WarningDays' }

    $failures = @()
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        $hosts = @(Import-CertInventoryCollection -Path $InputPath)
        if ($hosts.Count -eq 0) { throw 'no collection found in -InputPath' }
        $maxAge = $MaxCollectionAgeDays
    }
    else {
        $targets = @()
        if ($ComputerName) { $targets += $ComputerName }
        if ($ComputerListPath) { $targets += @(Read-ComputerList -Path $ComputerListPath) }
        if ($targets.Count -eq 0) { $targets = @('localhost') }
        $stores = $StoreName
        if (-not $stores) { $stores = Get-CertInventoryDefaultStore }
        $collectParams = @{
            ComputerName      = $targets
            ThrottleLimit     = $ThrottleLimit
            TimeoutSeconds    = $TimeoutSeconds
            StoreName         = $stores
            SkipKeyInspection = $SkipKeyInspection
            Authentication    = $Authentication
        }
        if ($Credential) { $collectParams.Credential = $Credential }
        if ($UseSSL) { $collectParams.UseSSL = $true }
        if ($Port) { $collectParams.Port = $Port }
        $collection = Invoke-CertInventoryCollection @collectParams
        $hosts = @($collection.Hosts)
        $failures = @($collection.Failures)
        $maxAge = 0

        if ($CollectOnly) {
            foreach ($f in $failures) { [Console]::Error.WriteLine(('cert-inventory: {0}: {1}' -f $f.ComputerName, (ConvertTo-SafeText $f.Error))) }
            $clean = @($hosts | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName)
            if ($clean.Count -eq 1) { $text = ConvertTo-Json -InputObject $clean[0] -Depth 8 }
            else { $text = ConvertTo-Json -InputObject $clean -Depth 8 }
            Write-Out -Text $text -Path $OutFile
            if ($failures.Count -gt 0) { exit 3 }
            exit 0
        }
    }

    $report = New-CertInventoryReport -Hosts $hosts -Failures $failures -WarningDays $WarningDays -CriticalDays $CriticalDays -MinRsaKeySize $MinRsaKeySize -AllowExportable $AllowExportable -MaxCollectionAgeDays $maxAge

    if ($CsvPath) {
        $rows = @(ConvertTo-CertInventoryCsvRow -Report $report)
        $rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    }
    if ($Json) {
        Write-Out -Text (ConvertTo-CertInventoryJson -Report $report) -Path $OutFile
    }
    else {
        Write-Out -Text ((Format-CertInventoryText -Report $report -ShowInfo:$ShowInfo -Inventory:$Inventory) -join [Environment]::NewLine) -Path $OutFile
    }
    exit $report.ExitCode
}
catch {
    [Console]::Error.WriteLine('cert-inventory: ' + $_.Exception.Message)
    exit 3
}

#Requires -Version 5.1
<#
    cert-inventory analysis module: collection orchestration (WinRM or
    local), offline import, findings, fleet correlation and output.

    Everything here runs on the administration host. The code that runs on
    each audited host lives in Collector.ps1.
#>

Set-StrictMode -Version 3.0

$script:ToolVersion = '0.1.0'
$script:CollectorPath = Join-Path $PSScriptRoot 'Collector.ps1'
$script:DefaultStores = @('My', 'WebHosting', 'Remote Desktop', 'Root', 'CA', 'TrustedPeople', 'TrustedPublisher')
# Stores whose content is trust material rather than the host's own identities.
$script:TrustStores = @('Root', 'AuthRoot', 'CA', 'TrustedPeople', 'TrustedPublisher', 'Disallowed', 'TrustedDevices')
$script:FleetName = '(fleet)'
$script:SeverityRank = @{ critical = 4; unknown = 3; warning = 2; info = 1 }

function Get-CertInventoryVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:ToolVersion
}

function Get-CertInventoryDefaultStore {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return $script:DefaultStores
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function ConvertTo-UtcDate {
    <# Accepts the collector's ISO 8601 strings or DateTime values (ConvertFrom-Json converts them on PowerShell 7). #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([AllowNull()] $Value)
    if ($null -eq $Value -or ($Value -is [string] -and $Value -eq '')) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $formats = [string[]]@('yyyy-MM-ddTHH:mm:ssZ', 'yyyy-MM-ddTHH:mm:ss.FFFFFFFZ', 'o')
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$Value, $formats, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    throw "invalid date '$Value'"
}

function Format-UtcDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value, [switch] $DateOnly)
    if ($null -eq $Value) { return '' }
    $fmt = 'yyyy-MM-ddTHH:mm:ssZ'
    if ($DateOnly) { $fmt = 'yyyy-MM-dd' }
    return ([datetime]$Value).ToString($fmt, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-PropertyValue {
    <# Strict-mode safe property access for deserialised and JSON objects. #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

function ConvertTo-SafeText {
    <# Neutralises control characters (terminal escape sequences in certificate fields). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Text)
    if ($null -eq $Text) { return '' }
    return [regex]::Replace($Text, '[\x00-\x1F\x7F-\x9F]', { param($m) '\x{0:X2}' -f [int][char]$m.Value })
}

function ConvertTo-CsvSafeValue {
    <# Prevents spreadsheet formula injection from certificate fields. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return '' }
    $s = ConvertTo-SafeText -Text ([string]$Value)
    if ($s -match '^[=+\-@\t]') { return "'" + $s }
    return $s
}

function Test-LocalComputerName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)
    $n = $Name.Trim().ToLowerInvariant()
    if ($n -in @('.', 'localhost', '127.0.0.1', '::1')) { return $true }
    $machine = [System.Environment]::MachineName.ToLowerInvariant()
    if ($n -eq $machine) { return $true }
    try {
        $p = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if ($p.DomainName -and $n -eq ('{0}.{1}' -f $p.HostName, $p.DomainName).ToLowerInvariant()) { return $true }
    }
    catch { Write-Verbose 'local FQDN unavailable' }
    return $false
}

function Read-ComputerList {
    <# One host per line; blank lines and '#' comments ignored; CSV exports with a Name/ComputerName/DNSHostName column accepted. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "computer list not found: $Path" }
    $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    $header = $null
    foreach ($l in $lines) { if ($l.Trim() -and -not $l.Trim().StartsWith('#')) { $header = $l; break } }
    $names = @()
    if ($null -ne $header -and $header -match ',') {
        $rows = @($lines | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | ConvertFrom-Csv)
        $col = $null
        foreach ($c in @('DNSHostName', 'ComputerName', 'Name', 'Host', 'Hostname')) {
            if ($rows.Count -gt 0 -and $rows[0].PSObject.Properties[$c]) { $col = $c; break }
        }
        if (-not $col) { throw "computer list ${Path}: CSV without a DNSHostName, ComputerName, Name, Host or Hostname column" }
        $names = @($rows | ForEach-Object { [string]$_.$col })
    }
    else {
        $names = @($lines | ForEach-Object { ($_ -replace '#.*$', '').Trim() })
    }
    return @($names | Where-Object { $_ })
}

function Get-UniqueName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyCollection()] [string[]] $Name)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out = @()
    foreach ($n in $Name) {
        $t = $n.Trim()
        if ($t -and $seen.Add($t)) { $out += $t }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

function Get-ErrorTarget {
    <# Finds which computer an Invoke-Command error record belongs to. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $ErrorRecord, [string[]] $Candidates)
    $names = @()
    if ($ErrorRecord.PSObject.Properties['TargetObject'] -and $ErrorRecord.TargetObject -is [string]) { $names += $ErrorRecord.TargetObject }
    $origin = Get-PropertyValue -InputObject $ErrorRecord -Name 'OriginInfo'
    if ($origin) { $names += [string](Get-PropertyValue -InputObject $origin -Name 'PSComputerName') }
    $ci = Get-PropertyValue -InputObject $ErrorRecord -Name 'CategoryInfo'
    if ($ci) { $names += [string](Get-PropertyValue -InputObject $ci -Name 'TargetName') }
    foreach ($n in $names) {
        foreach ($c in $Candidates) { if ($n -and $c -ieq $n) { return $c } }
    }
    $msg = [string]$ErrorRecord
    foreach ($c in ($Candidates | Sort-Object Length -Descending)) {
        if ($msg -match ('(?i)(^|[^\w.-])' + [regex]::Escape($c) + '($|[^\w.-])')) { return $c }
    }
    return $null
}

function Test-WinRmSupported {
    <# WinRM remoting (and the WSMan session options) only exist in PowerShell on Windows. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function New-CollectorSessionOption {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no system state.')]
    param([Parameter(Mandatory)] [int] $TimeoutSeconds)
    $ms = $TimeoutSeconds * 1000
    return New-PSSessionOption -OpenTimeout $ms -OperationTimeout $ms -CancelTimeout 10000 -NoMachineProfile
}

function Invoke-CertInventoryCollection {
    <#
    .SYNOPSIS
        Runs the collector locally or over WinRM and returns @{ Hosts; Failures }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $ComputerName,
        [System.Management.Automation.PSCredential] $Credential,
        [switch] $UseSSL,
        [int] $Port,
        [ValidateSet('Default', 'Kerberos', 'Negotiate')] [string] $Authentication = 'Default',
        [ValidateRange(1, 1024)] [int] $ThrottleLimit = 32,
        [ValidateRange(5, 3600)] [int] $TimeoutSeconds = 60,
        [string[]] $StoreName = $script:DefaultStores,
        [switch] $SkipKeyInspection
    )
    $hosts = @()
    $failures = @()
    $targets = Get-UniqueName -Name $ComputerName
    $local = @($targets | Where-Object { Test-LocalComputerName -Name $_ })
    $remote = @($targets | Where-Object { -not (Test-LocalComputerName -Name $_) })
    $inspect = -not $SkipKeyInspection

    foreach ($t in $local) {
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            $failures += [pscustomobject]@{ ComputerName = $t; Error = 'local collection requires Windows' }
            continue
        }
        try {
            $r = & $script:CollectorPath -StoreName $StoreName -InspectKeys $inspect
            $r | Add-Member -NotePropertyName Target -NotePropertyValue $t -Force
            $hosts += $r
        }
        catch {
            $failures += [pscustomobject]@{ ComputerName = $t; Error = $_.Exception.Message }
        }
    }

    if ($remote.Count -gt 0) {
        if (-not (Test-WinRmSupported)) {
            foreach ($t in $remote) {
                $failures += [pscustomobject]@{ ComputerName = $t; Error = 'WinRM collection requires Windows; on Linux/macOS analyse collections saved with -CollectOnly (-InputPath)' }
            }
            return [pscustomobject]@{ Hosts = $hosts; Failures = $failures }
        }
        $sessionOption = New-CollectorSessionOption -TimeoutSeconds $TimeoutSeconds
        $argList = New-Object object[] 2
        $argList[0] = [string[]]$StoreName
        $argList[1] = [bool]$inspect
        $params = @{
            ComputerName  = $remote
            FilePath      = $script:CollectorPath
            ArgumentList  = $argList
            SessionOption = $sessionOption
            ThrottleLimit = $ThrottleLimit
            ErrorAction   = 'SilentlyContinue'
            ErrorVariable = 'remoteErrors'
        }
        if ($Credential) { $params.Credential = $Credential }
        if ($UseSSL) { $params.UseSSL = $true }
        if ($Port -gt 0) { $params.Port = $Port }
        if ($Authentication -ne 'Default') { $params.Authentication = $Authentication }

        $remoteErrors = @()
        $results = @(Invoke-Command @params)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $results) {
            if ($null -eq $r -or -not $r.PSObject.Properties['Certificates']) { continue }
            $target = [string](Get-PropertyValue -InputObject $r -Name 'PSComputerName')
            if (-not $target) { $target = [string]$r.ComputerName }
            if (-not $seen.Add($target)) { continue }
            $r | Add-Member -NotePropertyName Target -NotePropertyValue $target -Force
            $hosts += $r
        }
        $errorsByHost = @{}
        foreach ($e in @($remoteErrors)) {
            $t = Get-ErrorTarget -ErrorRecord $e -Candidates $remote
            if (-not $t) { $t = '(unknown host)' }
            if (-not $errorsByHost.ContainsKey($t)) { $errorsByHost[$t] = @() }
            $errorsByHost[$t] += (([string]$e) -replace '\s+', ' ').Trim()
        }
        foreach ($t in $remote) {
            if ($seen.Contains($t)) { continue }
            $msg = 'no data returned'
            if ($errorsByHost.ContainsKey($t)) { $msg = ($errorsByHost[$t] | Select-Object -Unique) -join ' | ' }
            $failures += [pscustomobject]@{ ComputerName = $t; Error = $msg }
        }
        if ($errorsByHost.ContainsKey('(unknown host)')) {
            Write-Warning ('unattributed remoting errors: ' + ($errorsByHost['(unknown host)'] -join ' | '))
        }
    }
    return [pscustomobject]@{ Hosts = $hosts; Failures = $failures }
}

function Import-CertInventoryCollection {
    <#
    .SYNOPSIS
        Loads collections saved with -CollectOnly (one host object or an array per file).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Path)
    $hosts = @()
    $files = @()
    foreach ($p in $Path) {
        $resolved = @(Resolve-Path -Path $p -ErrorAction Stop)
        foreach ($r in $resolved) {
            if (Test-Path -LiteralPath $r.ProviderPath -PathType Container) {
                $files += @(Get-ChildItem -LiteralPath $r.ProviderPath -Filter '*.json' -File | ForEach-Object FullName)
            }
            else { $files += $r.ProviderPath }
        }
    }
    foreach ($f in $files) {
        $text = Get-Content -LiteralPath $f -Raw -Encoding UTF8 -ErrorAction Stop
        try { $data = $text | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "${f}: invalid JSON: $($_.Exception.Message)" }
        foreach ($h in @($data)) {
            if ($null -eq $h -or -not $h.PSObject.Properties['Certificates'] -or -not $h.PSObject.Properties['ComputerName']) {
                throw "${f}: not a cert-inventory collection (missing ComputerName/Certificates)"
            }
            $target = [string](Get-PropertyValue -InputObject $h -Name 'Target')
            if (-not $target) { $target = [string](Get-PropertyValue -InputObject $h -Name 'Fqdn') }
            if (-not $target) { $target = [string]$h.ComputerName }
            $h | Add-Member -NotePropertyName Target -NotePropertyValue $target -Force
            $h | Add-Member -NotePropertyName SourceFile -NotePropertyValue $f -Force
            $hosts += $h
        }
    }
    return $hosts
}

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

function New-Finding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no system state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [ValidateSet('critical', 'warning', 'unknown', 'info')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [string] $Message,
        $Certificate = $null
    )
    $store = $null; $tp = $null; $subject = $null; $notAfter = $null
    if ($Certificate) {
        $store = $Certificate.Store; $tp = $Certificate.Thumbprint; $subject = $Certificate.Subject
        $notAfter = $Certificate.NotAfter
    }
    return [pscustomobject][ordered]@{
        ComputerName = $ComputerName
        Severity     = $Severity
        Code         = $Code
        Store        = $store
        Thumbprint   = $tp
        Subject      = $subject
        NotAfter     = $notAfter
        Message      = $Message
    }
}

function Test-WildcardMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [string[]] $Value, [AllowNull()] [string[]] $Pattern)
    if (-not $Pattern) { return $false }
    foreach ($v in $Value) {
        if (-not $v) { continue }
        foreach ($p in $Pattern) { if ($v -like $p) { return $true } }
    }
    return $false
}

function Get-NormalizedCertificate {
    <# Adds parsed dates and binding information to the collected records of one host. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $HostData, [Parameter(Mandatory)] [datetime] $Now)
    $bindings = @(Get-PropertyValue -InputObject $HostData -Name 'Bindings' -Default @())
    $byThumb = @{}
    foreach ($b in $bindings) {
        $tp = [string](Get-PropertyValue -InputObject $b -Name 'Thumbprint')
        if (-not $tp) { continue }
        $tp = $tp.ToUpperInvariant()
        if (-not $byThumb.ContainsKey($tp)) { $byThumb[$tp] = @() }
        $byThumb[$tp] += ('{0} {1}' -f $b.Service, $b.Endpoint)
    }
    $out = @()
    foreach ($c in @(Get-PropertyValue -InputObject $HostData -Name 'Certificates' -Default @())) {
        if ($null -eq $c) { continue }
        $tp = ([string]$c.Thumbprint).ToUpperInvariant()
        $notAfter = ConvertTo-UtcDate $c.NotAfter
        $notBefore = ConvertTo-UtcDate $c.NotBefore
        $bound = @()
        if ($byThumb.ContainsKey($tp)) { $bound = $byThumb[$tp] }
        $isTrust = $script:TrustStores -contains [string]$c.Store
        $o = [ordered]@{}
        foreach ($p in $c.PSObject.Properties) {
            if ($p.Name -in @('PSComputerName', 'RunspaceId', 'PSShowComputerName')) { continue }
            $o[$p.Name] = $p.Value
        }
        $o.Thumbprint = $tp
        $o.NotAfter = $notAfter
        $o.NotBefore = $notBefore
        $o.DaysLeft = [int][math]::Floor(($notAfter - $Now).TotalDays)
        $o.BoundTo = $bound
        $o.IsTrustStore = $isTrust
        foreach ($k in @('DnsNames', 'IPAddresses', 'Upns', 'Eku', 'ParseErrors')) {
            if (-not $o.Contains($k) -or $null -eq $o[$k]) { $o[$k] = @() } else { $o[$k] = @($o[$k]) }
        }
        foreach ($k in @('HasPrivateKey', 'KeyExportable', 'KeyPlaintextExport', 'KeyError', 'KeyStorage', 'KeyProvider', 'KeySize', 'KeyAlgorithm', 'SignatureAlgorithm', 'SelfIssued', 'TemplateName', 'TemplateOid', 'IsCA')) {
            if (-not $o.Contains($k)) { $o[$k] = $null }
        }
        $out += [pscustomobject]$o
    }
    return $out
}

function Find-Successor {
    <# A renewed certificate: same store, same subject (and template when known), with a private key, valid now and lasting longer. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Certificate, [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $All, [Parameter(Mandatory)] [datetime] $Now)
    foreach ($o in $All) {
        if ($o.Thumbprint -eq $Certificate.Thumbprint) { continue }
        if ($o.Store -ne $Certificate.Store -or $o.Subject -ne $Certificate.Subject) { continue }
        if (-not $o.HasPrivateKey) { continue }
        if ($Certificate.TemplateOid -and $o.TemplateOid -and $o.TemplateOid -ne $Certificate.TemplateOid) { continue }
        if ($o.NotAfter -le $Certificate.NotAfter -or $o.NotAfter -le $Now -or $o.NotBefore -gt $Now) { continue }
        return $o
    }
    return $null
}

function Get-HostFinding {
    <#
    .SYNOPSIS
        Findings for one collected host. Certificates must come from Get-NormalizedCertificate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $HostData,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Certificates,
        [Parameter(Mandatory)] [datetime] $Now,
        [int] $WarningDays = 30,
        [int] $CriticalDays = 14,
        [int] $MinRsaKeySize = 2048,
        [string[]] $AllowExportable,
        [int] $MaxCollectionAgeDays = 0
    )
    $name = [string]$HostData.Target
    $f = @()

    foreach ($e in @(Get-PropertyValue -InputObject $HostData -Name 'Errors' -Default @())) {
        if ($e) { $f += New-Finding -ComputerName $name -Severity warning -Code 'COLLECTION_PARTIAL' -Message ([string]$e) }
    }
    if ($MaxCollectionAgeDays -gt 0) {
        $collected = ConvertTo-UtcDate (Get-PropertyValue -InputObject $HostData -Name 'CollectedAt')
        if ($collected -and ($Now - $collected).TotalDays -gt $MaxCollectionAgeDays) {
            $f += New-Finding -ComputerName $name -Severity warning -Code 'STALE_COLLECTION' -Message ('collection is {0} days old (collected {1})' -f [int]($Now - $collected).TotalDays, (Format-UtcDate $collected))
        }
    }

    $trustExpired = @{}
    foreach ($c in $Certificates) {
        if ($c.IsTrustStore -and $c.BoundTo.Count -eq 0 -and -not $c.HasPrivateKey) {
            if ($c.NotAfter -le $Now) {
                if (-not $trustExpired.ContainsKey($c.Store)) { $trustExpired[$c.Store] = 0 }
                $trustExpired[$c.Store]++
            }
            continue
        }
        if (-not $c.HasPrivateKey -and $c.BoundTo.Count -eq 0) {
            # A public certificate outside the trust stores (e.g. a partner certificate in My): expiry only.
            if ($c.NotAfter -le $Now) {
                $f += New-Finding -ComputerName $name -Severity info -Code 'EXPIRED_NO_KEY' -Certificate $c -Message ('expired {0} (no private key, not bound)' -f (Format-UtcDate $c.NotAfter -DateOnly))
            }
            continue
        }

        $bound = $c.BoundTo.Count -gt 0
        $boundText = ''
        if ($bound) { $boundText = ', bound to ' + ($c.BoundTo -join ', ') }
        $succ = Find-Successor -Certificate $c -All $Certificates -Now $Now
        $expired = $c.NotAfter -le $Now

        if ($expired) {
            if ($bound) {
                $code = 'EXPIRED_BOUND'
                $msg = 'expired {0}{1}' -f (Format-UtcDate $c.NotAfter -DateOnly), $boundText
                if ($succ) { $msg += "; renewed certificate $($succ.Thumbprint) is not bound" }
                $f += New-Finding -ComputerName $name -Severity critical -Code $code -Certificate $c -Message $msg
            }
            elseif ($succ) {
                $f += New-Finding -ComputerName $name -Severity info -Code 'SUPERSEDED' -Certificate $c -Message ('expired {0}, superseded by {1} (clean-up candidate)' -f (Format-UtcDate $c.NotAfter -DateOnly), $succ.Thumbprint)
            }
            else {
                $f += New-Finding -ComputerName $name -Severity warning -Code 'EXPIRED' -Certificate $c -Message ('expired {0} with no renewed certificate in {1}' -f (Format-UtcDate $c.NotAfter -DateOnly), $c.Store)
            }
            continue
        }

        if ($c.NotBefore -gt $Now) {
            $sev = 'info'
            if ($bound) { $sev = 'warning' }
            $f += New-Finding -ComputerName $name -Severity $sev -Code 'NOT_YET_VALID' -Certificate $c -Message ('valid from {0}{1}' -f (Format-UtcDate $c.NotBefore), $boundText)
        }

        if ($c.DaysLeft -le $WarningDays) {
            $sev = 'warning'
            if ($c.DaysLeft -le $CriticalDays) { $sev = 'critical' }
            $when = 'expires in {0} day(s) ({1})' -f $c.DaysLeft, (Format-UtcDate $c.NotAfter -DateOnly)
            if ($succ -and $bound) {
                $f += New-Finding -ComputerName $name -Severity $sev -Code 'RENEWED_NOT_REBOUND' -Certificate $c -Message ("$when$boundText; renewed certificate $($succ.Thumbprint) is not bound")
            }
            elseif ($succ) {
                $f += New-Finding -ComputerName $name -Severity info -Code 'RENEWED' -Certificate $c -Message ("$when; renewed as $($succ.Thumbprint)")
            }
            else {
                $f += New-Finding -ComputerName $name -Severity $sev -Code 'EXPIRING' -Certificate $c -Message ("$when$boundText")
            }
        }

        # Key and signature strength.
        $alg = [string]$c.KeyAlgorithm
        $size = $c.KeySize
        if ($alg -eq 'DSA') {
            $f += New-Finding -ComputerName $name -Severity warning -Code 'WEAK_KEY' -Certificate $c -Message 'DSA key (deprecated, not supported by TLS 1.3)'
        }
        elseif ($alg -eq 'RSA' -and $null -ne $size -and [int]$size -lt $MinRsaKeySize) {
            $sev = 'warning'
            if ($bound -or [int]$size -lt 1024) { $sev = 'critical' }
            $f += New-Finding -ComputerName $name -Severity $sev -Code 'WEAK_KEY' -Certificate $c -Message ("RSA $size bits (< $MinRsaKeySize)$boundText")
        }
        elseif ($alg -eq 'ECC' -and $null -ne $size -and [int]$size -lt 256) {
            $f += New-Finding -ComputerName $name -Severity warning -Code 'WEAK_KEY' -Certificate $c -Message ("ECC $size bits (< 256)")
        }
        if (-not $c.SelfIssued -and ([string]$c.SignatureAlgorithm) -match '^(md2|md5|sha1)') {
            $f += New-Finding -ComputerName $name -Severity warning -Code 'WEAK_SIGNATURE' -Certificate $c -Message ("signed with $($c.SignatureAlgorithm)$boundText")
        }

        # Private key protection.
        if ($c.HasPrivateKey -and $c.KeyExportable -eq $true) {
            $what = 'private key is exportable'
            if ($c.KeyPlaintextExport -eq $true) { $what = 'private key is exportable in plaintext' }
            if ($c.KeyProvider) { $what += " ($($c.KeyProvider))" }
            $sev = 'warning'
            if (Test-WildcardMatch -Value @($c.TemplateName, $c.TemplateOid, $c.Subject, $c.Thumbprint) -Pattern $AllowExportable) {
                $sev = 'info'; $what += ', allowed by -AllowExportable'
            }
            $f += New-Finding -ComputerName $name -Severity $sev -Code 'EXPORTABLE_KEY' -Certificate $c -Message $what
        }
        if ($c.HasPrivateKey -and $c.KeyError -and $c.KeyError -ne 'skipped') {
            $f += New-Finding -ComputerName $name -Severity info -Code 'KEY_UNREADABLE' -Certificate $c -Message ("private key export policy not readable: $($c.KeyError)")
        }

        # Server certificates without SubjectAltName are rejected by modern clients.
        $serverAuth = @($c.Eku | Where-Object { $_ -and (Get-PropertyValue -InputObject $_ -Name 'Oid') -eq '1.3.6.1.5.5.7.3.1' }).Count -gt 0
        $httpBound = @($c.BoundTo | Where-Object { $_ -like 'http.sys *' -or $_ -like 'winrm *' }).Count -gt 0
        if (($serverAuth -or $httpBound) -and $c.DnsNames.Count -eq 0 -and $c.IPAddresses.Count -eq 0) {
            $sev = 'info'
            if ($httpBound) { $sev = 'warning' }
            $f += New-Finding -ComputerName $name -Severity $sev -Code 'NO_SAN' -Certificate $c -Message ("server certificate without SubjectAltName (clients ignore the CN)$boundText")
        }
        if ($httpBound -and $c.SelfIssued) {
            $f += New-Finding -ComputerName $name -Severity info -Code 'SELF_SIGNED_BOUND' -Certificate $c -Message ("self-signed certificate$boundText")
        }
    }

    foreach ($s in ($trustExpired.Keys | Sort-Object)) {
        $f += New-Finding -ComputerName $name -Severity info -Code 'TRUST_EXPIRED' -Message ("{0} expired certificate(s) in the {1} store" -f $trustExpired[$s], $s)
    }

    # Bindings that point to nothing usable.
    $byThumb = @{}
    foreach ($c in $Certificates) { $byThumb[$c.Thumbprint] = $c }
    $collectedStores = @(Get-PropertyValue -InputObject $HostData -Name 'Stores' -Default $script:DefaultStores)
    foreach ($b in @(Get-PropertyValue -InputObject $HostData -Name 'Bindings' -Default @())) {
        $tp = [string](Get-PropertyValue -InputObject $b -Name 'Thumbprint')
        if (-not $tp) { continue }
        $tp = $tp.ToUpperInvariant()
        $label = '{0} {1}' -f $b.Service, $b.Endpoint
        if (-not $byThumb.ContainsKey($tp)) {
            $bStore = [string](Get-PropertyValue -InputObject $b -Name 'Store')
            $storeCollected = (-not $bStore) -or (@($collectedStores | Where-Object { $_ -ieq $bStore }).Count -gt 0)
            if ($storeCollected) {
                $f += New-Finding -ComputerName $name -Severity critical -Code 'BINDING_CERT_MISSING' -Message ("$label references certificate $tp, which is not in the $bStore store")
            }
            else {
                $f += New-Finding -ComputerName $name -Severity info -Code 'BINDING_NOT_CHECKED' -Message ("$label uses certificate $tp from store '$bStore', which was not collected")
            }
        }
        elseif (-not $byThumb[$tp].HasPrivateKey) {
            $f += New-Finding -ComputerName $name -Severity critical -Code 'BINDING_NO_PRIVATE_KEY' -Certificate $byThumb[$tp] -Message ("$label uses a certificate without a private key")
        }
    }
    return $f
}

function Get-FleetFinding {
    <# Cross-host correlation: the same certificate (and therefore the same private key) on several hosts. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $HostReports, [int] $MinHosts = 2)
    $map = @{}
    foreach ($h in $HostReports) {
        foreach ($c in $h.Certificates) {
            if (-not $c.HasPrivateKey -or $c.IsTrustStore) { continue }
            if (-not $map.ContainsKey($c.Thumbprint)) { $map[$c.Thumbprint] = @{ Cert = $c; Hosts = @(); Exportable = $false } }
            if ($map[$c.Thumbprint].Hosts -notcontains $h.ComputerName) { $map[$c.Thumbprint].Hosts += $h.ComputerName }
            if ($c.KeyExportable -eq $true) { $map[$c.Thumbprint].Exportable = $true }
        }
    }
    $out = @()
    foreach ($tp in ($map.Keys | Sort-Object)) {
        $e = $map[$tp]
        if ($e.Hosts.Count -lt $MinHosts) { continue }
        $msg = 'same certificate and private key on {0} hosts: {1}' -f $e.Hosts.Count, (($e.Hosts | Sort-Object) -join ', ')
        if ($e.Exportable) { $msg += ' (exportable on at least one host)' }
        $out += New-Finding -ComputerName $script:FleetName -Severity info -Code 'SHARED_KEY' -Certificate $e.Cert -Message $msg
    }
    return $out
}

function Get-ReportExitCode {
    <# Nagios semantics: CRITICAL 2 > UNKNOWN 3 (a host could not be audited) > WARNING 1 > OK 0. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowEmptyCollection()] [object[]] $Findings, [int] $FailedHosts = 0)
    $sev = @($Findings | ForEach-Object { $_.Severity })
    if ($sev -contains 'critical') { return 2 }
    if ($FailedHosts -gt 0 -or $sev -contains 'unknown') { return 3 }
    if ($sev -contains 'warning') { return 1 }
    return 0
}

function New-CertInventoryReport {
    <#
    .SYNOPSIS
        Builds the full report (hosts, certificates, findings, summary, exit code).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no system state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Hosts,
        [AllowEmptyCollection()] [object[]] $Failures = @(),
        [datetime] $Now = [datetime]::UtcNow,
        [ValidateRange(0, 3650)] [int] $WarningDays = 30,
        [ValidateRange(0, 3650)] [int] $CriticalDays = 14,
        [ValidateRange(512, 16384)] [int] $MinRsaKeySize = 2048,
        [string[]] $AllowExportable,
        [int] $MaxCollectionAgeDays = 0
    )
    if ($CriticalDays -gt $WarningDays) { throw '-CriticalDays must not be greater than -WarningDays' }
    $Now = $Now.ToUniversalTime()
    $hostReports = @()
    $findings = @()
    foreach ($h in $Hosts) {
        $certs = @(Get-NormalizedCertificate -HostData $h -Now $Now)
        $hf = @(Get-HostFinding -HostData $h -Certificates $certs -Now $Now -WarningDays $WarningDays -CriticalDays $CriticalDays -MinRsaKeySize $MinRsaKeySize -AllowExportable $AllowExportable -MaxCollectionAgeDays $MaxCollectionAgeDays)
        $findings += $hf
        $hostReports += [pscustomobject][ordered]@{
            ComputerName     = [string]$h.Target
            NetBiosName      = [string](Get-PropertyValue -InputObject $h -Name 'ComputerName')
            Fqdn             = [string](Get-PropertyValue -InputObject $h -Name 'Fqdn')
            OS               = [string](Get-PropertyValue -InputObject $h -Name 'OS')
            PSVersion        = [string](Get-PropertyValue -InputObject $h -Name 'PSVersion')
            CollectedAt      = ConvertTo-UtcDate (Get-PropertyValue -InputObject $h -Name 'CollectedAt')
            CollectorVersion = [string](Get-PropertyValue -InputObject $h -Name 'CollectorVersion')
            Bindings         = @(Get-PropertyValue -InputObject $h -Name 'Bindings' -Default @())
            Certificates     = $certs
        }
    }
    foreach ($x in $Failures) {
        $findings += New-Finding -ComputerName ([string]$x.ComputerName) -Severity unknown -Code 'HOST_FAILED' -Message ([string]$x.Error)
    }
    $findings += @(Get-FleetFinding -HostReports $hostReports)
    $findings = @($findings | Sort-Object -Property @{ Expression = { $script:SeverityRank[$_.Severity] }; Descending = $true }, ComputerName, Code, Subject)

    $count = @{ critical = 0; warning = 0; unknown = 0; info = 0 }
    foreach ($x in $findings) { $count[$x.Severity]++ }
    $templates = @{}
    foreach ($hr in $hostReports) {
        foreach ($c in $hr.Certificates) {
            if (-not $c.TemplateOid -and -not $c.TemplateName) { continue }
            $key = [string]$c.TemplateName
            if (-not $key) { $key = [string]$c.TemplateOid }
            if (-not $templates.ContainsKey($key)) { $templates[$key] = 0 }
            $templates[$key]++
        }
    }
    $templateList = @($templates.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Template = $_; Count = $templates[$_] } })
    $certCount = 0
    foreach ($hr in $hostReports) { $certCount += $hr.Certificates.Count }
    $exit = Get-ReportExitCode -Findings $findings -FailedHosts @($Failures).Count

    return [pscustomobject][ordered]@{
        Tool        = 'cert-inventory'
        Version     = $script:ToolVersion
        GeneratedAt = $Now
        Parameters  = [pscustomobject]@{ WarningDays = $WarningDays; CriticalDays = $CriticalDays; MinRsaKeySize = $MinRsaKeySize; AllowExportable = @($AllowExportable | Where-Object { $_ }) }
        Summary     = [pscustomobject][ordered]@{
            Hosts        = $hostReports.Count + @($Failures).Count
            FailedHosts  = @($Failures).Count
            Certificates = $certCount
            Critical     = $count.critical
            Warning      = $count.warning
            Unknown      = $count.unknown
            Info         = $count.info
            Templates    = $templateList
        }
        Status      = @('OK', 'WARNING', 'CRITICAL', 'UNKNOWN')[$exit]
        ExitCode    = $exit
        Findings    = $findings
        Hosts       = $hostReports
    }
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

function ConvertTo-CertInventoryJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Report)
    # Dates as ISO 8601 UTC strings, independent of the PowerShell version.
    return (ConvertTo-PlainObject -InputObject $Report | ConvertTo-Json -Depth 12)
}

function ConvertTo-PlainObject {
    <# Recursively converts dates to ISO strings so JSON output is stable across PowerShell 5.1 and 7. #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [datetime]) { return (Format-UtcDate $InputObject.ToUniversalTime()) }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $h[[string]$k] = ConvertTo-PlainObject -InputObject $InputObject[$k] }
        return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $InputObject) { $list.Add((ConvertTo-PlainObject -InputObject $i)) }
        return , $list.ToArray()
    }
    $o = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) {
        if ($p.MemberType -notin @('NoteProperty', 'Property')) { continue }
        $o[$p.Name] = ConvertTo-PlainObject -InputObject $p.Value
    }
    return $o
}

function ConvertTo-CertInventoryCsvRow {
    <# One row per certificate per host, for spreadsheets and CMDB imports. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report)
    $codes = @{}
    foreach ($x in $Report.Findings) {
        if (-not $x.Thumbprint) { continue }
        $k = '{0}|{1}|{2}' -f $x.ComputerName, $x.Store, $x.Thumbprint
        if (-not $codes.ContainsKey($k)) { $codes[$k] = @() }
        $codes[$k] += $x.Code
    }
    foreach ($h in $Report.Hosts) {
        foreach ($c in $h.Certificates) {
            $k = '{0}|{1}|{2}' -f $h.ComputerName, $c.Store, $c.Thumbprint
            $fc = @()
            if ($codes.ContainsKey($k)) { $fc = $codes[$k] }
            [pscustomobject][ordered]@{
                ComputerName       = ConvertTo-CsvSafeValue $h.ComputerName
                Store              = ConvertTo-CsvSafeValue $c.Store
                Subject            = ConvertTo-CsvSafeValue $c.Subject
                Issuer             = ConvertTo-CsvSafeValue $c.Issuer
                Thumbprint         = $c.Thumbprint
                SerialNumber       = ConvertTo-CsvSafeValue $c.SerialNumber
                NotBefore          = Format-UtcDate $c.NotBefore
                NotAfter           = Format-UtcDate $c.NotAfter
                DaysLeft           = $c.DaysLeft
                DnsNames           = ConvertTo-CsvSafeValue (@($c.DnsNames) -join ';')
                TemplateName       = ConvertTo-CsvSafeValue $c.TemplateName
                TemplateOid        = $c.TemplateOid
                KeyAlgorithm       = $c.KeyAlgorithm
                KeySize            = $c.KeySize
                SignatureAlgorithm = $c.SignatureAlgorithm
                HasPrivateKey      = $c.HasPrivateKey
                KeyExportable      = $c.KeyExportable
                KeyStorage         = $c.KeyStorage
                KeyProvider        = ConvertTo-CsvSafeValue $c.KeyProvider
                BoundTo            = ConvertTo-CsvSafeValue (@($c.BoundTo) -join ';')
                Findings           = (@($fc | Select-Object -Unique) -join ';')
            }
        }
    }
}

function Format-CertInventoryText {
    <#
    .SYNOPSIS
        Human-readable report as an array of lines.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] $Report,
        [switch] $ShowInfo,
        [switch] $Inventory
    )
    $s = $Report.Summary
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('cert-inventory {0}: {1} - {2} host(s), {3} failed, {4} certificate(s); {5} critical, {6} warning, {7} unknown, {8} info' -f
            $Report.Version, $Report.Status, $s.Hosts, $s.FailedHosts, $s.Certificates, $s.Critical, $s.Warning, $s.Unknown, $s.Info))

    $visible = @($Report.Findings | Where-Object { $ShowInfo -or $_.Severity -ne 'info' })
    $hidden = @($Report.Findings).Count - $visible.Count
    # Hosts with the most severe findings first, fleet-wide findings last.
    $groups = @($visible | Group-Object -Property ComputerName | Sort-Object -Property @(
            @{ Expression = { $_.Name -eq $script:FleetName } },
            @{ Expression = { ($_.Group | ForEach-Object { $script:SeverityRank[$_.Severity] } | Measure-Object -Maximum).Maximum }; Descending = $true },
            @{ Expression = { $_.Name } }))
    foreach ($g in $groups) {
        $lines.Add('')
        $hr = @($Report.Hosts | Where-Object { $_.ComputerName -eq $g.Name } | Select-Object -First 1)
        $head = ConvertTo-SafeText $g.Name
        if ($hr.Count -gt 0 -and $hr[0].OS) { $head += ('  ({0}, collected {1})' -f (ConvertTo-SafeText $hr[0].OS), (Format-UtcDate $hr[0].CollectedAt)) }
        $lines.Add($head)
        foreach ($x in $g.Group) {
            $where = ''
            if ($x.Store) { $where = ('[{0}] {1} ' -f $x.Store, (ConvertTo-SafeText $x.Subject)) }
            if ($x.Thumbprint) { $where += ('{0}  ' -f $x.Thumbprint.Substring(0, [math]::Min(12, $x.Thumbprint.Length))) }
            $lines.Add(('  {0,-8} {1,-22} {2}{3}' -f $x.Severity.ToUpperInvariant(), $x.Code, $where, (ConvertTo-SafeText $x.Message)))
        }
    }
    if ($visible.Count -eq 0) {
        $lines.Add('')
        $lines.Add('No findings.')
    }
    if ($hidden -gt 0) {
        $lines.Add('')
        $lines.Add(('{0} informational finding(s) hidden; use -ShowInfo to list them.' -f $hidden))
    }
    if ($s.Templates.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Certificates per ADCS template:')
        foreach ($t in $s.Templates) { $lines.Add(('  {0,6}  {1}' -f $t.Count, (ConvertTo-SafeText $t.Template))) }
    }
    if ($Inventory) {
        $lines.Add('')
        $lines.Add(('{0,-24} {1,-14} {2,6} {3,-10} {4,-5} {5,-12} {6}' -f 'HOST', 'STORE', 'DAYS', 'KEY', 'EXP', 'TEMPLATE', 'SUBJECT'))
        foreach ($h in $Report.Hosts) {
            foreach ($c in ($h.Certificates | Where-Object { $_.HasPrivateKey -or $_.BoundTo.Count -gt 0 } | Sort-Object NotAfter)) {
                $key = '{0}{1}' -f $c.KeyAlgorithm, $c.KeySize
                $exp = '-'
                if ($c.KeyExportable -eq $true) { $exp = 'yes' } elseif ($c.KeyExportable -eq $false) { $exp = 'no' }
                $tpl = [string]$c.TemplateName
                if (-not $tpl) { $tpl = [string]$c.TemplateOid }
                if (-not $tpl) { $tpl = '-' }
                $lines.Add(('{0,-24} {1,-14} {2,6} {3,-10} {4,-5} {5,-12} {6}' -f (ConvertTo-SafeText $h.ComputerName), $c.Store, $c.DaysLeft, $key, $exp, (ConvertTo-SafeText $tpl), (ConvertTo-SafeText $c.Subject)))
            }
        }
    }
    return , $lines.ToArray()
}

Export-ModuleMember -Function @(
    'Get-CertInventoryVersion', 'Get-CertInventoryDefaultStore', 'Read-ComputerList', 'Test-LocalComputerName',
    'Invoke-CertInventoryCollection', 'Import-CertInventoryCollection', 'New-CertInventoryReport',
    'ConvertTo-CertInventoryJson', 'ConvertTo-CertInventoryCsvRow', 'Format-CertInventoryText',
    'Get-ErrorTarget', 'ConvertTo-UtcDate', 'ConvertTo-SafeText', 'ConvertTo-CsvSafeValue', 'Get-ReportExitCode'
)

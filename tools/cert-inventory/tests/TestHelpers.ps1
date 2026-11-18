# Shared helpers for the cert-inventory Pester tests (dot-sourced in BeforeAll).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixtures build in-memory objects only.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stand-in cmdlet signatures for mocking.')]
param()

# Pester can only mock commands that exist: provide stand-ins for the
# Windows-only cmdlets when the tests run on Linux or macOS.
if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
    function global:Get-CimInstance {
        [CmdletBinding()]
        param([string] $Namespace, [string] $ClassName, [string] $Filter)
        throw 'Get-CimInstance is not available on this platform'
    }
}

function New-TestCertificate {
    <# Builds a real self-signed X509Certificate2 with optional extensions (works on Linux, macOS and Windows). #>
    [CmdletBinding()]
    param(
        [string] $Subject = 'CN=test.example.com',
        [ValidateSet('RSA', 'ECC')] [string] $KeyType = 'RSA',
        [int] $KeySize = 2048,
        [string[]] $DnsName,
        [string[]] $IPAddress,
        [string[]] $Upn,
        [string[]] $Eku,
        [byte[]] $TemplateV2Der,
        [byte[]] $TemplateV1Der,
        [switch] $CA,
        [int] $DaysBefore = 1,
        [int] $DaysAfter = 365
    )
    $X = 'System.Security.Cryptography.X509Certificates'
    if ($KeyType -eq 'RSA') {
        $key = [System.Security.Cryptography.RSA]::Create($KeySize)
        $req = New-Object "$X.CertificateRequest" $Subject, $key, ([System.Security.Cryptography.HashAlgorithmName]::SHA256), ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    else {
        $curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
        if ($KeySize -eq 384) { $curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP384 }
        $key = [System.Security.Cryptography.ECDsa]::Create($curve)
        $req = New-Object "$X.CertificateRequest" $Subject, $key, ([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    if ($DnsName -or $IPAddress -or $Upn) {
        $b = New-Object "$X.SubjectAlternativeNameBuilder"
        foreach ($d in $DnsName) { $b.AddDnsName($d) }
        foreach ($i in $IPAddress) { $b.AddIpAddress([System.Net.IPAddress]::Parse($i)) }
        foreach ($u in $Upn) { $b.AddUserPrincipalName($u) }
        $req.CertificateExtensions.Add($b.Build())
    }
    if ($Eku) {
        $oc = New-Object System.Security.Cryptography.OidCollection
        foreach ($e in $Eku) { [void]$oc.Add((New-Object System.Security.Cryptography.Oid $e)) }
        $req.CertificateExtensions.Add((New-Object "$X.X509EnhancedKeyUsageExtension" $oc, $false))
    }
    if ($CA) {
        $req.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" $true, $true, 1, $true))
    }
    if ($TemplateV2Der) {
        $req.CertificateExtensions.Add((New-Object "$X.X509Extension" '1.3.6.1.4.1.311.21.7', $TemplateV2Der, $false))
    }
    if ($TemplateV1Der) {
        $req.CertificateExtensions.Add((New-Object "$X.X509Extension" '1.3.6.1.4.1.311.20.2', $TemplateV1Der, $false))
    }
    $nb = [System.DateTimeOffset]::UtcNow.AddDays(-$DaysBefore)
    $na = [System.DateTimeOffset]::UtcNow.AddDays($DaysAfter)
    return $req.CreateSelfSigned($nb, $na)
}

function ConvertTo-TestDerOid {
    <# Minimal OID encoder for building test extensions. #>
    param([string] $Oid)
    $arcs = $Oid.Split('.') | ForEach-Object { [long]$_ }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte](40 * $arcs[0] + $arcs[1]))
    for ($i = 2; $i -lt $arcs.Count; $i++) {
        $v = $arcs[$i]
        $chunk = New-Object System.Collections.Generic.List[byte]
        $chunk.Insert(0, [byte]($v -band 0x7F))
        $v = [math]::Floor($v / 128)
        while ($v -gt 0) { $chunk.Insert(0, [byte](($v -band 0x7F) -bor 0x80)); $v = [math]::Floor($v / 128) }
        $bytes.AddRange($chunk)
    }
    return , ([byte[]](@(0x06, $bytes.Count) + $bytes.ToArray()))
}

function New-TestTemplateV2Der {
    param([string] $Oid, [int] $Major = 100, [int] $Minor = 4)
    $body = [byte[]]((ConvertTo-TestDerOid $Oid) + @(0x02, 0x01, $Major, 0x02, 0x01, $Minor))
    return , ([byte[]](@(0x30, $body.Length) + $body))
}

function New-TestTemplateV1Der {
    param([string] $Name)
    $b = [System.Text.Encoding]::BigEndianUnicode.GetBytes($Name)
    return , ([byte[]](@(0x1E, $b.Length) + $b))
}

function New-TestRecord {
    <# A collected certificate record as produced by Collector.ps1 (dates relative to now). #>
    param([hashtable] $Override = @{})
    $now = [datetime]::UtcNow
    $r = [ordered]@{
        Store              = 'My'
        Thumbprint         = ([guid]::NewGuid().ToString('N') + '00000000').Substring(0, 40).ToUpperInvariant()
        Subject            = 'CN=web01.corp.example.com'
        Issuer             = 'CN=Corp Issuing CA 1, DC=corp, DC=example, DC=com'
        SerialNumber       = '6100000012AB'
        FriendlyName       = ''
        NotBefore          = $now.AddDays(-300).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        NotAfter           = $now.AddDays(200).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        SelfIssued         = $false
        IsCA               = $false
        PathLength         = $null
        DnsNames           = @('web01.corp.example.com')
        IPAddresses        = @()
        Upns               = @()
        Eku                = @([pscustomobject]@{ Oid = '1.3.6.1.5.5.7.3.1'; Name = 'Server Authentication' })
        KeyAlgorithm       = 'RSA'
        KeySize            = 2048
        KeyCurve           = $null
        SignatureAlgorithm = 'sha256RSA'
        HasPrivateKey      = $true
        KeyExportable      = $false
        KeyPlaintextExport = $false
        KeyProvider        = 'Microsoft Software Key Storage Provider'
        KeyStorage         = 'Software'
        KeyError           = $null
        TemplateOid        = '1.3.6.1.4.1.311.21.8.1111.2222.3'
        TemplateName       = 'CorpWebServer'
        TemplateMajor      = 100
        TemplateMinor      = 4
        ParseErrors        = @()
    }
    foreach ($k in $Override.Keys) {
        $v = $Override[$k]
        if ($k -in @('NotAfterDays', 'NotBeforeDays')) {
            $field = $k.Replace('Days', '')
            $v = $now.AddDays($v).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
            $r[$field] = $v
        }
        else { $r[$k] = $v }
    }
    return [pscustomobject]$r
}

function New-TestHost {
    param(
        [string] $Name = 'web01.corp.example.com',
        [object[]] $Certificates = @(),
        [object[]] $Bindings = @(),
        [string[]] $Errors = @(),
        [int] $CollectedDaysAgo = 0
    )
    return [pscustomobject][ordered]@{
        ComputerName     = $Name.Split('.')[0].ToUpperInvariant()
        Fqdn             = $Name
        CollectedAt      = [datetime]::UtcNow.AddDays(-$CollectedDaysAgo).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        CollectorVersion = '0.1.0'
        OS               = 'Microsoft Windows Server 2022 Datacenter'
        PSVersion        = '5.1.20348.2849'
        Stores           = @('My', 'WebHosting', 'Remote Desktop', 'Root', 'CA', 'TrustedPeople', 'TrustedPublisher')
        Certificates     = $Certificates
        Bindings         = $Bindings
        Errors           = $Errors
        Target           = $Name
    }
}

function New-TestBinding {
    param([string] $Thumbprint, [string] $Service = 'http.sys', [string] $Endpoint = '0.0.0.0:443', [string] $Store = 'MY')
    return [pscustomobject]@{ Service = $Service; Endpoint = $Endpoint; Thumbprint = $Thumbprint; Store = $Store }
}

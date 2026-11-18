<#
.SYNOPSIS
    cert-inventory collector: reads the local machine certificate stores and
    certificate bindings and returns one plain data object.

.DESCRIPTION
    This file is sent as-is to remote hosts with Invoke-Command -FilePath, so
    it must stay self-contained and compatible with Windows PowerShell 5.1
    (no ternary operator, no null-coalescing, no System.Formats.Asn1).

    It is strictly read-only: stores are opened with ReadOnly and
    OpenExistingOnly, private keys are only opened to read their export
    policy (never exported, never used), the registry and CIM are only read.

    Dot-source it with -LibraryOnly to load the helper functions without
    collecting anything (used by the unit tests).
#>
[CmdletBinding()]
param(
    [string[]] $StoreName = @('My', 'WebHosting', 'Remote Desktop', 'Root', 'CA', 'TrustedPeople', 'TrustedPublisher'),
    # A [bool] rather than a switch so that Invoke-Command -ArgumentList can bind it positionally.
    [bool] $InspectKeys = $true,
    [switch] $LibraryOnly
)

Set-StrictMode -Version 2.0

$script:CollectorVersion = '0.1.0'

# ---------------------------------------------------------------------------
# Minimal DER reader (definite lengths only, which is all DER allows).
# ---------------------------------------------------------------------------

function Read-DerElement {
    <# Returns @{ Tag; Constructed; Class; Number; Start; Length; ContentStart; End } for the element at $Offset. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [int] $Offset = 0
    )
    if ($Offset -ge $Bytes.Length) { throw "DER: offset $Offset beyond end of data" }
    $tag = [int]$Bytes[$Offset]
    if (($tag -band 0x1F) -eq 0x1F) { throw 'DER: multi-byte tags are not supported' }
    $pos = $Offset + 1
    if ($pos -ge $Bytes.Length) { throw 'DER: truncated length' }
    $first = [int]$Bytes[$pos]
    $pos++
    if ($first -lt 0x80) {
        $len = $first
    }
    elseif ($first -eq 0x80) {
        throw 'DER: indefinite length is not allowed'
    }
    else {
        $n = $first -band 0x7F
        if ($n -gt 4) { throw 'DER: length too large' }
        if ($pos + $n -gt $Bytes.Length) { throw 'DER: truncated length' }
        $len = 0
        for ($i = 0; $i -lt $n; $i++) {
            $len = ($len * 256) + [int]$Bytes[$pos + $i]
        }
        $pos += $n
    }
    if ($pos + $len -gt $Bytes.Length) { throw 'DER: element extends beyond end of data' }
    return @{
        Tag          = $tag
        Class        = ($tag -band 0xC0) -shr 6
        Constructed  = (($tag -band 0x20) -ne 0)
        Number       = $tag -band 0x1F
        Start        = $Offset
        ContentStart = $pos
        Length       = $len
        End          = $pos + $len
    }
}

function Get-DerChildElement {
    <# Returns the direct children of a constructed element. #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter(Mandatory)] [hashtable] $Element
    )
    $children = New-Object System.Collections.Generic.List[hashtable]
    $pos = $Element.ContentStart
    while ($pos -lt $Element.End) {
        $child = Read-DerElement -Bytes $Bytes -Offset $pos
        if ($child.End -gt $Element.End) { throw 'DER: child extends beyond its parent' }
        $children.Add($child)
        $pos = $child.End
    }
    return , $children.ToArray()
}

function Get-DerContent {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [Parameter(Mandatory)] [hashtable] $Element
    )
    if ($Element.Length -eq 0) { return , ([byte[]]@()) }
    $out = New-Object byte[] $Element.Length
    [Array]::Copy($Bytes, $Element.ContentStart, $out, 0, $Element.Length)
    return , $out
}

function ConvertFrom-DerOid {
    <# Decodes the content octets of an OBJECT IDENTIFIER (arcs up to ~2^70; [decimal] because System.Numerics is not loaded in Windows PowerShell 5.1). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Content)
    if ($Content.Length -eq 0) { throw 'DER: empty OID' }
    $arcs = New-Object System.Collections.Generic.List[string]
    $value = [decimal]0
    $firstDone = $false
    for ($i = 0; $i -lt $Content.Length; $i++) {
        $b = [int]$Content[$i]
        if ($value -gt [decimal]1e20) { throw 'DER: OID arc too large' }
        $value = ($value * 128) + ($b -band 0x7F)
        if (($b -band 0x80) -eq 0) {
            if (-not $firstDone) {
                if ($value -lt 40) { $arcs.Add('0'); $arcs.Add($value.ToString()) }
                elseif ($value -lt 80) { $arcs.Add('1'); $arcs.Add(($value - 40).ToString()) }
                else { $arcs.Add('2'); $arcs.Add(($value - 80).ToString()) }
                $firstDone = $true
            }
            else {
                $arcs.Add($value.ToString())
            }
            $value = [decimal]0
        }
        elseif ($i -eq $Content.Length - 1) {
            throw 'DER: truncated OID'
        }
    }
    return ($arcs -join '.')
}

function ConvertFrom-DerInteger {
    [CmdletBinding()]
    [OutputType([long])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Content)
    if ($Content.Length -eq 0 -or $Content.Length -gt 8) { throw 'DER: unsupported INTEGER size' }
    [long]$v = 0
    if (($Content[0] -band 0x80) -ne 0) { $v = -1 }
    foreach ($b in $Content) { $v = ($v * 256) + [long]$b }
    return $v
}

function ConvertFrom-DerString {
    <# Decodes the common ASN.1 string types to .NET strings. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [int] $Tag,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Content
    )
    switch ($Tag) {
        0x1E { return [System.Text.Encoding]::BigEndianUnicode.GetString($Content) } # BMPString
        0x0C { return [System.Text.Encoding]::UTF8.GetString($Content) }            # UTF8String
        default { return [System.Text.Encoding]::ASCII.GetString($Content) }        # IA5, Printable, ...
    }
}

# ---------------------------------------------------------------------------
# Certificate field extraction (works on any platform where .NET can parse
# an X509Certificate2; used remotely on Windows and in the unit tests).
# ---------------------------------------------------------------------------

$script:OidNames = @{
    '1.2.840.113549.1.1.1'    = 'RSA'
    '1.2.840.10045.2.1'       = 'ECC'
    '1.2.840.10040.4.1'       = 'DSA'
    '1.3.101.112'             = 'Ed25519'
    '1.2.840.113549.1.1.4'    = 'md5RSA'
    '1.2.840.113549.1.1.5'    = 'sha1RSA'
    '1.2.840.113549.1.1.11'   = 'sha256RSA'
    '1.2.840.113549.1.1.12'   = 'sha384RSA'
    '1.2.840.113549.1.1.13'   = 'sha512RSA'
    '1.2.840.113549.1.1.10'   = 'RSASSA-PSS'
    '1.2.840.10045.4.1'       = 'sha1ECDSA'
    '1.2.840.10045.4.3.2'     = 'sha256ECDSA'
    '1.2.840.10045.4.3.3'     = 'sha384ECDSA'
    '1.2.840.10045.4.3.4'     = 'sha512ECDSA'
    '1.2.840.10040.4.3'       = 'sha1DSA'
    '1.3.6.1.5.5.7.3.1'       = 'Server Authentication'
    '1.3.6.1.5.5.7.3.2'       = 'Client Authentication'
    '1.3.6.1.5.5.7.3.3'       = 'Code Signing'
    '1.3.6.1.5.5.7.3.4'       = 'Secure Email'
    '1.3.6.1.5.5.7.3.8'       = 'Time Stamping'
    '1.3.6.1.5.5.7.3.9'       = 'OCSP Signing'
    '1.3.6.1.4.1.311.20.2.2'  = 'Smart Card Logon'
    '1.3.6.1.4.1.311.10.3.4'  = 'Encrypting File System'
    '1.3.6.1.4.1.311.54.1.2'  = 'Remote Desktop Authentication'
    '1.3.6.1.5.2.3.5'         = 'KDC Authentication'
    '1.3.6.1.4.1.311.21.6'    = 'Key Recovery Agent'
    '1.3.6.1.4.1.311.10.3.12' = 'Document Signing'
    '2.5.29.37.0'             = 'Any Purpose'
}

function Get-OidName {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Oid, [string] $FriendlyName)
    if ($Oid -and $script:OidNames.ContainsKey($Oid)) { return $script:OidNames[$Oid] }
    if ($FriendlyName) { return $FriendlyName }
    return $Oid
}

function Get-CertExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [string] $Oid
    )
    foreach ($ext in $Certificate.Extensions) {
        if ($ext.Oid.Value -eq $Oid) { return $ext }
    }
    return $null
}

function Get-CertTemplateInfo {
    <#
    Reads the ADCS template extensions:
      1.3.6.1.4.1.311.21.7  Certificate Template Information (v2+):
                            SEQUENCE { templateID OID, major INTEGER, minor INTEGER OPTIONAL }
      1.3.6.1.4.1.311.20.2  Certificate Template Name (v1): BMPString
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $info = [ordered]@{ TemplateOid = $null; TemplateName = $null; TemplateMajorVersion = $null; TemplateMinorVersion = $null }

    $v2 = Get-CertExtension -Certificate $Certificate -Oid '1.3.6.1.4.1.311.21.7'
    if ($v2) {
        $raw = [byte[]]$v2.RawData
        $seq = Read-DerElement -Bytes $raw
        if ($seq.Tag -ne 0x30) { throw 'template information is not a SEQUENCE' }
        $kids = Get-DerChildElement -Bytes $raw -Element $seq
        if ($kids.Count -lt 1 -or $kids[0].Tag -ne 0x06) { throw 'template information has no OID' }
        $info.TemplateOid = ConvertFrom-DerOid -Content (Get-DerContent -Bytes $raw -Element $kids[0])
        if ($kids.Count -ge 2 -and $kids[1].Tag -eq 0x02) {
            $info.TemplateMajorVersion = ConvertFrom-DerInteger -Content (Get-DerContent -Bytes $raw -Element $kids[1])
        }
        if ($kids.Count -ge 3 -and $kids[2].Tag -eq 0x02) {
            $info.TemplateMinorVersion = ConvertFrom-DerInteger -Content (Get-DerContent -Bytes $raw -Element $kids[2])
        }
        # On domain members, Windows resolves template OIDs registered in AD.
        try {
            $friendly = (New-Object System.Security.Cryptography.Oid $info.TemplateOid).FriendlyName
            if ($friendly -and $friendly -ne $info.TemplateOid) { $info.TemplateName = $friendly }
        }
        catch { Write-Verbose "template OID $($info.TemplateOid) not resolvable" }
    }

    $v1 = Get-CertExtension -Certificate $Certificate -Oid '1.3.6.1.4.1.311.20.2'
    if ($v1) {
        $raw = [byte[]]$v1.RawData
        $el = Read-DerElement -Bytes $raw
        $info.TemplateName = ConvertFrom-DerString -Tag $el.Tag -Content (Get-DerContent -Bytes $raw -Element $el)
    }
    return [pscustomobject]$info
}

function Get-CertSubjectAltName {
    <# Parses SubjectAltName (2.5.29.17): DNS, IP, email, URI and UPN entries. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $result = [ordered]@{ Dns = @(); IP = @(); Email = @(); Uri = @(); Upn = @() }
    $ext = Get-CertExtension -Certificate $Certificate -Oid '2.5.29.17'
    if (-not $ext) { return [pscustomobject]$result }
    $raw = [byte[]]$ext.RawData
    $seq = Read-DerElement -Bytes $raw
    if ($seq.Tag -ne 0x30) { throw 'SubjectAltName is not a SEQUENCE' }
    $dns = @(); $ip = @(); $email = @(); $uri = @(); $upn = @()
    foreach ($gn in (Get-DerChildElement -Bytes $raw -Element $seq)) {
        if ($gn.Class -ne 2) { continue }
        $content = Get-DerContent -Bytes $raw -Element $gn
        switch ($gn.Number) {
            1 { $email += [System.Text.Encoding]::ASCII.GetString($content) }
            2 { $dns += [System.Text.Encoding]::ASCII.GetString($content) }
            6 { $uri += [System.Text.Encoding]::ASCII.GetString($content) }
            7 {
                if ($content.Length -eq 4 -or $content.Length -eq 16) {
                    $ip += (New-Object System.Net.IPAddress (, $content)).ToString()
                }
            }
            0 {
                # otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
                $kids = Get-DerChildElement -Bytes $raw -Element $gn
                if ($kids.Count -ge 2 -and $kids[0].Tag -eq 0x06) {
                    $typeId = ConvertFrom-DerOid -Content (Get-DerContent -Bytes $raw -Element $kids[0])
                    if ($typeId -eq '1.3.6.1.4.1.311.20.2.3') {
                        $inner = Get-DerChildElement -Bytes $raw -Element $kids[1]
                        if ($inner.Count -ge 1) {
                            $upn += ConvertFrom-DerString -Tag $inner[0].Tag -Content (Get-DerContent -Bytes $raw -Element $inner[0])
                        }
                    }
                }
            }
        }
    }
    $result.Dns = $dns; $result.IP = $ip; $result.Email = $email; $result.Uri = $uri; $result.Upn = $upn
    return [pscustomobject]$result
}

function Get-AlgorithmKeySize {
    <# Reads KeySize through the base class: PowerShell's adapter sees a write-only override on some types (RSAOpenSsl). #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Security.Cryptography.AsymmetricAlgorithm] $Key)
    return [int][System.Security.Cryptography.AsymmetricAlgorithm].GetProperty('KeySize').GetValue($Key, $null)
}

function Get-CertPublicKeyInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $oid = $Certificate.PublicKey.Oid.Value
    $alg = Get-OidName -Oid $oid -FriendlyName $Certificate.PublicKey.Oid.FriendlyName
    $size = $null
    $curve = $null
    try {
        switch ($oid) {
            '1.2.840.113549.1.1.1' {
                $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
                if ($k) { $size = Get-AlgorithmKeySize -Key $k; $k.Dispose() }
            }
            '1.2.840.10045.2.1' {
                $k = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
                if ($k) { $size = Get-AlgorithmKeySize -Key $k; $k.Dispose() }
                # The curve OID is the AlgorithmIdentifier parameter.
                $p = [byte[]]$Certificate.PublicKey.EncodedParameters.RawData
                if ($p -and $p.Length -gt 2 -and $p[0] -eq 0x06) {
                    $curve = ConvertFrom-DerOid -Content (Get-DerContent -Bytes $p -Element (Read-DerElement -Bytes $p))
                }
            }
            '1.2.840.10040.4.1' {
                # DSA: size of the public key modulus p, from the parameters.
                $p = [byte[]]$Certificate.PublicKey.EncodedParameters.RawData
                $seq = Read-DerElement -Bytes $p
                $kids = Get-DerChildElement -Bytes $p -Element $seq
                $pBytes = Get-DerContent -Bytes $p -Element $kids[0]
                $lead = 0
                while ($lead -lt $pBytes.Length -and $pBytes[$lead] -eq 0) { $lead++ }
                $size = ($pBytes.Length - $lead) * 8
            }
            default {
                $size = $Certificate.PublicKey.EncodedKeyValue.RawData.Length * 8
            }
        }
    }
    catch { Write-Verbose "public key size unavailable: $($_.Exception.Message)" }
    return [pscustomobject]@{ Algorithm = $alg; Oid = $oid; Size = $size; Curve = $curve }
}

function Test-PrivateKeyExportable {
    <#
    Reads the export policy of an opened private key object.
      CNG (RSACng/ECDsaCng/DSACng): .Key.ExportPolicy flags
            AllowExport = 1, AllowPlaintextExport = 2
      CAPI (RSACryptoServiceProvider/DSACryptoServiceProvider): .CspKeyContainerInfo
    Returns Exportable ($true/$false/$null), PlaintextExportable, Provider,
    Storage (Software/TPM/SmartCard/Hardware/Unknown) and Api (CNG/CAPI).
    #>
    [CmdletBinding()]
    param([AllowNull()] $Key)
    $r = [ordered]@{ Exportable = $null; PlaintextExportable = $null; Provider = $null; Storage = 'Unknown'; Api = $null }
    if ($null -eq $Key) { return [pscustomobject]$r }

    $cng = $null
    if ($Key.PSObject.Properties['Key']) { $cng = $Key.Key }
    if ($null -ne $cng -and $cng.PSObject.Properties['ExportPolicy']) {
        $policy = [int]$cng.ExportPolicy
        $r.Api = 'CNG'
        $r.Exportable = (($policy -band 0x3) -ne 0)
        $r.PlaintextExportable = (($policy -band 0x2) -ne 0)
        $prov = $cng.Provider
        if ($null -ne $prov -and $prov.PSObject.Properties['Provider']) { $prov = $prov.Provider }
        $r.Provider = [string]$prov
    }
    elseif ($Key.PSObject.Properties['CspKeyContainerInfo']) {
        $info = $Key.CspKeyContainerInfo
        $r.Api = 'CAPI'
        $r.Exportable = [bool]$info.Exportable
        $r.PlaintextExportable = [bool]$info.Exportable
        $r.Provider = [string]$info.ProviderName
        if ($info.PSObject.Properties['HardwareDevice'] -and $info.HardwareDevice) { $r.Storage = 'Hardware' }
        if ($info.PSObject.Properties['Removable'] -and $info.Removable) { $r.Storage = 'SmartCard' }
    }
    else {
        return [pscustomobject]$r
    }

    if ($r.Storage -eq 'Unknown') {
        $p = [string]$r.Provider
        if ($p -match 'Platform Crypto Provider') { $r.Storage = 'TPM' }
        elseif ($p -match 'Smart ?Card') { $r.Storage = 'SmartCard' }
        elseif ($p -match 'Software Key Storage|Cryptographic Provider|Cryptographic Service Provider|RSA and AES|Enhanced|Strong|Base|DSS|SChannel') { $r.Storage = 'Software' }
        else { $r.Storage = 'Hardware' } # third-party KSP/CSP: HSM, vendor token...
    }
    if ($r.Storage -eq 'TPM' -or $r.Storage -eq 'SmartCard') {
        # The flag is meaningless for keys that cannot leave the device.
        $r.Exportable = $false
        $r.PlaintextExportable = $false
    }
    return [pscustomobject]$r
}

function Get-CertPrivateKeyInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [switch] $SkipKeyInspection
    )
    $base = [ordered]@{ Exportable = $null; PlaintextExportable = $null; Provider = $null; Storage = $null; Api = $null; Error = $null }
    if (-not $Certificate.HasPrivateKey) { return [pscustomobject]$base }
    if ($SkipKeyInspection) { $base.Error = 'skipped'; return [pscustomobject]$base }
    $key = $null
    try {
        switch ($Certificate.PublicKey.Oid.Value) {
            '1.2.840.113549.1.1.1' { $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) }
            '1.2.840.10045.2.1' { $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate) }
            default { $key = $Certificate.PrivateKey }
        }
        $info = Test-PrivateKeyExportable -Key $key
        foreach ($p in $info.PSObject.Properties) { $base[$p.Name] = $p.Value }
        if ($null -eq $key) { $base.Error = 'private key could not be opened' }
    }
    catch {
        $base.Error = $_.Exception.Message
    }
    finally {
        if ($null -ne $key -and $key -is [System.IDisposable]) { $key.Dispose() }
    }
    return [pscustomobject]$base
}

function ConvertTo-CertRecord {
    <# Converts an X509Certificate2 into a plain, serialisable record. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [string] $Store,
        [switch] $SkipKeyInspection
    )
    $errors = @()
    $san = $null
    try { $san = Get-CertSubjectAltName -Certificate $Certificate }
    catch { $errors += "SubjectAltName: $($_.Exception.Message)" }
    $tpl = $null
    try { $tpl = Get-CertTemplateInfo -Certificate $Certificate }
    catch { $errors += "template: $($_.Exception.Message)" }
    $pub = Get-CertPublicKeyInfo -Certificate $Certificate
    $priv = Get-CertPrivateKeyInfo -Certificate $Certificate -SkipKeyInspection:$SkipKeyInspection

    $eku = @()
    $isCa = $null
    $pathLen = $null
    foreach ($ext in $Certificate.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($o in $ext.EnhancedKeyUsages) {
                $eku += [pscustomobject]@{ Oid = $o.Value; Name = (Get-OidName -Oid $o.Value -FriendlyName $o.FriendlyName) }
            }
        }
        elseif ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $isCa = [bool]$ext.CertificateAuthority
            if ($ext.HasPathLengthConstraint) { $pathLen = $ext.PathLengthConstraint }
        }
    }

    $dns = @(); $ips = @(); $upn = @()
    if ($san) { $dns = @($san.Dns); $ips = @($san.IP); $upn = @($san.Upn) }
    $template = [ordered]@{ Oid = $null; Name = $null; MajorVersion = $null; MinorVersion = $null }
    if ($tpl) {
        $template.Oid = $tpl.TemplateOid; $template.Name = $tpl.TemplateName
        $template.MajorVersion = $tpl.TemplateMajorVersion; $template.MinorVersion = $tpl.TemplateMinorVersion
    }

    return [pscustomobject][ordered]@{
        Store               = $Store
        Thumbprint          = $Certificate.Thumbprint.ToUpperInvariant()
        Subject             = $Certificate.Subject
        Issuer              = $Certificate.Issuer
        SerialNumber        = $Certificate.SerialNumber
        FriendlyName        = $Certificate.FriendlyName
        NotBefore           = $Certificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        NotAfter            = $Certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        SelfIssued          = ($Certificate.Subject -eq $Certificate.Issuer)
        IsCA                = $isCa
        PathLength          = $pathLen
        DnsNames            = $dns
        IPAddresses         = $ips
        Upns                = $upn
        Eku                 = $eku
        KeyAlgorithm        = $pub.Algorithm
        KeySize             = $pub.Size
        KeyCurve            = $pub.Curve
        SignatureAlgorithm  = (Get-OidName -Oid $Certificate.SignatureAlgorithm.Value -FriendlyName $Certificate.SignatureAlgorithm.FriendlyName)
        HasPrivateKey       = [bool]$Certificate.HasPrivateKey
        KeyExportable       = $priv.Exportable
        KeyPlaintextExport  = $priv.PlaintextExportable
        KeyProvider         = $priv.Provider
        KeyStorage          = $priv.Storage
        KeyError            = $priv.Error
        TemplateOid         = $template.Oid
        TemplateName        = $template.Name
        TemplateMajor       = $template.MajorVersion
        TemplateMinor       = $template.MinorVersion
        ParseErrors         = $errors
    }
}

# ---------------------------------------------------------------------------
# Windows-only collection: stores and bindings.
# ---------------------------------------------------------------------------

function ConvertTo-HexString {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [byte[]] $Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-HttpSysBinding {
    <# HTTP.sys TLS bindings (IIS, WinRM over HTTP.sys, WAP, ADFS, custom services) from the registry. #>
    [CmdletBinding()]
    param([string] $RegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters')
    $out = @()
    foreach ($kind in @('SslBindingInfo', 'SslSniBindingInfo')) {
        $path = $RegistryRoot + '\' + $kind
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($k in (Get-ChildItem -LiteralPath $path -ErrorAction Stop)) {
            $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
            $hash = $null
            if ($props.PSObject.Properties['SslCertHash']) { $hash = ConvertTo-HexString -Bytes ([byte[]]$props.SslCertHash) }
            $store = 'MY'
            if ($props.PSObject.Properties['SslCertStoreName'] -and $props.SslCertStoreName) { $store = [string]$props.SslCertStoreName }
            $out += [pscustomobject]@{ Service = 'http.sys'; Endpoint = $k.PSChildName; Thumbprint = $hash; Store = $store }
        }
    }
    return $out
}

function Get-RdpBinding {
    [CmdletBinding()]
    param()
    $s = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName 'Win32_TSGeneralSetting' -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop -Verbose:$false
    $out = @()
    foreach ($i in @($s)) {
        if ($i.SSLCertificateSHA1Hash) {
            $out += [pscustomobject]@{ Service = 'rdp'; Endpoint = 'RDP-Tcp'; Thumbprint = ([string]$i.SSLCertificateSHA1Hash).ToUpperInvariant(); Store = 'Remote Desktop' }
        }
    }
    return $out
}

function Get-WinRmBinding {
    [CmdletBinding()]
    param([string] $RegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener')
    $out = @()
    if (-not (Test-Path -LiteralPath $RegistryRoot)) { return $out }
    foreach ($k in (Get-ChildItem -LiteralPath $RegistryRoot -ErrorAction Stop)) {
        if ($k.PSChildName -notmatch 'HTTPS$') { continue }
        $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
        if ($props.PSObject.Properties['certThumbprint'] -and $props.certThumbprint) {
            $tp = ([string]$props.certThumbprint) -replace '\s', ''
            $out += [pscustomobject]@{ Service = 'winrm'; Endpoint = $k.PSChildName; Thumbprint = $tp.ToUpperInvariant(); Store = 'My' }
        }
    }
    return $out
}

function Get-StoreCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($Name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $flags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
    $store.Open($flags)
    try {
        $list = @()
        foreach ($c in $store.Certificates) { $list += $c }
        return , $list
    }
    finally { $store.Close() }
}

function Get-LocalFqdn {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    try {
        $p = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if ($p.DomainName) { return ('{0}.{1}' -f $p.HostName, $p.DomainName).ToLowerInvariant() }
        return $p.HostName.ToLowerInvariant()
    }
    catch { return [System.Environment]::MachineName.ToLowerInvariant() }
}

function Invoke-CertCollection {
    [CmdletBinding()]
    param([string[]] $StoreName, [switch] $SkipKeyInspection)
    $errors = @()
    $certs = @()
    foreach ($s in $StoreName) {
        try { $items = Get-StoreCertificate -Name $s }
        catch {
            # A missing optional store (e.g. WebHosting without IIS) is not an error.
            $ex = $_.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            # 0x80070002 = ERROR_FILE_NOT_FOUND (the message itself is localised).
            if ($ex.HResult -ne -2147024894 -and $ex.Message -notmatch 'cannot find|not found|does not exist|0x80070002') {
                $errors += "store ${s}: $($_.Exception.Message)"
            }
            continue
        }
        foreach ($c in $items) {
            try { $certs += ConvertTo-CertRecord -Certificate $c -Store $s -SkipKeyInspection:$SkipKeyInspection }
            catch { $errors += "store ${s}, $($c.Thumbprint): $($_.Exception.Message)" }
            finally { $c.Reset() }
        }
    }
    $bindings = @()
    foreach ($fn in @('Get-HttpSysBinding', 'Get-RdpBinding', 'Get-WinRmBinding')) {
        try { $bindings += & $fn }
        catch {
            # Editions without Remote Desktop Services expose no TerminalServices namespace.
            if ($fn -eq 'Get-RdpBinding' -and $_.Exception.Message -match 'Invalid namespace|Invalid class|0x8004100E|0x80041010') { continue }
            $errors += "${fn}: $($_.Exception.Message)"
        }
    }
    $os = $null
    try { $os = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop -Verbose:$false).Caption }
    catch { $os = [System.Environment]::OSVersion.VersionString }

    return [pscustomobject][ordered]@{
        ComputerName     = [System.Environment]::MachineName
        Fqdn             = (Get-LocalFqdn)
        CollectedAt      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        CollectorVersion = $script:CollectorVersion
        OS               = $os
        PSVersion        = $PSVersionTable.PSVersion.ToString()
        Stores           = $StoreName
        Certificates     = $certs
        Bindings         = $bindings
        Errors           = $errors
    }
}

if (-not $LibraryOnly) {
    Invoke-CertCollection -StoreName $StoreName -SkipKeyInspection:(-not $InspectKeys)
}

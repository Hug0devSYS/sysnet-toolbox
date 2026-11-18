BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '../src/Collector.ps1') -LibraryOnly
}

Describe 'DER reader' {
    It 'decodes OIDs with multi-byte arcs' {
        $der = ConvertTo-TestDerOid '1.3.6.1.4.1.311.21.8.16777215.4294967296.1'
        $el = Read-DerElement -Bytes $der
        ConvertFrom-DerOid -Content (Get-DerContent -Bytes $der -Element $el) | Should -Be '1.3.6.1.4.1.311.21.8.16777215.4294967296.1'
    }

    It 'decodes first arcs of the 2.x branch' {
        ConvertFrom-DerOid -Content ([byte[]](0x88, 0x37, 0x03)) | Should -Be '2.999.3'
    }

    It 'rejects a truncated OID' {
        { ConvertFrom-DerOid -Content ([byte[]](0x2B, 0x86)) } | Should -Throw '*truncated*'
    }

    It 'decodes long-form lengths' {
        $content = [byte[]](1..200 | ForEach-Object { 0x41 })
        $der = [byte[]](@(0x16, 0x81, 200) + $content)
        $el = Read-DerElement -Bytes $der
        $el.Length | Should -Be 200
        $el.ContentStart | Should -Be 3
    }

    It 'rejects indefinite lengths and overruns' {
        { Read-DerElement -Bytes ([byte[]](0x30, 0x80, 0x00, 0x00)) } | Should -Throw '*indefinite*'
        { Read-DerElement -Bytes ([byte[]](0x30, 0x05, 0x01)) } | Should -Throw '*beyond*'
        { Read-DerElement -Bytes ([byte[]](0x30)) } | Should -Throw '*truncated*'
    }

    It 'rejects a child that overruns its parent' {
        $bytes = [byte[]](0x30, 0x03, 0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05)
        $el = Read-DerElement -Bytes $bytes
        { Get-DerChildElement -Bytes $bytes -Element $el } | Should -Throw
    }

    It 'decodes signed integers' {
        ConvertFrom-DerInteger -Content ([byte[]](0x00, 0xFF)) | Should -Be 255
        ConvertFrom-DerInteger -Content ([byte[]](0xFF)) | Should -Be -1
        ConvertFrom-DerInteger -Content ([byte[]](0x01, 0x00)) | Should -Be 256
    }
}

Describe 'Certificate field extraction' {
    It 'reads a v2 template extension (OID and versions)' {
        $c = New-TestCertificate -TemplateV2Der (New-TestTemplateV2Der -Oid '1.3.6.1.4.1.311.21.8.8765.4321.1' -Major 100 -Minor 7)
        $t = Get-CertTemplateInfo -Certificate $c
        $t.TemplateOid | Should -Be '1.3.6.1.4.1.311.21.8.8765.4321.1'
        $t.TemplateMajorVersion | Should -Be 100
        $t.TemplateMinorVersion | Should -Be 7
    }

    It 'reads a v1 template name (BMPString)' {
        $c = New-TestCertificate -TemplateV1Der (New-TestTemplateV1Der -Name 'WebServer')
        (Get-CertTemplateInfo -Certificate $c).TemplateName | Should -Be 'WebServer'
    }

    It 'returns empty template info without the extensions' {
        $t = Get-CertTemplateInfo -Certificate (New-TestCertificate)
        $t.TemplateOid | Should -BeNullOrEmpty
        $t.TemplateName | Should -BeNullOrEmpty
    }

    It 'parses DNS, IPv4, IPv6 and UPN SubjectAltName entries' {
        $c = New-TestCertificate -DnsName 'a.example.com', 'b.example.com' -IPAddress '192.0.2.10', '2001:db8::1' -Upn 'svc-web@corp.example.com'
        $san = Get-CertSubjectAltName -Certificate $c
        $san.Dns | Should -Be @('a.example.com', 'b.example.com')
        $san.IP | Should -Be @('192.0.2.10', '2001:db8::1')
        $san.Upn | Should -Be @('svc-web@corp.example.com')
    }

    It 'reports RSA and ECC key sizes and the curve' {
        (Get-CertPublicKeyInfo -Certificate (New-TestCertificate -KeySize 3072)).Size | Should -Be 3072
        $ec = Get-CertPublicKeyInfo -Certificate (New-TestCertificate -KeyType ECC -KeySize 384)
        $ec.Algorithm | Should -Be 'ECC'
        $ec.Size | Should -Be 384
        $ec.Curve | Should -Be '1.3.132.0.34'
    }

    It 'converts a certificate into a complete record' {
        $c = New-TestCertificate -Subject 'CN=web01.example.com' -DnsName 'web01.example.com' -Eku '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2' -CA `
            -TemplateV2Der (New-TestTemplateV2Der -Oid '1.3.6.1.4.1.311.21.8.1.2')
        $r = ConvertTo-CertRecord -Certificate $c -Store 'My'
        $r.Store | Should -Be 'My'
        $r.Thumbprint | Should -Be $c.Thumbprint.ToUpperInvariant()
        $r.Subject | Should -Be 'CN=web01.example.com'
        $r.SelfIssued | Should -BeTrue
        $r.IsCA | Should -BeTrue
        $r.PathLength | Should -Be 1
        $r.DnsNames | Should -Be @('web01.example.com')
        @($r.Eku.Name) | Should -Be @('Server Authentication', 'Client Authentication')
        $r.KeyAlgorithm | Should -Be 'RSA'
        $r.KeySize | Should -Be 2048
        $r.SignatureAlgorithm | Should -Be 'sha256RSA'
        $r.HasPrivateKey | Should -BeTrue
        $r.TemplateOid | Should -Be '1.3.6.1.4.1.311.21.8.1.2'
        $r.NotAfter | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
        $r.ParseErrors.Count | Should -Be 0
    }

    It 'records a parse error instead of failing on a malformed extension' {
        $c = New-TestCertificate -TemplateV2Der ([byte[]](0x30, 0x03, 0x02, 0x01, 0x05))
        $r = ConvertTo-CertRecord -Certificate $c -Store 'My'
        $r.ParseErrors | Should -Match 'template'
        $r.Thumbprint | Should -Not -BeNullOrEmpty
    }

    It 'does not open keys with -SkipKeyInspection' {
        $r = ConvertTo-CertRecord -Certificate (New-TestCertificate) -Store 'My' -SkipKeyInspection
        $r.KeyError | Should -Be 'skipped'
        $r.KeyExportable | Should -BeNullOrEmpty
    }
}

Describe 'Test-PrivateKeyExportable' {
    It 'reads the CNG export policy' {
        $k = [pscustomobject]@{ Key = [pscustomobject]@{ ExportPolicy = 1; Provider = [pscustomobject]@{ Provider = 'Microsoft Software Key Storage Provider' } } }
        $r = Test-PrivateKeyExportable -Key $k
        $r.Api | Should -Be 'CNG'
        $r.Exportable | Should -BeTrue
        $r.PlaintextExportable | Should -BeFalse
        $r.Storage | Should -Be 'Software'
    }

    It 'detects plaintext export' {
        $k = [pscustomobject]@{ Key = [pscustomobject]@{ ExportPolicy = 3; Provider = 'Microsoft Software Key Storage Provider' } }
        (Test-PrivateKeyExportable -Key $k).PlaintextExportable | Should -BeTrue
    }

    It 'treats a non-exportable CNG key as such' {
        $k = [pscustomobject]@{ Key = [pscustomobject]@{ ExportPolicy = 0; Provider = 'Microsoft Software Key Storage Provider' } }
        (Test-PrivateKeyExportable -Key $k).Exportable | Should -BeFalse
    }

    It 'never reports TPM-protected keys as exportable' {
        $k = [pscustomobject]@{ Key = [pscustomobject]@{ ExportPolicy = 1; Provider = 'Microsoft Platform Crypto Provider' } }
        $r = Test-PrivateKeyExportable -Key $k
        $r.Storage | Should -Be 'TPM'
        $r.Exportable | Should -BeFalse
    }

    It 'reads the CAPI container flags' {
        $k = [pscustomobject]@{ CspKeyContainerInfo = [pscustomobject]@{ Exportable = $true; ProviderName = 'Microsoft Enhanced RSA and AES Cryptographic Provider'; HardwareDevice = $false; Removable = $false } }
        $r = Test-PrivateKeyExportable -Key $k
        $r.Api | Should -Be 'CAPI'
        $r.Exportable | Should -BeTrue
        $r.Storage | Should -Be 'Software'
    }

    It 'recognises smart card CSPs' {
        $k = [pscustomobject]@{ CspKeyContainerInfo = [pscustomobject]@{ Exportable = $true; ProviderName = 'Microsoft Base Smart Card Crypto Provider'; HardwareDevice = $true; Removable = $true } }
        $r = Test-PrivateKeyExportable -Key $k
        $r.Storage | Should -Be 'SmartCard'
        $r.Exportable | Should -BeFalse
    }

    It 'flags vendor providers as hardware' {
        $k = [pscustomobject]@{ Key = [pscustomobject]@{ ExportPolicy = 0; Provider = 'SafeNet Key Storage Provider' } }
        (Test-PrivateKeyExportable -Key $k).Storage | Should -Be 'Hardware'
    }

    It 'returns unknown for null or unsupported key objects' {
        (Test-PrivateKeyExportable -Key $null).Exportable | Should -BeNullOrEmpty
        (Test-PrivateKeyExportable -Key ([pscustomobject]@{ Foo = 1 })).Storage | Should -Be 'Unknown'
    }
}

Describe 'Binding discovery' {
    It 'reads HTTP.sys IP and SNI bindings from the registry' {
        Mock Test-Path { $true }
        Mock Get-ChildItem {
            if ($LiteralPath -like '*SslSniBindingInfo') { return [pscustomobject]@{ PSPath = 'sni1'; PSChildName = 'portal.example.com:443' } }
            return [pscustomobject]@{ PSPath = 'ip1'; PSChildName = '0.0.0.0:443' }
        }
        Mock Get-ItemProperty {
            if ($LiteralPath -eq 'sni1') { return [pscustomobject]@{ SslCertHash = [byte[]](0xAB, 0xCD); SslCertStoreName = 'WebHosting' } }
            return [pscustomobject]@{ SslCertHash = [byte[]](0x01, 0x0F) }
        }
        $b = @(Get-HttpSysBinding)
        $b.Count | Should -Be 2
        $b[0].Endpoint | Should -Be '0.0.0.0:443'
        $b[0].Thumbprint | Should -Be '010F'
        $b[0].Store | Should -Be 'MY'
        $b[1].Endpoint | Should -Be 'portal.example.com:443'
        $b[1].Store | Should -Be 'WebHosting'
    }

    It 'returns nothing when HTTP.sys has no TLS bindings' {
        Mock Test-Path { $false }
        @(Get-HttpSysBinding).Count | Should -Be 0
    }

    It 'reads only HTTPS WinRM listeners' {
        Mock Test-Path { $true }
        Mock Get-ChildItem { @([pscustomobject]@{ PSPath = 'l1'; PSChildName = '*+HTTP' }, [pscustomobject]@{ PSPath = 'l2'; PSChildName = '*+HTTPS' }) }
        Mock Get-ItemProperty { [pscustomobject]@{ certThumbprint = 'ab cd ef' } }
        $b = @(Get-WinRmBinding)
        $b.Count | Should -Be 1
        $b[0].Thumbprint | Should -Be 'ABCDEF'
        $b[0].Service | Should -Be 'winrm'
    }

    It 'reads the RDP listener certificate' {
        Mock Get-CimInstance { [pscustomobject]@{ SSLCertificateSHA1Hash = 'aa11' } }
        $b = @(Get-RdpBinding)
        $b[0].Thumbprint | Should -Be 'AA11'
        $b[0].Store | Should -Be 'Remote Desktop'
    }
}

Describe 'Invoke-CertCollection' {
    # Fresh objects for every test: the collector calls Reset() on each certificate it has processed.
    BeforeEach {
        $script:certA = New-TestCertificate -Subject 'CN=a.example.com' -DnsName 'a.example.com'
        $script:certB = New-TestCertificate -Subject 'CN=Root' -CA
    }

    It 'collects every store, ignores missing optional stores and records real errors' {
        Mock Get-StoreCertificate {
            switch ($Name) {
                'My' { return , @($script:certA) }
                'Root' { return , @($script:certB) }
                'WebHosting' { throw (New-Object System.Security.Cryptography.CryptographicException 'The system cannot find the file specified.') }
                'CA' { throw (New-Object System.UnauthorizedAccessException 'Access is denied.') }
            }
        }
        Mock Get-HttpSysBinding { New-TestBinding -Thumbprint $script:certA.Thumbprint }
        Mock Get-RdpBinding { throw 'Invalid namespace' }
        Mock Get-WinRmBinding { @() }
        Mock Get-CimInstance { [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Standard' } }

        $r = Invoke-CertCollection -StoreName 'My', 'WebHosting', 'Root', 'CA'
        @($r.Certificates).Count | Should -Be 2
        @($r.Certificates | Where-Object Store -EQ 'My').Subject | Should -Be 'CN=a.example.com'
        @($r.Bindings).Count | Should -Be 1
        @($r.Errors).Count | Should -Be 1
        $r.Errors[0] | Should -Match '^store CA: '
        $r.OS | Should -Be 'Microsoft Windows Server 2022 Standard'
        $r.CollectorVersion | Should -Be '0.1.0'
        $r.Stores | Should -Be @('My', 'WebHosting', 'Root', 'CA')
    }

    It 'keeps going when one certificate cannot be converted' {
        Mock Get-StoreCertificate { , @($script:certA, $script:certB) }
        Mock ConvertTo-CertRecord { if ($Certificate.Subject -eq 'CN=Root') { throw 'boom' }; [pscustomobject]@{ Thumbprint = 'X' } }
        Mock Get-HttpSysBinding { @() }
        Mock Get-RdpBinding { @() }
        Mock Get-WinRmBinding { throw 'registry unavailable' }
        Mock Get-CimInstance { throw 'no CIM' }
        $r = Invoke-CertCollection -StoreName 'My'
        @($r.Certificates).Count | Should -Be 1
        @($r.Errors).Count | Should -Be 2
        ($r.Errors -join "`n") | Should -Match 'boom'
        ($r.Errors -join "`n") | Should -Match 'Get-WinRmBinding: registry unavailable'
    }
}

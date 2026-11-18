BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module (Join-Path $PSScriptRoot '../src/CertInventory.psm1') -Force

    function Get-FindingCode {
        param($Report, [string] $Severity)
        @($Report.Findings | Where-Object { -not $Severity -or $_.Severity -eq $Severity } | ForEach-Object Code)
    }
    function Get-Finding {
        param($Report, [string] $Code)
        @($Report.Findings | Where-Object Code -EQ $Code)
    }
}

Describe 'Expiry analysis' {
    It 'is OK for a valid, bound, non-exportable certificate' {
        $c = New-TestRecord
        $h = New-TestHost -Certificates @($c) -Bindings @(New-TestBinding -Thumbprint $c.Thumbprint)
        $r = New-CertInventoryReport -Hosts @($h)
        @($r.Findings).Count | Should -Be 0
        $r.ExitCode | Should -Be 0
        $r.Status | Should -Be 'OK'
        $r.Hosts[0].Certificates[0].BoundTo | Should -Be @('http.sys 0.0.0.0:443')
        $r.Hosts[0].Certificates[0].DaysLeft | Should -BeIn 199, 200
    }

    It 'warns and then goes critical as a certificate approaches expiry' {
        $warn = New-TestRecord @{ NotAfterDays = 25 }
        $crit = New-TestRecord @{ NotAfterDays = 5; Subject = 'CN=other' }
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($warn, $crit))
        (Get-Finding $r 'EXPIRING' | Where-Object Thumbprint -EQ $warn.Thumbprint).Severity | Should -Be 'warning'
        (Get-Finding $r 'EXPIRING' | Where-Object Thumbprint -EQ $crit.Thumbprint).Severity | Should -Be 'critical'
        $r.ExitCode | Should -Be 2
    }

    It 'honours custom thresholds' {
        $c = New-TestRecord @{ NotAfterDays = 50 }
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c)) -WarningDays 60 -CriticalDays 10
        (Get-Finding $r 'EXPIRING').Severity | Should -Be 'warning'
    }

    It 'rejects -CriticalDays greater than -WarningDays' {
        { New-CertInventoryReport -Hosts @() -WarningDays 10 -CriticalDays 20 } | Should -Throw '*CriticalDays*'
    }

    It 'is critical for an expired certificate that is still bound' {
        $c = New-TestRecord @{ NotAfterDays = -3 }
        $h = New-TestHost -Certificates @($c) -Bindings @(New-TestBinding -Thumbprint $c.Thumbprint)
        $f = Get-Finding (New-CertInventoryReport -Hosts @($h)) 'EXPIRED_BOUND'
        $f.Severity | Should -Be 'critical'
        $f.Message | Should -Match 'bound to http.sys 0.0.0.0:443'
    }

    It 'only reports a superseded expired certificate as a clean-up candidate' {
        $old = New-TestRecord @{ NotAfterDays = -40; NotBeforeDays = -400 }
        $new = New-TestRecord @{ NotAfterDays = 325; NotBeforeDays = -40 }
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($old, $new))
        Get-FindingCode $r | Should -Be @('SUPERSEDED')
        (Get-Finding $r 'SUPERSEDED').Severity | Should -Be 'info'
        $r.ExitCode | Should -Be 0
    }

    It 'warns about an expired certificate without a successor' {
        $c = New-TestRecord @{ NotAfterDays = -2 }
        (Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c))) 'EXPIRED').Severity | Should -Be 'warning'
    }

    It 'detects a renewal that was never bound' {
        $old = New-TestRecord @{ NotAfterDays = 6 }
        $new = New-TestRecord @{ NotAfterDays = 371; NotBeforeDays = -1 }
        $h = New-TestHost -Certificates @($old, $new) -Bindings @(New-TestBinding -Thumbprint $old.Thumbprint)
        $r = New-CertInventoryReport -Hosts @($h)
        $f = Get-Finding $r 'RENEWED_NOT_REBOUND'
        $f.Severity | Should -Be 'critical'
        $f.Message | Should -Match $new.Thumbprint
        Get-FindingCode $r | Should -Not -Contain 'EXPIRING'
    }

    It 'treats an unbound renewed certificate as information' {
        $old = New-TestRecord @{ NotAfterDays = 6 }
        $new = New-TestRecord @{ NotAfterDays = 371; NotBeforeDays = -1 }
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($old, $new))
        Get-FindingCode $r | Should -Be @('RENEWED')
    }

    It 'does not count a certificate from another template as a successor' {
        $old = New-TestRecord @{ NotAfterDays = 6 }
        $other = New-TestRecord @{ NotAfterDays = 371; TemplateOid = '1.3.6.1.4.1.311.21.8.9.9.9' }
        Get-FindingCode (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($old, $other))) | Should -Contain 'EXPIRING'
    }

    It 'does not count a successor that is not valid yet' {
        $old = New-TestRecord @{ NotAfterDays = 6 }
        $future = New-TestRecord @{ NotAfterDays = 400; NotBeforeDays = 10 }
        $codes = Get-FindingCode (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($old, $future)))
        $codes | Should -Contain 'EXPIRING'
        $codes | Should -Contain 'NOT_YET_VALID'
    }

    It 'summarises expired trust anchors per store instead of one finding each' {
        $roots = 1..3 | ForEach-Object { New-TestRecord @{ Store = 'Root'; HasPrivateKey = $false; NotAfterDays = -100; Subject = "CN=Old Root $_"; SelfIssued = $true } }
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates $roots)
        $f = Get-Finding $r 'TRUST_EXPIRED'
        $f.Count | Should -Be 1
        $f[0].Message | Should -Match '^3 expired certificate\(s\) in the Root store'
        $r.ExitCode | Should -Be 0
    }

    It 'accepts DateTime values as produced by ConvertFrom-Json on PowerShell 7' {
        $c = New-TestRecord
        $c.NotAfter = [datetime]::UtcNow.AddDays(3)
        $c.NotBefore = [datetime]::Now.AddDays(-3)
        (Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c))) 'EXPIRING').Severity | Should -Be 'critical'
    }
}

Describe 'Key and signature checks' {
    It 'flags weak RSA keys, critical when bound' {
        $a = New-TestRecord @{ KeySize = 1024 }
        $b = New-TestRecord @{ KeySize = 1536; Subject = 'CN=b' }
        $h = New-TestHost -Certificates @($a, $b) -Bindings @(New-TestBinding -Thumbprint $b.Thumbprint)
        $f = Get-Finding (New-CertInventoryReport -Hosts @($h)) 'WEAK_KEY'
        ($f | Where-Object Thumbprint -EQ $a.Thumbprint).Severity | Should -Be 'warning'
        ($f | Where-Object Thumbprint -EQ $b.Thumbprint).Severity | Should -Be 'critical'
    }

    It 'honours -MinRsaKeySize' {
        $c = New-TestRecord @{ KeySize = 2048 }
        (Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c)) -MinRsaKeySize 3072) 'WEAK_KEY').Count | Should -Be 1
    }

    It 'flags DSA keys and small curves' {
        $d = New-TestRecord @{ KeyAlgorithm = 'DSA'; KeySize = 2048 }
        $e = New-TestRecord @{ KeyAlgorithm = 'ECC'; KeySize = 224; Subject = 'CN=e' }
        (Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($d, $e))) 'WEAK_KEY').Count | Should -Be 2
    }

    It 'flags SHA-1 signatures on issued certificates only' {
        $issued = New-TestRecord @{ SignatureAlgorithm = 'sha1RSA' }
        $self = New-TestRecord @{ SignatureAlgorithm = 'sha1RSA'; SelfIssued = $true; Subject = 'CN=self'; Issuer = 'CN=self' }
        $f = Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($issued, $self))) 'WEAK_SIGNATURE'
        $f.Count | Should -Be 1
        $f[0].Thumbprint | Should -Be $issued.Thumbprint
    }

    It 'warns about exportable private keys and mentions plaintext export' {
        $c = New-TestRecord @{ KeyExportable = $true; KeyPlaintextExport = $true }
        $f = Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c))) 'EXPORTABLE_KEY'
        $f.Severity | Should -Be 'warning'
        $f.Message | Should -Match 'plaintext'
    }

    It 'downgrades expected exportable keys with -AllowExportable' {
        $c = New-TestRecord @{ KeyExportable = $true; TemplateName = 'CorpWebServer-Exportable' }
        $f = Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c)) -AllowExportable '*-Exportable') 'EXPORTABLE_KEY'
        $f.Severity | Should -Be 'info'
    }

    It 'reports unreadable private keys as information, but not skipped inspection' {
        $a = New-TestRecord @{ KeyExportable = $null; KeyError = 'Keyset does not exist' }
        $b = New-TestRecord @{ KeyExportable = $null; KeyError = 'skipped'; Subject = 'CN=b' }
        $f = Get-Finding (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($a, $b))) 'KEY_UNREADABLE'
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'info'
    }

    It 'warns about a bound server certificate without SubjectAltName' {
        $c = New-TestRecord @{ DnsNames = @() }
        $h = New-TestHost -Certificates @($c) -Bindings @(New-TestBinding -Thumbprint $c.Thumbprint)
        (Get-Finding (New-CertInventoryReport -Hosts @($h)) 'NO_SAN').Severity | Should -Be 'warning'
    }

    It 'does not check SubjectAltName on client certificates' {
        $c = New-TestRecord @{ DnsNames = @(); Eku = @([pscustomobject]@{ Oid = '1.3.6.1.5.5.7.3.2'; Name = 'Client Authentication' }) }
        Get-FindingCode (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c))) | Should -Not -Contain 'NO_SAN'
    }

    It 'skips strength checks on expired certificates' {
        $c = New-TestRecord @{ NotAfterDays = -1; KeySize = 1024; KeyExportable = $true }
        Get-FindingCode (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c))) | Should -Be @('EXPIRED')
    }
}

Describe 'Binding checks' {
    It 'is critical when a binding references a missing certificate' {
        $h = New-TestHost -Certificates @() -Bindings @(New-TestBinding -Thumbprint 'AABBCC')
        $f = Get-Finding (New-CertInventoryReport -Hosts @($h)) 'BINDING_CERT_MISSING'
        $f.Severity | Should -Be 'critical'
        $f.Message | Should -Match 'AABBCC'
    }

    It 'matches binding store names case-insensitively and thumbprints in any case' {
        $c = New-TestRecord
        $h = New-TestHost -Certificates @($c) -Bindings @(New-TestBinding -Thumbprint $c.Thumbprint.ToLowerInvariant() -Store 'MY')
        @((New-CertInventoryReport -Hosts @($h)).Findings).Count | Should -Be 0
    }

    It 'does not claim a certificate is missing from a store that was not collected' {
        $h = New-TestHost -Bindings @(New-TestBinding -Thumbprint 'AABBCC' -Store 'CustomStore')
        (Get-Finding (New-CertInventoryReport -Hosts @($h)) 'BINDING_NOT_CHECKED').Severity | Should -Be 'info'
    }

    It 'is critical when a bound certificate has no private key' {
        $c = New-TestRecord @{ HasPrivateKey = $false }
        $h = New-TestHost -Certificates @($c) -Bindings @(New-TestBinding -Thumbprint $c.Thumbprint -Service 'rdp' -Endpoint 'RDP-Tcp')
        (Get-Finding (New-CertInventoryReport -Hosts @($h)) 'BINDING_NO_PRIVATE_KEY').Severity | Should -Be 'critical'
    }

    It 'notes self-signed certificates bound to HTTP.sys but not the RDP default' {
        $web = New-TestRecord @{ SelfIssued = $true }
        $rdp = New-TestRecord @{ SelfIssued = $true; Store = 'Remote Desktop'; Subject = 'CN=WEB01' }
        $h = New-TestHost -Certificates @($web, $rdp) -Bindings @(
            (New-TestBinding -Thumbprint $web.Thumbprint),
            (New-TestBinding -Thumbprint $rdp.Thumbprint -Service 'rdp' -Endpoint 'RDP-Tcp' -Store 'Remote Desktop'))
        $f = Get-Finding (New-CertInventoryReport -Hosts @($h)) 'SELF_SIGNED_BOUND'
        $f.Count | Should -Be 1
        $f[0].Thumbprint | Should -Be $web.Thumbprint
    }
}

Describe 'Host and fleet level' {
    It 'reports failed hosts as UNKNOWN (exit 3) unless something is critical' {
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @(New-TestRecord @{ NotAfterDays = 20 })) -Failures @([pscustomobject]@{ ComputerName = 'db01'; Error = 'WinRM cannot complete the operation' })
        (Get-Finding $r 'HOST_FAILED').Severity | Should -Be 'unknown'
        $r.Summary.FailedHosts | Should -Be 1
        $r.Summary.Hosts | Should -Be 2
        $r.ExitCode | Should -Be 3
        $r.Status | Should -Be 'UNKNOWN'
    }

    It 'turns partial collection errors into warnings' {
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Errors @('store CA: Access is denied.'))
        (Get-Finding $r 'COLLECTION_PARTIAL').Severity | Should -Be 'warning'
        $r.ExitCode | Should -Be 1
    }

    It 'flags stale offline collections' {
        $r = New-CertInventoryReport -Hosts @(New-TestHost -CollectedDaysAgo 10) -MaxCollectionAgeDays 7
        (Get-Finding $r 'STALE_COLLECTION').Count | Should -Be 1
    }

    It 'reports the same certificate and key on several hosts' {
        $c = New-TestRecord @{ Subject = 'CN=*.corp.example.com'; DnsNames = @('*.corp.example.com') }
        $c2 = $c.PSObject.Copy(); $c2.KeyExportable = $true
        $r = New-CertInventoryReport -Hosts @((New-TestHost -Name 'web01' -Certificates @($c)), (New-TestHost -Name 'web02' -Certificates @($c2)))
        $f = Get-Finding $r 'SHARED_KEY'
        $f.Count | Should -Be 1
        $f[0].ComputerName | Should -Be '(fleet)'
        $f[0].Message | Should -Match 'on 2 hosts: web01, web02 \(exportable'
    }

    It 'counts certificates per template' {
        $a = New-TestRecord; $b = New-TestRecord @{ Subject = 'CN=b' }; $c = New-TestRecord @{ TemplateName = $null; TemplateOid = $null; Subject = 'CN=c' }
        $t = (New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($a, $b, $c))).Summary.Templates
        @($t).Count | Should -Be 1
        $t[0].Template | Should -Be 'CorpWebServer'
        $t[0].Count | Should -Be 2
    }

    It 'orders findings by severity' {
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @(
                (New-TestRecord @{ KeyExportable = $true; Subject = 'CN=a' }),
                (New-TestRecord @{ NotAfterDays = 2; Subject = 'CN=b' }),
                (New-TestRecord @{ KeyError = 'denied'; Subject = 'CN=c' })))
        @($r.Findings.Severity) | Should -Be @('critical', 'warning', 'info')
    }
}

Describe 'Exit code' {
    It 'follows CRITICAL > UNKNOWN > WARNING > OK' {
        Get-ReportExitCode -Findings @() | Should -Be 0
        Get-ReportExitCode -Findings @([pscustomobject]@{ Severity = 'info' }) | Should -Be 0
        Get-ReportExitCode -Findings @([pscustomobject]@{ Severity = 'warning' }) | Should -Be 1
        Get-ReportExitCode -Findings @([pscustomobject]@{ Severity = 'warning' }) -FailedHosts 1 | Should -Be 3
        Get-ReportExitCode -Findings @([pscustomobject]@{ Severity = 'critical' }) -FailedHosts 1 | Should -Be 2
    }
}

Describe 'Output' {
    BeforeAll {
        $script:sample = New-TestRecord @{ NotAfterDays = 5; Subject = "CN=evil`e[31m.example.com" }
        $script:report = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($script:sample, (New-TestRecord @{ KeyError = 'denied'; Subject = 'CN=x' })))
    }

    It 'produces JSON with ISO 8601 dates and arrays preserved' {
        $j = ConvertTo-CertInventoryJson -Report $script:report
        $j | Should -Match '"NotAfter": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"'
        $j | Should -Match '"BoundTo": \[\]'
        $o = $j | ConvertFrom-Json
        $o.ExitCode | Should -Be 2
        $o.Summary.Critical | Should -Be 1
        $o.Hosts[0].Certificates.Count | Should -Be 2
        @($o.Hosts[0].Certificates[0].DnsNames).Count | Should -Be 1
    }

    It 'neutralises control characters in the text report' {
        $text = (Format-CertInventoryText -Report $script:report) -join "`n"
        $text | Should -Not -Match "`e"
        $text | Should -Match 'CN=evil\\x1B\[31m'
        $text | Should -Match '^cert-inventory 0\.1\.0: CRITICAL - 1 host\(s\), 0 failed, 2 certificate\(s\)'
        $text | Should -Match '1 informational finding\(s\) hidden'
    }

    It 'lists informational findings and the inventory on request' {
        $text = (Format-CertInventoryText -Report $script:report -ShowInfo -Inventory) -join "`n"
        $text | Should -Match 'KEY_UNREADABLE'
        $text | Should -Match 'HOST\s+STORE\s+DAYS'
        $text | Should -Match 'Certificates per ADCS template'
    }

    It 'produces one CSV row per certificate with finding codes and formula-safe cells' {
        $c = New-TestRecord @{ FriendlyName = 'x'; Subject = '=HYPERLINK("http://x")' }
        $r = New-CertInventoryReport -Hosts @(New-TestHost -Certificates @($c, (New-TestRecord @{ NotAfterDays = 3; Subject = 'CN=y' })))
        $rows = @(ConvertTo-CertInventoryCsvRow -Report $r)
        $rows.Count | Should -Be 2
        ($rows | Where-Object Subject -Like "'=*").Count | Should -Be 1
        ($rows | Where-Object Subject -EQ 'CN=y').Findings | Should -Be 'EXPIRING'
    }

    It 'neutralises CSV formula prefixes' {
        ConvertTo-CsvSafeValue '+cmd' | Should -Be "'+cmd"
        ConvertTo-CsvSafeValue '@SUM(1)' | Should -Be "'@SUM(1)"
        ConvertTo-CsvSafeValue 'CN=ok' | Should -Be 'CN=ok'
        ConvertTo-CsvSafeValue $null | Should -Be ''
    }
}

Describe 'Import-CertInventoryCollection' {
    It 'loads single objects and arrays from files and directories' {
        $dir = Join-Path $TestDrive 'col'
        $null = New-Item -ItemType Directory -Path $dir
        New-TestHost -Name 'a.example.com' -Certificates @(New-TestRecord) | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $dir 'a.json')
        ConvertTo-Json -Depth 8 -InputObject @((New-TestHost -Name 'b.example.com'), (New-TestHost -Name 'c.example.com')) | Set-Content (Join-Path $dir 'bc.json')
        $h = @(Import-CertInventoryCollection -Path $dir)
        $h.Count | Should -Be 3
        @($h.Target | Sort-Object) | Should -Be @('a.example.com', 'b.example.com', 'c.example.com')
        $r = New-CertInventoryReport -Hosts $h
        $r.Summary.Certificates | Should -Be 1
    }

    It 'rejects files that are not collections' {
        $f = Join-Path $TestDrive 'bad.json'
        '{"foo": 1}' | Set-Content $f
        { Import-CertInventoryCollection -Path $f } | Should -Throw '*not a cert-inventory collection*'
        'not json' | Set-Content $f
        { Import-CertInventoryCollection -Path $f } | Should -Throw '*invalid JSON*'
    }
}

Describe 'Read-ComputerList' {
    It 'reads plain lists with comments and blank lines' {
        $f = Join-Path $TestDrive 'hosts.txt'
        "# web tier`nweb01`n`n web02  # second`nweb01`n" | Set-Content $f
        Read-ComputerList -Path $f | Should -Be @('web01', 'web02', 'web01')
    }

    It 'reads AD CSV exports' {
        $f = Join-Path $TestDrive 'ad.csv'
        "Name,DNSHostName,Enabled`nWEB01,web01.corp.example.com,True`nWEB02,web02.corp.example.com,True" | Set-Content $f
        Read-ComputerList -Path $f | Should -Be @('web01.corp.example.com', 'web02.corp.example.com')
    }

    It 'fails clearly for a missing file or an unknown CSV layout' {
        { Read-ComputerList -Path (Join-Path $TestDrive 'nope.txt') } | Should -Throw '*not found*'
        $f = Join-Path $TestDrive 'odd.csv'
        "a,b`n1,2" | Set-Content $f
        { Read-ComputerList -Path $f } | Should -Throw '*column*'
    }
}

Describe 'Invoke-CertInventoryCollection (WinRM orchestration)' {
    BeforeAll {
        $script:sessionOption = New-Object System.Management.Automation.Remoting.PSSessionOption
    }

    It 'passes WinRM options, deduplicates targets and maps errors to hosts' {
        Mock -ModuleName CertInventory Test-WinRmSupported { $true }
        Mock -ModuleName CertInventory New-CollectorSessionOption { $script:sessionOption }
        Mock -ModuleName CertInventory Invoke-RemoteCollector {
            $o = New-TestHost -Name 'WEB01'
            $o | Add-Member -NotePropertyName PSComputerName -NotePropertyValue 'web01' -Force
            $err = New-Object System.Management.Automation.ErrorRecord (
                (New-Object System.Exception 'Connecting to remote server db01 failed: WinRM cannot complete the operation.'),
                'CannotConnect,PSSessionStateBroken', 'OpenError', 'db01')
            [pscustomobject]@{ Results = @($o); Errors = @($err) }
        }
        $cred = New-Object System.Management.Automation.PSCredential ('CORP\audit', (New-Object System.Security.SecureString))
        $r = Invoke-CertInventoryCollection -ComputerName 'web01', 'WEB01', 'db01', 'app01' -Credential $cred -UseSSL -Port 5986 -Authentication Kerberos -ThrottleLimit 8 -TimeoutSeconds 30 -StoreName 'My' -SkipKeyInspection

        Should -Invoke -ModuleName CertInventory Invoke-RemoteCollector -Times 1 -Exactly -ParameterFilter {
            $p = $Parameters
            ($p.ComputerName -join ',') -eq 'web01,db01,app01' -and $p.UseSSL -and $p.Port -eq 5986 -and $p.Authentication -eq 'Kerberos' -and
            $p.ThrottleLimit -eq 8 -and $p.Credential.UserName -eq 'CORP\audit' -and $p.FilePath -like '*Collector.ps1' -and
            ($p.ArgumentList[0] -join ',') -eq 'My' -and $p.ArgumentList[1] -eq $false
        }
        Should -Invoke -ModuleName CertInventory New-CollectorSessionOption -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -eq 30 }
        @($r.Hosts).Count | Should -Be 1
        $r.Hosts[0].Target | Should -Be 'web01'
        @($r.Failures).Count | Should -Be 2
        ($r.Failures | Where-Object ComputerName -EQ 'db01').Error | Should -Match 'WinRM cannot complete'
        ($r.Failures | Where-Object ComputerName -EQ 'app01').Error | Should -Be 'no data returned'
    }

    It 'collects the local computer without WinRM (or fails cleanly off Windows)' {
        Mock -ModuleName CertInventory Invoke-RemoteCollector { throw 'should not be called' }
        $r = Invoke-CertInventoryCollection -ComputerName 'localhost'
        Should -Invoke -ModuleName CertInventory Invoke-RemoteCollector -Times 0
        if (-not $IsWindows) {
            $r.Failures[0].Error | Should -Be 'local collection requires Windows'
        }
    }

    It 'reports remote targets as failed where WinRM is unavailable' {
        Mock -ModuleName CertInventory Test-WinRmSupported { $false }
        Mock -ModuleName CertInventory Invoke-RemoteCollector { throw 'should not be called' }
        $r = Invoke-CertInventoryCollection -ComputerName 'web01', 'web02'
        @($r.Failures).Count | Should -Be 2
        $r.Failures[0].Error | Should -Match 'requires Windows'
    }

    It 'maps errors through OriginInfo-less records by message' {
        $e = New-Object System.Management.Automation.ErrorRecord ((New-Object System.Exception '[srv-02.corp.example.com] Connecting to remote server srv-02.corp.example.com failed'), 'x', 'OpenError', $null)
        Get-ErrorTarget -ErrorRecord $e -Candidates @('srv-02', 'srv-02.corp.example.com') | Should -Be 'srv-02.corp.example.com'
    }
}

Describe 'ConvertTo-UtcDate' {
    It 'parses collector timestamps as UTC' {
        $d = ConvertTo-UtcDate '2026-01-02T03:04:05Z'
        $d.Kind | Should -Be 'Utc'
        $d.Hour | Should -Be 3
    }

    It 'rejects garbage' {
        { ConvertTo-UtcDate 'yesterday-ish' } | Should -Throw '*invalid date*'
    }
}

# Integration tests against the real Windows certificate stores. They run on
# Windows only (the CI windows-latest runner is elevated); elsewhere they are
# skipped. Test certificates are created in LocalMachine\My and removed
# afterwards.

BeforeDiscovery {
    $script:OnWindows = ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
    $script:IsAdmin = $false
    if ($script:OnWindows) {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $script:IsAdmin = (New-Object System.Security.Principal.WindowsPrincipal $id).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $script:Skip = -not ($script:OnWindows -and $script:IsAdmin)
}

Describe 'Collector on Windows' -Tag 'Windows' -Skip:$script:Skip {
    BeforeAll {
        $script:Collector = Join-Path $PSScriptRoot '../src/Collector.ps1'
        $script:Ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $script:Tag = 'cert-inventory-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        # The PKI module is used through Windows PowerShell 5.1, where it is native.
        $create = "`$e = New-SelfSignedCertificate -Subject 'CN=$($script:Tag)-exp' -DnsName '$($script:Tag)-exp.example.test' -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(10); " +
            "`$l = New-SelfSignedCertificate -Subject 'CN=$($script:Tag)-locked' -DnsName '$($script:Tag)-locked.example.test' -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy NonExportable -KeyLength 2048; " +
            "`$e.Thumbprint; `$l.Thumbprint"
        $tp = @(& $script:Ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $create)
        if ($LASTEXITCODE -ne 0 -or $tp.Count -lt 2) { throw "could not create test certificates: $($tp -join ' ')" }
        $script:ExportableThumbprint = $tp[-2].Trim().ToUpperInvariant()
        $script:LockedThumbprint = $tp[-1].Trim().ToUpperInvariant()
    }

    AfterAll {
        foreach ($t in @($script:ExportableThumbprint, $script:LockedThumbprint)) {
            if ($t) { & $script:Ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Remove-Item -LiteralPath 'Cert:\LocalMachine\My\$t' -DeleteKey -ErrorAction SilentlyContinue" }
        }
    }

    It 'collects the stores and reads the export policy of the private keys (PowerShell 7)' {
        $r = & $script:Collector -StoreName 'My', 'Root'
        $exp = @($r.Certificates | Where-Object Thumbprint -EQ $script:ExportableThumbprint)
        $lock = @($r.Certificates | Where-Object Thumbprint -EQ $script:LockedThumbprint)
        $exp.Count | Should -Be 1
        $lock.Count | Should -Be 1
        $exp[0].HasPrivateKey | Should -BeTrue
        $exp[0].KeyExportable | Should -BeTrue
        $lock[0].KeyExportable | Should -BeFalse
        $exp[0].KeyStorage | Should -Be 'Software'
        $exp[0].DnsNames | Should -Contain "$($script:Tag)-exp.example.test"
        @($r.Certificates | Where-Object Store -EQ 'Root').Count | Should -BeGreaterThan 0
        $r.OS | Should -Match 'Windows'
    }

    It 'runs unchanged under Windows PowerShell 5.1, the runtime used on remote hosts' {
        $ps51 = $script:Ps51
        $cmd = "& '$($script:Collector)' -StoreName My | ConvertTo-Json -Depth 6"
        $json = & $ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd
        $LASTEXITCODE | Should -Be 0
        $r = ($json -join "`n") | ConvertFrom-Json
        $exp = @($r.Certificates | Where-Object Thumbprint -EQ $script:ExportableThumbprint)
        $exp.Count | Should -Be 1
        $exp[0].KeyExportable | Should -BeTrue
        @($r.Certificates | Where-Object Thumbprint -EQ $script:LockedThumbprint)[0].KeyExportable | Should -BeFalse
        $r.PSVersion | Should -Match '^5\.1'
    }

    It 'produces an analysable report for the local computer through the CLI' {
        $cli = Join-Path $PSScriptRoot '../cert-inventory.ps1'
        $pwsh = (Get-Process -Id $PID).Path
        $out = & $pwsh -NoProfile -NonInteractive -File $cli -ComputerName localhost -StoreName My -Json
        $LASTEXITCODE | Should -BeIn 0, 1, 2
        $j = ($out -join "`n") | ConvertFrom-Json
        $f = @($j.Findings | Where-Object Thumbprint -EQ $script:ExportableThumbprint | ForEach-Object Code)
        $f | Should -Contain 'EXPIRING'
        $f | Should -Contain 'EXPORTABLE_KEY'
    }
}

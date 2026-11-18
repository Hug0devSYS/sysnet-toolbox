BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Cli = Join-Path $PSScriptRoot '../cert-inventory.ps1'
    $script:Pwsh = (Get-Process -Id $PID).Path

    function Invoke-Cli {
        param([string[]] $Arguments)
        $out = & $script:Pwsh -NoProfile -NonInteractive -File $script:Cli @Arguments 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (@($out | ForEach-Object { [string]$_ }) -join "`n") }
    }

    function Save-Collection {
        param([string] $Name, [object[]] $HostData)
        $p = Join-Path $TestDrive $Name
        ConvertTo-Json -InputObject $HostData -Depth 8 | Set-Content -LiteralPath $p -Encoding UTF8
        return $p
    }
}

Describe 'cert-inventory.ps1 command line' {
    It 'prints its version' {
        $r = Invoke-Cli -Arguments @('-Version')
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match '^cert-inventory 0\.1\.0'
    }

    It 'exits 0 with a clean text report' {
        $p = Save-Collection 'ok.json' @(New-TestHost -Certificates @(New-TestRecord))
        $r = Invoke-Cli -Arguments @('-InputPath', $p)
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'cert-inventory 0\.1\.0: OK - 1 host\(s\)'
        $r.Output | Should -Match 'No findings\.'
    }

    It 'exits 1 on warnings and 2 on critical findings' {
        $w = Save-Collection 'warn.json' @(New-TestHost -Certificates @(New-TestRecord @{ NotAfterDays = 20 }))
        (Invoke-Cli -Arguments @('-InputPath', $w)).ExitCode | Should -Be 1
        $c = Save-Collection 'crit.json' @(New-TestHost -Certificates @(New-TestRecord @{ NotAfterDays = 2 }))
        (Invoke-Cli -Arguments @('-InputPath', $c)).ExitCode | Should -Be 2
        (Invoke-Cli -Arguments @('-InputPath', $c, '-CriticalDays', '0', '-WarningDays', '0')).ExitCode | Should -Be 0
    }

    It 'writes JSON, a CSV inventory and an output file' {
        $p = Save-Collection 'json.json' @(New-TestHost -Certificates @((New-TestRecord), (New-TestRecord @{ NotAfterDays = 10; Subject = 'CN=b' })))
        $csv = Join-Path $TestDrive 'inv.csv'
        $out = Join-Path $TestDrive 'report.json'
        $r = Invoke-Cli -Arguments @('-InputPath', $p, '-Json', '-CsvPath', $csv, '-OutFile', $out)
        $r.ExitCode | Should -Be 2
        $j = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
        $j.Tool | Should -Be 'cert-inventory'
        $j.Status | Should -Be 'CRITICAL'
        $j.Findings[0].Code | Should -Be 'EXPIRING'
        $rows = @(Import-Csv -LiteralPath $csv)
        $rows.Count | Should -Be 2
        ($rows | Where-Object Subject -EQ 'CN=b').Findings | Should -Be 'EXPIRING'
    }

    It 'warns about stale collections by default when analysing saved files' {
        $p = Save-Collection 'stale.json' @(New-TestHost -CollectedDaysAgo 30 -Certificates @(New-TestRecord))
        $r = Invoke-Cli -Arguments @('-InputPath', $p)
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match 'STALE_COLLECTION'
        (Invoke-Cli -Arguments @('-InputPath', $p, '-MaxCollectionAgeDays', '0')).ExitCode | Should -Be 0
    }

    It 'exits 3 with a message on usage and input errors' {
        $r = Invoke-Cli -Arguments @('-InputPath', (Join-Path $TestDrive 'missing.json'))
        $r.ExitCode | Should -Be 3
        $r.Output | Should -Match '^cert-inventory: '
        $c = Save-Collection 'x.json' @(New-TestHost)
        (Invoke-Cli -Arguments @('-InputPath', $c, '-WarningDays', '5', '-CriticalDays', '10')).ExitCode | Should -Be 3
    }

    It 'shows help through Get-Help' {
        $help = Get-Help $script:Cli -Full | Out-String
        $help | Should -Match 'ComputerListPath'
        $help | Should -Match 'Exit codes'
    }
}

@{
    RootModule           = 'src/CertInventory.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '3f6f0f55-7d0e-4c1b-9a43-5f2a0c9e8b71'
    Author               = 'Hug0devSYS'
    CompanyName          = 'Hug0devSYS'
    Copyright            = '(c) Hug0devSYS. MIT License.'
    Description          = 'Inventory and audit of Windows machine certificate stores over WinRM: expirations with renewal awareness, broken bindings, exportable keys, weak keys, ADCS templates.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    # No external module dependencies. Development/CI only: PSScriptAnalyzer >= 1.21, Pester >= 5.5.
    RequiredModules      = @()
    FunctionsToExport    = @(
        'Get-CertInventoryVersion', 'Get-CertInventoryDefaultStore', 'Read-ComputerList', 'Test-LocalComputerName',
        'Invoke-CertInventoryCollection', 'Import-CertInventoryCollection', 'New-CertInventoryReport',
        'ConvertTo-CertInventoryJson', 'ConvertTo-CertInventoryCsvRow', 'Format-CertInventoryText',
        'Get-ErrorTarget', 'ConvertTo-UtcDate', 'ConvertTo-SafeText', 'ConvertTo-CsvSafeValue', 'Get-ReportExitCode'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('PKI', 'Certificates', 'ADCS', 'WinRM', 'Audit', 'Inventory')
            LicenseUri = 'https://github.com/Hug0devSYS/sysnet-toolbox/blob/main/LICENSE'
            ProjectUri = 'https://github.com/Hug0devSYS/sysnet-toolbox/tree/main/tools/cert-inventory'
        }
    }
}

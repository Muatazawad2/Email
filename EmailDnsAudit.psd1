@{
    RootModule = 'EmailDnsAudit.psm1'
    ModuleVersion = '1.0.0'
    GUID = '8e3a5938-cb6e-4fd1-9c74-8d08e1d8c1e0'
    Author = 'Muataz Awad'
    CompanyName = 'Community'
    Copyright = '(c) Muataz Awad. All rights reserved.'
    Description = 'EmailDnsAudit scans domains for MX, SPF, DMARC, and DKIM records and generates reports.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-EmailDnsAudit')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('DNS', 'Email', 'MX', 'SPF', 'DMARC', 'DKIM', 'Audit', 'Security')
            ReleaseNotes = 'Initial release of EmailDnsAudit module.'
        }
    }
}

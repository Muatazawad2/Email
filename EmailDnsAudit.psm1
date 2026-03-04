function Invoke-EmailDnsAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InputFile,

        [Parameter(Mandatory = $false)]
        [string[]]$DomainInput,

        [Parameter(Mandatory = $false)]
        [string]$OutputCsv,

        [Parameter(Mandatory = $false)]
        [string]$OutputHtml,

        [Parameter(Mandatory = $false)]
        [string]$OutputJson,

        [Parameter(Mandatory = $false)]
        [switch]$ShowAll,

        [Parameter(Mandatory = $false)]
        [switch]$PromptForFile,

        [Parameter(Mandatory = $false)]
        [switch]$UseExchangeAcceptedDomains,

        [Parameter(Mandatory = $false)]
        [string]$ExchangeOrganization,

        [Parameter(Mandatory = $false)]
        [bool]$ExcludeOnMicrosoftDomains = $true,

        [Parameter(Mandatory = $false)]
        [string[]]$DkimSelectors,

        [Parameter(Mandatory = $false)]
        [string]$DnsServer,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 5,

        [Parameter(Mandatory = $false)]
        [bool]$ShowProgress = $true,

        [Parameter(Mandatory = $false)]
        [string]$DeveloperName = 'Muataz Awad',

        [Parameter(Mandatory = $false)]
        [switch]$FilterMxNotMicrosoft,

        [Parameter(Mandatory = $false)]
        [switch]$FilterMissingAnyCore,

        [Parameter(Mandatory = $false)]
        [switch]$FilterMissingAllCore,

        [Parameter(Mandatory = $false)]
        [ValidateSet('MX', 'SPF', 'DMARC', 'DKIM')]
        [string[]]$FilterMissingAnyOf,

        [Parameter(Mandatory = $false)]
        [ValidateSet('MX', 'SPF', 'DMARC', 'DKIM')]
        [string[]]$FilterMissingAllOf,

        [Parameter(Mandatory = $false)]
        [switch]$NoOpenHtml
    )

    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'EmailDnsAudit.ps1'
    if (-not (Test-Path -Path $scriptPath)) {
        throw "Implementation script not found: $scriptPath"
    }

    & $scriptPath @PSBoundParameters
}

Export-ModuleMember -Function 'Invoke-EmailDnsAudit'

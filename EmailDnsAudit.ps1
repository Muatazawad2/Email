<#
.SYNOPSIS
EmailDnsAudit scans domains for email DNS records (MX, SPF, DMARC, and DKIM) and generates audit reports.

.DESCRIPTION
EmailDnsAudit can load domains from direct input, a file, or Exchange Online accepted domains.
It checks core email DNS controls and produces console output plus optional HTML, CSV, and JSON reports.

.NOTES
Developer: Muataz Awad
#>

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

function Get-InputFilePathFromConsole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StartDirectory
    )

    Write-Host 'Choose an input option:' -ForegroundColor Yellow
    Write-Host '[1] Type domain(s) directly'
    Write-Host '[2] Sign in to Exchange Online and import accepted domains'
    Write-Host '[3] Browse and select a domains text file (.txt)'

    $selection = Read-Host 'Enter 1, 2, or 3'

    if ($selection -eq '1') {
        return '__DIRECT_DOMAIN__'
    }

    if ($selection -eq '2') {
        return '__EXO_DOMAINS__'
    }

    if ($selection -eq '3') {
        return '__POPUP_FILE__'
    }

    Write-Warning 'Invalid selection. Please choose 1, 2, or 3.'
    return ''
}

function Get-InputFilePathFromPopup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StartDirectory
    )

    $windowsPowerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $windowsPowerShell) {
        $helperScriptPath = Join-Path $env:TEMP ('dns-popup-' + [guid]::NewGuid().ToString() + '.ps1')
        $helperResultPath = Join-Path $env:TEMP ('dns-popup-' + [guid]::NewGuid().ToString() + '.txt')

        $helperScriptTemplate = @'
Add-Type -AssemblyName System.Windows.Forms

$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.StartPosition = 'CenterScreen'
$owner.ShowInTaskbar = $false
$owner.FormBorderStyle = 'FixedToolWindow'
$owner.Opacity = 0
$owner.Width = 1
$owner.Height = 1
$owner.Show()
$owner.Activate()

$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select domains text file'
$dialog.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
$dialog.Multiselect = $false
if (Test-Path '__STARTDIR__') {
    $dialog.InitialDirectory = '__STARTDIR__'
}
$selection = $dialog.ShowDialog($owner)
$owner.Close()
$owner.Dispose()
if ($selection -eq [System.Windows.Forms.DialogResult]::OK) {
    Set-Content -Path '__RESULTPATH__' -Value $dialog.FileName -Encoding UTF8
}
'@

        $helperScript = $helperScriptTemplate.Replace('__STARTDIR__', $StartDirectory.Replace("'", "''")).Replace('__RESULTPATH__', $helperResultPath.Replace("'", "''"))
        Set-Content -Path $helperScriptPath -Value $helperScript -Encoding UTF8

        Write-Host 'Opening file picker popup...' -ForegroundColor Yellow
        $pickerProcess = Start-Process -FilePath $windowsPowerShell -ArgumentList @('-NoProfile', '-STA', '-File', $helperScriptPath) -PassThru -WindowStyle Hidden
        $pickerProcess.WaitForExit()

        $selectedPath = ''
        if (Test-Path $helperResultPath) {
            $selectedPath = (Get-Content -Path $helperResultPath -Raw).Trim()
        }

        Remove-Item -Path $helperScriptPath -ErrorAction SilentlyContinue
        Remove-Item -Path $helperResultPath -ErrorAction SilentlyContinue

        if ($selectedPath) {
            return $selectedPath
        }
    }

    Write-Warning 'Popup file picker did not return a file. Please enter the path manually.'
    $manualPath = Read-Host 'Enter the full path to your domains text file'
    return $manualPath.Trim()
}

function Get-DomainInputFromConsole {
    $rawDomainInput = Read-Host 'Enter one or more domains (comma-separated)'
    $domains = $rawDomainInput -split ',' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }

    return @($domains)
}

function Get-ExchangeAcceptedDomains {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Organization
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "ExchangeOnlineManagement module not found. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $connectParams = @{
        ShowBanner = $false
    }

    if ($Organization) {
        $connectParams.Organization = $Organization
    }

    Connect-ExchangeOnline @connectParams | Out-Null
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        return @(
            $acceptedDomains |
                ForEach-Object {
                    $domainName = $null
                    if ($_.DomainName) {
                        $domainName = [string]$_.DomainName
                    }
                    elseif ($_.Name) {
                        $domainName = [string]$_.Name
                    }

                    if ($domainName) {
                        $isDefault = $false
                        if ($null -ne $_.Default) {
                            $isDefault = [bool]$_.Default
                        }
                        elseif ($null -ne $_.IsDefault) {
                            $isDefault = [bool]$_.IsDefault
                        }

                        [PSCustomObject]@{
                            Domain    = $domainName
                            IsDefault = $isDefault
                        }
                    }
                } |
                Where-Object { $_ -and $_.Domain }
        )
    }
    finally {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}

function Confirm-SelectedFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedPath
    )

    Write-Host "Selected file: $SelectedPath" -ForegroundColor Cyan
    $confirm = Read-Host 'Use this file? [Y/n]'
    return ([string]::IsNullOrWhiteSpace($confirm) -or $confirm -match '^(y|yes)$')
}

function Get-InputFilePath {
    $startDirectory = (Get-Location).Path
    return (Get-InputFilePathFromConsole -StartDirectory $startDirectory)
}

if ((-not $DomainInput -or $DomainInput.Count -eq 0) -and ($PromptForFile -or -not $InputFile)) {
    $InputFile = Get-InputFilePath
}

if ($InputFile -eq '__POPUP_FILE__') {
    $InputFile = Get-InputFilePathFromPopup -StartDirectory (Get-Location).Path
}

if ($InputFile -eq '__DIRECT_DOMAIN__') {
    $DomainInput = Get-DomainInputFromConsole
    $InputFile = $null
}

if ($InputFile -eq '__EXO_DOMAINS__') {
    $UseExchangeAcceptedDomains = $true
    $InputFile = $null
}

$defaultDomainDisplay = $null

if ($UseExchangeAcceptedDomains) {
    Write-Host 'Signing in to Exchange Online and importing accepted domains...' -ForegroundColor Yellow
    try {
        $exchangeDomains = @(Get-ExchangeAcceptedDomains -Organization $ExchangeOrganization)

        if ($ExcludeOnMicrosoftDomains) {
            $exchangeDomains = @($exchangeDomains | Where-Object { $_.Domain -notmatch '\.onmicrosoft\.com$' })
        }

        $defaultDomainDisplay = @(
            $exchangeDomains |
                Where-Object { $_.IsDefault } |
                Select-Object -First 1 -ExpandProperty Domain
        ) | Select-Object -First 1

        $domains = @(
            $exchangeDomains |
                ForEach-Object { $_.Domain.Trim() } |
                Where-Object { $_ }
        )
    }
    catch {
        Write-Error "Exchange Online domain import failed: $($_.Exception.Message)"
        exit 1
    }
    $inputSourceDisplay = if ($ExchangeOrganization) { "Exchange Online org: $ExchangeOrganization" } else { 'Exchange Online' }
    if ($ExcludeOnMicrosoftDomains) {
        $inputSourceDisplay += ' | excluding *.onmicrosoft.com'
    }
}
elseif ($DomainInput -and $DomainInput.Count -gt 0) {
    $domains = @(
        $DomainInput |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
    $inputSourceDisplay = 'Direct domain input'
}
else {
    if (-not $InputFile -or -not (Test-Path -Path $InputFile)) {
        Write-Error "Input file not found or not provided: $InputFile"
        exit 1
    }

    $domains = @(
        Get-Content -Path $InputFile |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') }
    )
    $inputSourceDisplay = $InputFile
}

$domains = @($domains)

if (-not $domains) {
    Write-Warning "No domains found for source: $inputSourceDisplay"
    exit 0
}

function Get-DnsRecordsByType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Type
    )

    $queryParams = @{
        Name         = $Name
        Type         = $Type
        ErrorAction  = 'Stop'
        QuickTimeout = $true
    }

    if ($DnsServer) {
        $queryParams.Server = $DnsServer
    }

    $maxAttempts = 2
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return @(Resolve-DnsName @queryParams)
        }
        catch {
            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Milliseconds 120
                continue
            }

            if ($_.Exception.Message -match 'timed out|timeout') {
                Write-Warning "DNS query timeout: $Name [$Type]"
            }

            return @()
        }
    }

    return @()
}

function Get-TxtValues {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $records = Get-DnsRecordsByType -Name $Name -Type 'TXT'
    $values = foreach ($record in $records) {
        if ($record.Strings) {
            (($record.Strings -join '')).Trim()
        }
    }

    return @($values | Where-Object { $_ })
}

function New-StatusBadge {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$State
    )

    if ($State) {
        return "<span class='badge ok'>Present</span>"
    }

    return "<span class='badge warn'>Missing</span>"
}

function Convert-ToHtmlRecordList {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Text
    )

    if (-not $Text) {
        return "<span class='muted'>-</span>"
    }

    $items = $Text -split '\s\|\s'
    $encodedItems = foreach ($item in $items) {
        "<div class='record-line'>" + [System.Net.WebUtility]::HtmlEncode($item) + "</div>"
    }

    return ($encodedItems -join '')
}

function Test-IsRecordMissing {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result,

        [Parameter(Mandatory = $true)]
        [string]$RecordName
    )

    switch ($RecordName.ToUpperInvariant()) {
        'MX' { return -not $Result.HasMX }
        'SPF' { return -not $Result.HasSPF }
        'DMARC' { return -not $Result.HasDMARC }
        'DKIM' { return -not $Result.HasDKIM }
        default { return $false }
    }
}

if (-not $DkimSelectors -or $DkimSelectors.Count -eq 0) {
    $DkimSelectors = @('selector1', 'selector2', 'default', 'google', 'k1', 'k2', 'mail', 'dkim')
}

$domainResults = @()
$mxDetails = @()

$scanTotalDomains = $domains.Count
for ($domainIndex = 0; $domainIndex -lt $scanTotalDomains; $domainIndex++) {
    $domain = $domains[$domainIndex]

    if ($ShowProgress) {
        $domainPercent = [math]::Round((($domainIndex) / [math]::Max($scanTotalDomains, 1)) * 100, 0)
        Write-Progress -Id 1 -Activity 'Scanning Email DNS Records' -Status "Domain $($domainIndex + 1)/${scanTotalDomains}: $domain" -PercentComplete $domainPercent
    }

    if ($ShowProgress) {
        Write-Host "Processing domain $($domainIndex + 1)/${scanTotalDomains}: $domain"
    }

    if ($ShowProgress) {
        Write-Progress -Id 2 -ParentId 1 -Activity "Querying $domain" -Status 'MX lookup' -PercentComplete 0
    }

    $mxRecords = Get-DnsRecordsByType -Name $domain -Type 'MX' |
        Where-Object { $_.Type -eq 'MX' } |
        Sort-Object -Property Preference

    if ($ShowProgress) {
        Write-Progress -Id 2 -ParentId 1 -Activity "Querying $domain" -Status 'SPF lookup' -PercentComplete 20
    }
    $spfValues = Get-TxtValues -Name $domain | Where-Object { $_ -match '^v=spf1\b' }

    if ($ShowProgress) {
        Write-Progress -Id 2 -ParentId 1 -Activity "Querying $domain" -Status 'DMARC lookup' -PercentComplete 35
    }
    $dmarcValues = Get-TxtValues -Name "_dmarc.$domain" | Where-Object { $_ -match '^v=DMARC1\b' }

    if ($ShowProgress) {
        Write-Progress -Id 2 -ParentId 1 -Activity "Querying $domain" -Status 'DKIM selector checks' -PercentComplete 60
    }
    $dkimMatches = foreach ($selector in $DkimSelectors) {
        $name = "$selector._domainkey.$domain"
        $values = Get-TxtValues -Name $name | Where-Object { $_ -match '^v=DKIM1\b' }
        foreach ($value in $values) {
            [PSCustomObject]@{
                Selector = $selector
                Value    = $value
            }
        }
    }

    if ($ShowProgress) {
        Write-Progress -Id 2 -ParentId 1 -Activity "Querying $domain" -Status 'Finalizing domain results' -PercentComplete 90
    }

    $hasMx = $mxRecords.Count -gt 0
    $hasSpf = $spfValues.Count -gt 0
    $hasDmarc = $dmarcValues.Count -gt 0
    $hasDkim = $dkimMatches.Count -gt 0
    $mxPointsToEop = $false

    if ($hasMx) {
        $mxPointsToEop = @($mxRecords | Where-Object { $_.NameExchange -match '\.mail\.protection\.outlook\.com\.?$' }).Count -gt 0
    }

    if ($hasMx) {
        foreach ($mx in $mxRecords) {
            $mxDetails += [PSCustomObject]@{
                Domain     = $domain
                Preference = $mx.Preference
                Exchange   = $mx.NameExchange
            }
        }
    }
    else {
        $mxDetails += [PSCustomObject]@{
            Domain     = $domain
            Preference = $null
            Exchange   = ''
        }
    }

    $mxSummary = if ($hasMx) {
        (($mxRecords | ForEach-Object { "pref=$($_.Preference) $($_.NameExchange)" }) -join ' | ')
    }
    else {
        ''
    }

    $dkimRecordText = if ($hasDkim) {
        (($dkimMatches | ForEach-Object { "$($_.Selector): $($_.Value)" }) -join ' | ')
    }
    else {
        ''
    }

    $score = @($hasMx, $hasSpf, $hasDmarc, $hasDkim | Where-Object { $_ }).Count
    $overallStatus = if ($score -ge 4) { 'Strong' } elseif ($score -ge 2) { 'Moderate' } else { 'Needs Attention' }

    $missingControls = @()
    if (-not $hasMx) { $missingControls += 'MX' }
    if (-not $hasSpf) { $missingControls += 'SPF' }
    if (-not $hasDmarc) { $missingControls += 'DMARC' }
    if (-not $hasDkim) { $missingControls += 'DKIM' }

    $domainResults += [PSCustomObject]@{
        Domain        = $domain
        HasMX         = $hasMx
        HasSPF        = $hasSpf
        HasDMARC      = $hasDmarc
        HasDKIM       = $hasDkim
        MxPointsToEOP = $mxPointsToEop
        MX            = $mxSummary
        SPF           = $spfValues -join ' | '
        DMARC         = $dmarcValues -join ' | '
        DKIMSelectors = ($dkimMatches | Select-Object -ExpandProperty Selector -Unique) -join ', '
        DKIMRecords   = $dkimRecordText
        Missing       = $missingControls -join ', '
        OverallStatus = $overallStatus
    }

    if ($ShowProgress) {
        Write-Progress -Id 2 -Activity "Querying $domain" -Completed
    }
}

if ($ShowProgress) {
    Write-Progress -Id 1 -Activity 'Scanning Email DNS Records' -Completed
}

$allResults = $domainResults | Sort-Object Domain
$consoleResults = $allResults
$activeFilters = @()

if ($FilterMxNotMicrosoft) {
    $consoleResults = @($consoleResults | Where-Object { -not $_.MxPointsToEOP })
    $activeFilters += 'MX not pointing to Microsoft'
}

if ($FilterMissingAnyCore) {
    $consoleResults = @($consoleResults | Where-Object { -not $_.HasMX -or -not $_.HasSPF -or -not $_.HasDMARC -or -not $_.HasDKIM })
    $activeFilters += 'Missing any core record (MX/SPF/DMARC/DKIM)'
}

if ($FilterMissingAllCore) {
    $consoleResults = @($consoleResults | Where-Object { -not $_.HasMX -and -not $_.HasSPF -and -not $_.HasDMARC -and -not $_.HasDKIM })
    $activeFilters += 'Missing all core records (MX/SPF/DMARC/DKIM)'
}

if ($FilterMissingAnyOf -and $FilterMissingAnyOf.Count -gt 0) {
    $consoleResults = @($consoleResults | Where-Object {
        $result = $_
        @($FilterMissingAnyOf | Where-Object { Test-IsRecordMissing -Result $result -RecordName $_ }).Count -gt 0
    })
    $activeFilters += "Missing any of: $($FilterMissingAnyOf -join ', ')"
}

if ($FilterMissingAllOf -and $FilterMissingAllOf.Count -gt 0) {
    $consoleResults = @($consoleResults | Where-Object {
        $result = $_
        @($FilterMissingAllOf | Where-Object { Test-IsRecordMissing -Result $result -RecordName $_ }).Count -eq $FilterMissingAllOf.Count
    })
    $activeFilters += "Missing all of: $($FilterMissingAllOf -join ', ')"
}

if ($consoleResults.Count -eq 0) {
    Write-Warning 'No domains matched the selected filter(s).'
}

if ($ShowAll) {
    $consoleResults |
    Select-Object Domain, MxPointsToEOP, MX, SPF, DMARC, DKIMRecords, OverallStatus |
    Format-List
}
else {
    $consoleResults |
        Where-Object { $_.HasMX } |
        Select-Object Domain, HasMX, HasSPF, HasDMARC, HasDKIM, MxPointsToEOP, OverallStatus |
        Format-Table -AutoSize
}

if (-not $OutputHtml) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputHtml = Join-Path -Path (Get-Location) -ChildPath "email-dns-report-$timestamp.html"
}

$totalScannedDomains = $allResults.Count
$totalDomains = $consoleResults.Count
$domainsWithMx = ($consoleResults | Where-Object { $_.HasMX }).Count
$domainsWithSpf = ($consoleResults | Where-Object { $_.HasSPF }).Count
$domainsWithDmarc = ($consoleResults | Where-Object { $_.HasDMARC }).Count
$domainsWithDkim = ($consoleResults | Where-Object { $_.HasDKIM }).Count
$domainsMxNotMicrosoft = ($consoleResults | Where-Object { -not $_.MxPointsToEOP }).Count
$issuesOnly = $consoleResults | Where-Object { $_.Missing }

$domainSectionsHtml = @()
for ($i = 0; $i -lt $consoleResults.Count; $i++) {
    $record = $consoleResults[$i]
    $safeDomain = [System.Net.WebUtility]::HtmlEncode([string]$record.Domain)
    $safeSelectors = [System.Net.WebUtility]::HtmlEncode([string]$record.DKIMSelectors)
    $statusClass = if ($record.OverallStatus -eq 'Strong') { 'ok' } elseif ($record.OverallStatus -eq 'Moderate') { 'warn' } else { 'err' }
    $sectionId = "domain-section-$i"

    $domainSectionsHtml +=
    "<details class='domain-card domain-details' data-mx-eop='$($record.MxPointsToEOP.ToString().ToLower())' data-has-mx='$($record.HasMX.ToString().ToLower())' data-has-spf='$($record.HasSPF.ToString().ToLower())' data-has-dmarc='$($record.HasDMARC.ToString().ToLower())' data-has-dkim='$($record.HasDKIM.ToString().ToLower())'>" +
    "<summary class='domain-head'>" +
    "<h3>$safeDomain</h3>" +
    "<div class='domain-controls'><span class='badge $statusClass'>$($record.OverallStatus)</span><span class='collapse-hint'>Click to collapse/expand</span></div>" +
    "</summary>" +
    "<div class='record-grid' id='$sectionId'>" +
    "<div class='record-item'><div class='record-title'>MX</div><div class='record-content'>$(Convert-ToHtmlRecordList -Text $record.MX)</div></div>" +
    "<div class='record-item'><div class='record-title'>SPF</div><div class='record-content'>$(Convert-ToHtmlRecordList -Text $record.SPF)</div></div>" +
    "<div class='record-item'><div class='record-title'>DMARC</div><div class='record-content'>$(Convert-ToHtmlRecordList -Text $record.DMARC)</div></div>" +
    "<div class='record-item'><div class='record-title'>DKIM</div><div class='record-content'>$(Convert-ToHtmlRecordList -Text $record.DKIMRecords)</div></div>" +
    "<div class='record-item'><div class='record-title'>DKIM Selectors</div><div class='record-content'>$(if ($safeSelectors) { $safeSelectors } else { "<span class='muted'>-</span>" })</div></div>" +
    "</div>" +
    "</details>"
}

$issuesRowsHtml = foreach ($issue in $issuesOnly) {
    $safeDomain = [System.Net.WebUtility]::HtmlEncode([string]$issue.Domain)
    $safeMissing = [System.Net.WebUtility]::HtmlEncode([string]$issue.Missing)
    "<tr><td>$safeDomain</td><td>$safeMissing</td></tr>"
}

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$moduleName = 'EmailDnsAudit'
$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8' />
    <meta name='viewport' content='width=device-width, initial-scale=1' />
    <title>Email DNS Security Report</title>
    <style>
        :root {
            color-scheme: light dark;
            --bg: #0f172a;
            --panel: #111827;
            --text: #e5e7eb;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --ok: #22c55e;
            --warn: #f59e0b;
            --err: #ef4444;
            --line: #1f2937;
        }
        @media (prefers-color-scheme: light) {
            :root {
                --bg: #f8fafc;
                --panel: #ffffff;
                --text: #0f172a;
                --muted: #475569;
                --accent: #0369a1;
                --line: #e2e8f0;
            }
        }
        body {
            margin: 0;
            font-family: Segoe UI, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
        }
        .container {
            max-width: 1250px;
            margin: 32px auto;
            padding: 0 20px;
        }
        .header {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 18px;
        }
        h1 {
            margin: 0 0 8px 0;
            font-size: 30px;
        }
        .meta {
            color: var(--muted);
            font-size: 14px;
            margin-top: 2px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }
        .card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 16px;
        }
        .card .label {
            color: var(--muted);
            font-size: 13px;
            margin-bottom: 6px;
        }
        .card .value {
            font-size: 28px;
            font-weight: 700;
        }
        .section-title {
            margin: 18px 0 8px 2px;
            font-size: 17px;
            color: var(--accent);
        }
        .domain-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 16px;
            margin-bottom: 14px;
        }
        .domain-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 12px;
            cursor: pointer;
            list-style: none;
        }
        .domain-head::-webkit-details-marker {
            display: none;
        }
        .domain-controls {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .domain-head h3 {
            margin: 0;
            font-size: 18px;
        }
        .section-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            cursor: pointer;
            list-style: none;
            padding: 12px 14px;
            background: rgba(56, 189, 248, 0.08);
            color: var(--accent);
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .section-head::-webkit-details-marker {
            display: none;
        }
        .collapse-hint {
            border: 1px solid var(--line);
            background: transparent;
            color: var(--muted);
            border-radius: 8px;
            padding: 4px 10px;
            font-size: 12px;
        }
        .global-controls {
            display: flex;
            justify-content: flex-end;
            margin: 6px 0 10px 0;
        }
        .filter-panel {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 12px;
            margin-bottom: 12px;
        }
        .filter-row {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
        }
        .filter-item {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            color: var(--text);
        }
        .global-btn {
            border: 1px solid var(--line);
            background: var(--panel);
            color: var(--text);
            border-radius: 8px;
            padding: 6px 12px;
            font-size: 12px;
            cursor: pointer;
        }
        .global-btn:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .filtered-out {
            opacity: 0.55;
            border-style: dashed;
        }
        .hidden-by-filter {
            display: none;
        }
        .record-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 10px;
        }
        .record-item {
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 10px;
            background: rgba(148, 163, 184, 0.04);
        }
        .record-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--accent);
            margin-bottom: 6px;
            font-weight: 600;
        }
        .record-content {
            font-size: 13px;
            line-height: 1.35;
        }
        .table-wrap {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 14px;
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--line);
            text-align: left;
            font-size: 13px;
            vertical-align: top;
        }
        th {
            background: rgba(56, 189, 248, 0.08);
            color: var(--accent);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            white-space: nowrap;
        }
        tr:last-child td {
            border-bottom: none;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }
        .badge.ok { background: rgba(34, 197, 94, 0.2); color: var(--ok); }
        .badge.warn { background: rgba(245, 158, 11, 0.2); color: var(--warn); }
        .badge.err { background: rgba(239, 68, 68, 0.2); color: var(--err); }
        .record-line {
            margin-bottom: 6px;
            line-height: 1.35;
            word-break: break-word;
        }
        .record-line:last-child {
            margin-bottom: 0;
        }
        .muted {
            color: var(--muted);
        }
        .footer {
            margin-top: 12px;
            color: var(--muted);
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class='container'>
        <section class='header'>
            <h1>Email DNS Security Report</h1>
            <div class='meta'>Source: $([System.Net.WebUtility]::HtmlEncode($inputSourceDisplay))</div>
            $(if ($defaultDomainDisplay) { "<div class='meta'>Default domain: $([System.Net.WebUtility]::HtmlEncode($defaultDomainDisplay))</div>" } else { '' })
            <div class='meta'>Scanned domains: $totalScannedDomains</div>
        </section>

        <section class='summary'>
            <div class='card'><div class='label'>Domains In Report</div><div class='value'>$totalDomains</div></div>
            <div class='card'><div class='label'>MX Present</div><div class='value'>$domainsWithMx</div></div>
            <div class='card'><div class='label'>MX not pointing to Microsoft</div><div class='value'>$domainsMxNotMicrosoft</div></div>
            <div class='card'><div class='label'>SPF Present</div><div class='value'>$domainsWithSpf</div></div>
            <div class='card'><div class='label'>DMARC Present</div><div class='value'>$domainsWithDmarc</div></div>
            <div class='card'><div class='label'>DKIM Found</div><div class='value'>$domainsWithDkim</div></div>
        </section>

        <div class='section-title'>Issues Only</div>
        <details class='table-wrap' id='issues-section'>
            <summary class='section-head'>
                <span>Issues Only</span>
                <span class='collapse-hint'>Click to expand/collapse</span>
            </summary>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Missing Controls</th>
                    </tr>
                </thead>
                <tbody>
                    $(if ($issuesRowsHtml.Count -gt 0) { $issuesRowsHtml -join [Environment]::NewLine } else { "<tr><td colspan='2'><span class='badge ok'>No issues found</span></td></tr>" })
                </tbody>
            </table>
        </details>

        <div class='section-title'>View Filters</div>
        <section class='filter-panel'>
            <div class='filter-row'>
                <label class='filter-item'><input type='checkbox' id='f-mx-noteop' onchange='applyDomainFilters()' /> MX not pointing to Microsoft</label>
                <label class='filter-item'><input type='checkbox' id='f-missing-mx' onchange='applyDomainFilters()' /> Missing MX</label>
                <label class='filter-item'><input type='checkbox' id='f-missing-spf' onchange='applyDomainFilters()' /> Missing SPF</label>
                <label class='filter-item'><input type='checkbox' id='f-missing-dmarc' onchange='applyDomainFilters()' /> Missing DMARC</label>
                <label class='filter-item'><input type='checkbox' id='f-missing-dkim' onchange='applyDomainFilters()' /> Missing DKIM</label>
                <label class='filter-item'><input type='checkbox' id='f-hide-nonmatching' onchange='applyDomainFilters()' checked /> Hide non-matching</label>
                <button type='button' class='global-btn' onclick='applyDomainFilters()'>Apply Filters</button>
                <button type='button' class='global-btn' onclick='resetDomainFilters()'>Reset</button>
            </div>
            <div class='meta' id='filter-summary'>Showing all domains in this report.</div>
        </section>

        <div class='section-title'>Records By Domain</div>
        <div class='global-controls'>
            <button type='button' class='global-btn' onclick='toggleEverything(this)'>Expand All Sections</button>
            <button type='button' class='global-btn' onclick='toggleAllSections(this)'>Expand All</button>
        </div>
        $($domainSectionsHtml -join [Environment]::NewLine)

        <div class='section-title'>DNS Record Guide</div>
        <section class='table-wrap'>
            <table>
                <thead>
                    <tr>
                        <th>Record</th>
                        <th>What It Means</th>
                        <th>Why It Is Needed</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>MX</td>
                        <td>Specifies the mail servers that receive email for your domain.</td>
                        <td>Without valid MX, inbound email delivery may fail or be misrouted.</td>
                    </tr>
                    <tr>
                        <td>SPF (TXT)</td>
                        <td>Lists which sending servers are allowed to send mail for your domain.</td>
                        <td>Reduces spoofing risk by helping receivers reject unauthorized senders.</td>
                    </tr>
                    <tr>
                        <td>DMARC (TXT at _dmarc)</td>
                        <td>Defines policy and reporting for SPF/DKIM alignment checks.</td>
                        <td>Enforces anti-spoofing policy and provides visibility through aggregate/forensic reports.</td>
                    </tr>
                    <tr>
                        <td>DKIM (TXT at selector._domainkey)</td>
                        <td>Publishes public keys used to verify cryptographic email signatures.</td>
                        <td>Confirms message integrity and domain authenticity for outbound email.</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <div class='footer'>Report generated by $moduleName | Developer: $([System.Net.WebUtility]::HtmlEncode($DeveloperName)) | Generated: $generatedAt</div>
    </div>
    <script>
        function applyDomainFilters() {
            const mxNotMicrosoft = document.getElementById('f-mx-noteop').checked;
            const missingMx = document.getElementById('f-missing-mx').checked;
            const missingSpf = document.getElementById('f-missing-spf').checked;
            const missingDmarc = document.getElementById('f-missing-dmarc').checked;
            const missingDkim = document.getElementById('f-missing-dkim').checked;
            const hideNonMatching = document.getElementById('f-hide-nonmatching').checked;

            const sections = document.querySelectorAll('.domain-details');
            let visibleCount = 0;
            sections.forEach((section) => {
                const hasMx = section.dataset.hasMx === 'true';
                const hasSpf = section.dataset.hasSpf === 'true';
                const hasDmarc = section.dataset.hasDmarc === 'true';
                const hasDkim = section.dataset.hasDkim === 'true';
                const mxPointsToEop = section.dataset.mxEop === 'true';

                const pass =
                    (!mxNotMicrosoft || !mxPointsToEop) &&
                    (!missingMx || !hasMx) &&
                    (!missingSpf || !hasSpf) &&
                    (!missingDmarc || !hasDmarc) &&
                    (!missingDkim || !hasDkim);

                if (pass) {
                    visibleCount += 1;
                    section.classList.remove('filtered-out');
                    section.classList.remove('hidden-by-filter');
                } else {
                    section.classList.toggle('hidden-by-filter', hideNonMatching);
                    section.classList.toggle('filtered-out', !hideNonMatching);
                    section.open = false;
                }
            });

            const active = [];
            if (mxNotMicrosoft) active.push('MX not pointing to Microsoft');
            if (missingMx) active.push('Missing MX');
            if (missingSpf) active.push('Missing SPF');
            if (missingDmarc) active.push('Missing DMARC');
            if (missingDkim) active.push('Missing DKIM');
            if (hideNonMatching) active.push('Hide non-matching');

            const summary = document.getElementById('filter-summary');
            if (active.length === 0) {
                summary.textContent = 'Showing all domains in this report (' + visibleCount + ').';
            } else {
                summary.textContent = 'Active filters: ' + active.join(' | ') + '. Showing ' + visibleCount + ' domain(s).';
            }
        }

        function resetDomainFilters() {
            document.getElementById('f-mx-noteop').checked = false;
            document.getElementById('f-missing-mx').checked = false;
            document.getElementById('f-missing-spf').checked = false;
            document.getElementById('f-missing-dmarc').checked = false;
            document.getElementById('f-missing-dkim').checked = false;
            document.getElementById('f-hide-nonmatching').checked = true;
            applyDomainFilters();
        }

        function toggleAllSections(button) {
            const sections = document.querySelectorAll('.domain-details');
            const collapseAll = button.textContent === 'Collapse All';
            sections.forEach((section) => {
                section.open = !collapseAll;
            });

            button.textContent = collapseAll ? 'Expand All' : 'Collapse All';
        }

        function toggleEverything(button) {
            const expandAll = button.textContent === 'Expand All Sections';
            const domainSections = document.querySelectorAll('.domain-details');
            const issuesSection = document.getElementById('issues-section');

            domainSections.forEach((section) => {
                section.open = expandAll;
            });

            if (issuesSection) {
                issuesSection.open = expandAll;
            }

            const domainToggleButton = Array.from(document.querySelectorAll('.global-btn')).find((btn) => btn !== button && (btn.textContent === 'Expand All' || btn.textContent === 'Collapse All'));
            if (domainToggleButton) {
                domainToggleButton.textContent = expandAll ? 'Collapse All' : 'Expand All';
            }

            button.textContent = expandAll ? 'Collapse All Sections' : 'Expand All Sections';
        }

        applyDomainFilters();
    </script>
</body>
</html>
"@

Set-Content -Path $OutputHtml -Value $html -Encoding UTF8
Write-Host "HTML report written to: $OutputHtml"
if (-not $NoOpenHtml) {
    Write-Host "Opening HTML report in your default browser..."
    Start-Process -FilePath $OutputHtml
}

if ($OutputCsv) {
    $consoleResults |
        Sort-Object Domain |
        Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

    Write-Host "CSV report written to: $OutputCsv"
}

if ($OutputJson) {
    $consoleResults |
        Sort-Object Domain |
        ConvertTo-Json -Depth 6 |
        Set-Content -Path $OutputJson -Encoding UTF8

    Write-Host "JSON report written to: $OutputJson"
}

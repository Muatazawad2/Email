<#
.SYNOPSIS
    Deploys the MDO user-reported phishing playbooks to Microsoft Sentinel and grants the
    Microsoft Graph permissions that the Details and Notify playbooks need.

.DESCRIPTION
    Run in Azure Cloud Shell (PowerShell) or any PowerShell 7 session with the Az module.
    The signed-in account needs:
      - Owner (or Contributor + User Access Administrator) on the playbook resource group
        and on the Sentinel workspace resource group.
      - Global Administrator or Privileged Role Administrator in Microsoft Entra ID,
        to grant the Microsoft Graph application permissions ThreatSubmission.Read.All and
        ThreatSubmission.ReadWrite.All.

    What it does (safe to re-run):
      1. Creates the playbook resource group if it does not exist (in the workspace region).
      2. Deploys azuredeploy.json: Sentinel API connection (managed identity), four playbooks
         (Details, Notify-NoThreatsFound, Notify-Phishing, Notify-Spam), Microsoft Sentinel
         Responder for each playbook on the workspace, Microsoft Sentinel Automation Contributor
         for the Sentinel service account on the playbook resource group (only if missing), and
         two automation rules that run the Details playbook automatically.
      3. Grants Microsoft Graph permissions: ThreatSubmission.Read.All (read-only) to Details,
         and ThreatSubmission.ReadWrite.All to the three Notify playbooks.

.EXAMPLE
    ./deploy.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
                 -ResourceGroup rg-sentinel-playbooks `
                 -WorkspaceName contoso-sentinel -WorkspaceResourceGroup rg-sentinel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [string]$WorkspaceResourceGroup,
    [string]$Location,
    [string]$PlaybookPrefix = 'MDO-Submission',
    [switch]$SkipAutomationRules,
    [switch]$DisableAutomationRules,
    [switch]$SkipGraphPermission
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $WorkspaceResourceGroup) { $WorkspaceResourceGroup = $ResourceGroup }

function Write-Step($text) { Write-Host "`n=== $text" -ForegroundColor Cyan }

# 1. Azure sign-in and subscription
Write-Step 'Azure context'
if (-not (Get-AzContext -ErrorAction SilentlyContinue)) { Connect-AzAccount | Out-Null }
$ctx = Set-AzContext -Subscription $SubscriptionId
Write-Host "Signed in as $($ctx.Account.Id) | subscription $($ctx.Subscription.Name) | tenant $($ctx.Tenant.Id)"

# 2. Workspace and resource group
Write-Step 'Sentinel workspace and resource group'
$ws = Get-AzResource -ResourceGroupName $WorkspaceResourceGroup -ResourceType 'Microsoft.OperationalInsights/workspaces' -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $ws) { throw "Workspace '$WorkspaceName' not found in resource group '$WorkspaceResourceGroup'." }
if (-not $Location) { $Location = $ws.Location }
if (-not (Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroup -Location $Location | Out-Null
    Write-Host "Created resource group $ResourceGroup ($Location)"
} else { Write-Host "Using resource group $ResourceGroup" }

# 3. Sentinel service account (needed so automation rules and Run playbook can start the playbooks)
$sentinelSp = Get-AzADServicePrincipal -ApplicationId '98785600-1bb7-4fb9-b9fa-19afe2c8a360' -ErrorAction SilentlyContinue
$grantSentinelObjectId = ''
if ($sentinelSp) {
    Write-Host "Sentinel service account (Azure Security Insights): $($sentinelSp.Id)"
    $existingAutomation = Get-AzRoleAssignment -ObjectId $sentinelSp.Id -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue |
        Where-Object { $_.RoleDefinitionName -in @('Microsoft Sentinel Automation Contributor', 'Owner') }
    if ($existingAutomation) { Write-Host 'It already has Microsoft Sentinel Automation Contributor (or higher) here.' }
    else { $grantSentinelObjectId = $sentinelSp.Id }
}
else { Write-Warning 'Azure Security Insights service principal not found; grant Microsoft Sentinel Automation Contributor on the playbook resource group manually (Sentinel > Settings > Playbook permissions).' }

# 4. Deploy the template in two phases. Automation rules can only be created once Sentinel's
#    permission on the playbook resource group has propagated (new role assignments take a minute or two).
function Invoke-TemplateDeployment([bool]$withRules) {
    New-AzResourceGroupDeployment -Name ("{0}-{1}" -f $PlaybookPrefix.ToLower(), (Get-Date -Format 'yyyyMMddHHmmss')) `
        -ResourceGroupName $ResourceGroup -TemplateFile (Join-Path $here 'azuredeploy.json') `
        -TemplateParameterObject @{
            WorkspaceName                    = $WorkspaceName
            WorkspaceResourceGroup           = $WorkspaceResourceGroup
            PlaybookPrefix                   = $PlaybookPrefix
            Location                         = $Location
            SentinelServicePrincipalObjectId = $grantSentinelObjectId
            DeployAutomationRules            = $withRules
            AutomationRulesEnabled           = -not $DisableAutomationRules
        }
}
Write-Step 'Deploying playbooks and permissions (azuredeploy.json, phase 1)'
$deployment = Invoke-TemplateDeployment $false
if ($deployment.ProvisioningState -ne 'Succeeded') { throw "Deployment state: $($deployment.ProvisioningState)" }
$out = $deployment.Outputs

if (-not $SkipAutomationRules) {
    Write-Step 'Creating automation rules (phase 2)'
    $rulesOk = $false
    for ($attempt = 1; $attempt -le 6 -and -not $rulesOk; $attempt++) {
        Write-Host "Waiting 60 seconds for permissions to propagate (attempt $attempt of 6)..."
        Start-Sleep -Seconds 60
        try {
            $d2 = Invoke-TemplateDeployment $true
            $rulesOk = $d2.ProvisioningState -eq 'Succeeded'
        } catch {
            if ($_.Exception.Message -notmatch 'not using Microsoft Sentinel Incident trigger|AuthorizationFailed|does not have permission|Missing required permissions') { throw }
            Write-Host 'Sentinel cannot read the playbooks yet; retrying.'
        }
    }
    if ($rulesOk) { Write-Host 'Automation rules created.' }
    else { Write-Warning 'Automation rules were not created. Re-run this script in a few minutes (it is safe to re-run).' }
}
Write-Host ("Deployed: {0}, {1}, {2}, {3}" -f $out.detailsPlaybook.Value, $out.notifyNoThreatsFoundPlaybook.Value, $out.notifyPhishingPlaybook.Value, $out.notifySpamPlaybook.Value)

# 5. Microsoft Graph permissions: read-only for Details, read/write for the three Notify playbooks
if ($SkipGraphPermission) { Write-Warning 'Skipped the Graph permissions. Until they are granted, Details posts only links and the Notify playbooks cannot mark emails.'; return }
Write-Step 'Granting Microsoft Graph threat-submission permissions'

function Get-GraphToken {
    $t = Get-AzAccessToken -ResourceTypeName MSGraph
    if ($t.Token -is [securestring]) { return [System.Net.NetworkCredential]::new('', $t.Token).Password }
    return $t.Token
}
function Invoke-Graph($Method, $Uri, $Body) {
    $headers = @{ Authorization = "Bearer $script:graphToken" }
    if ($Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 5) }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
}

$script:graphToken = Get-GraphToken
$graphSp = (Invoke-Graph GET "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles").value[0]
function Get-AppRole($value) {
    $role = $graphSp.appRoles | Where-Object { $_.value -eq $value -and $_.allowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Graph app role $value not found." }
    return $role
}

$grants = @(
    @{ Name = $out.detailsPlaybook.Value;              Id = $out.detailsPrincipalId.Value;              Role = Get-AppRole 'ThreatSubmission.Read.All' },
    @{ Name = $out.notifyNoThreatsFoundPlaybook.Value; Id = $out.notifyNoThreatsFoundPrincipalId.Value; Role = Get-AppRole 'ThreatSubmission.ReadWrite.All' },
    @{ Name = $out.notifyPhishingPlaybook.Value;       Id = $out.notifyPhishingPrincipalId.Value;       Role = Get-AppRole 'ThreatSubmission.ReadWrite.All' },
    @{ Name = $out.notifySpamPlaybook.Value;           Id = $out.notifySpamPrincipalId.Value;           Role = Get-AppRole 'ThreatSubmission.ReadWrite.All' }
)
$failed = @()
foreach ($g in $grants) {
    $done = $false
    for ($attempt = 1; $attempt -le 5 -and -not $done; $attempt++) {
        try {
            $existing = (Invoke-Graph GET "https://graph.microsoft.com/v1.0/servicePrincipals/$($g.Id)/appRoleAssignments").value |
                Where-Object { $_.appRoleId -eq $g.Role.id -and $_.resourceId -eq $graphSp.id }
            if ($existing) { Write-Host "Already granted: $($g.Name) ($($g.Role.value))"; $done = $true; continue }
            Invoke-Graph POST "https://graph.microsoft.com/v1.0/servicePrincipals/$($g.Id)/appRoleAssignments" @{ principalId = $g.Id; resourceId = $graphSp.id; appRoleId = $g.Role.id } | Out-Null
            Write-Host "Granted: $($g.Name) ($($g.Role.value))"
            $done = $true
        } catch {
            # A brand-new managed identity can take a few seconds to appear in Microsoft Entra ID.
            if ($attempt -lt 5 -and "$($_.ErrorDetails.Message)$($_.Exception.Message)" -match 'ResourceNotFound|does not exist|404') { Start-Sleep -Seconds 15; continue }
            Write-Warning "Could not grant $($g.Name): $($_.Exception.Message)"
            $failed += $g
            $done = $true
        }
    }
}
if ($failed) {
    Write-Warning 'Grant the missing permissions with Microsoft Graph PowerShell as a Global Administrator or Privileged Role Administrator:'
    Write-Host "  Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Application.Read.All'"
    foreach ($g in $failed) {
        Write-Host "  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $($g.Id) -PrincipalId $($g.Id) -ResourceId $($graphSp.id) -AppRoleId $($g.Role.id)   # $($g.Name): $($g.Role.value)"
    }
}

Write-Step 'Done'
Write-Host 'Next: report a test email, then open the incident > Activities to see the "Reported email: <subject>" comment,'
Write-Host "and try '... > Run playbook > $($out.notifyNoThreatsFoundPlaybook.Value)' on that incident."

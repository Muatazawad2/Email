# EmailDnsAudit

PowerShell module that checks domains for the email DNS records **MX**, **SPF**, **DMARC** and **DKIM**, and writes the results to the console and to HTML, CSV and JSON reports.

## What it checks

| Record | What it reports |
|---|---|
| MX | The mail servers, and whether they point to Microsoft 365 (`*.mail.protection.outlook.com`) |
| SPF | The SPF record |
| DMARC | The DMARC record |
| DKIM | DKIM records for common selectors: `selector1`, `selector2`, `default`, `google`, `k1`, `k2`, `mail` and `dkim`. Use `-DkimSelectors` to check others. |

Each domain also gets an overall status.

## Requirements

- Windows, with Windows PowerShell 5.1 or PowerShell 7. DNS lookups use `Resolve-DnsName`, which is only available on Windows.
- To read domains from Exchange Online: the **ExchangeOnlineManagement** module and an account that can view the accepted domains.

## Usage

```powershell
git clone https://github.com/Muatazawad2/Email.git
cd Email/EmailDnsAudit

Import-Module ./EmailDnsAudit.psd1
Invoke-EmailDnsAudit -DomainInput contoso.com, fabrikam.com
```

You can also run the script directly, with the same parameters:

```powershell
./EmailDnsAudit.ps1 -InputFile ./domains.txt -OutputCsv ./email-dns-report.csv
```

Run it without `-DomainInput` or `-InputFile` and it asks where the domains come from: type them, import the accepted domains from Exchange Online, or select a text file.

## Parameters

| Parameter | Description |
|---|---|
| `-DomainInput` | One or more domains. |
| `-InputFile` | A text file with one domain per line. Lines that start with `#` are skipped. |
| `-UseExchangeAcceptedDomains` | Sign in to Exchange Online and check its accepted domains. `*.onmicrosoft.com` domains are skipped unless you add `-ExcludeOnMicrosoftDomains $false`. |
| `-ExchangeOrganization` | Passed to `Connect-ExchangeOnline -Organization`, for example `contoso.onmicrosoft.com`. |
| `-PromptForFile` | Show the input choices even if `-InputFile` is set. |
| `-OutputHtml` | Path for the HTML report. By default it's `email-dns-report-<timestamp>.html` in the current folder. The report opens in your browser. |
| `-NoOpenHtml` | Don't open the HTML report. |
| `-OutputCsv`, `-OutputJson` | Also write a CSV or JSON report. |
| `-ShowAll` | List the record details for every domain in the console. By default, the console table shows only domains that have MX records. |
| `-DkimSelectors` | DKIM selectors to check instead of the defaults. |
| `-DnsServer` | DNS server to query instead of the system default. |
| `-ShowProgress` | `$false` hides the progress display. |
| `-FilterMxNotMicrosoft` | Keep only domains whose MX records don't point to Microsoft 365. |
| `-FilterMissingAnyCore`, `-FilterMissingAllCore` | Keep only domains missing any, or all, of MX, SPF, DMARC and DKIM. |
| `-FilterMissingAnyOf`, `-FilterMissingAllOf` | Keep only domains missing any, or all, of the records you list, for example `-FilterMissingAnyOf DMARC, DKIM`. |
| `-DeveloperName` | Name shown in the HTML report's footer. |

The filters apply to the console output and to the reports.

## Files

| File | What it is |
|---|---|
| `EmailDnsAudit.psd1` | Module manifest |
| `EmailDnsAudit.psm1` | Module. Exports `Invoke-EmailDnsAudit`. |
| `EmailDnsAudit.ps1` | The scan and the reports |

## License

[MIT](../LICENSE)

---

**Developer**: Dr. Muataz Awad

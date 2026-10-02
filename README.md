# Email

PowerShell tools and Microsoft security automation for email.

| Project | What it does |
|---|---|
| [**MDO-Reported-Email-Playbooks**](MDO-Reported-Email-Playbooks/) | Microsoft Sentinel playbooks for Defender for Office 365 user-reported email. They post each report's status in the incident with a working **Open in Submissions** link, and let analysts mark reported emails and notify the reporters with **Run playbook**. |
| [**EmailDnsAudit**](#emaildnsaudit) | PowerShell module that checks domains for MX, SPF, DMARC and DKIM records and produces console, HTML, CSV and JSON reports. |

## EmailDnsAudit

The module files are at the root of this repository: [`EmailDnsAudit.psd1`](EmailDnsAudit.psd1), [`EmailDnsAudit.psm1`](EmailDnsAudit.psm1) and [`EmailDnsAudit.ps1`](EmailDnsAudit.ps1). It reads domains from direct input, a file, or Exchange Online accepted domains.

```powershell
Import-Module ./EmailDnsAudit.psd1
Invoke-EmailDnsAudit -DomainInput contoso.com, fabrikam.com -OutputHtml ./email-dns-report.html
```

## License

[MIT](LICENSE)
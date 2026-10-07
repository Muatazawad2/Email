# Email

PowerShell tools and Microsoft security automation for email.

| Project | What it does |
|---|---|
| [**MDO-Reported-Email-Playbooks**](MDO-Reported-Email-Playbooks/) | Microsoft Sentinel playbooks for Defender for Office 365 user-reported email. They post each report's status in the incident with a working **Open in Submissions** link, and let analysts mark reported emails and notify the reporters with **Run playbook**. |
| [**AttackSimulator**](AttackSimulator/) | Hourly Azure Function (Python) that copies Defender for Office 365 **Attack Simulation Training** results from Microsoft Graph to Azure Table Storage, with a ten-page Power BI report and a step-by-step portal guide. |
| [**EmailDnsAudit**](EmailDnsAudit/) | PowerShell module that checks domains for MX, SPF, DMARC and DKIM records and produces console, HTML, CSV and JSON reports. |

Each project has its own folder and README.

## License

[MIT](LICENSE)

---

**Developer**: Dr. Muataz Awad

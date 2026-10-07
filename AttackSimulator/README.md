# Attack Simulation Training reporting

An Azure Functions app (Python, Flex Consumption) that copies Microsoft Defender for Office 365 **Attack Simulation Training** data from Microsoft Graph into Azure Table Storage every hour, for Power BI reporting.

It writes the same seven tables, with the same column names, as [cammurray/ASTSync](https://github.com/cammurray/ASTSync), so reports built on that project keep working:

| Table | Source (Microsoft Graph) |
|---|---|
| `Simulations` | `/beta/security/attackSimulation/simulations` |
| `SimulationUsers`, `SimulationUserEvents` | `/beta/security/attackSimulation/simulations/{id}/report/simulationUsers` |
| `Users` | `/v1.0/users` (via `$batch`, 20 per call) |
| `Trainings` | `/beta/security/attackSimulation/trainings` |
| `Payloads` | `/beta/security/attackSimulation/payloads` |
| `TrainingUserCoverage` | `/beta/reports/security/getAttackSimulationTrainingUserCoverage` |

A small `SyncState` table records when Microsoft's catalogues were last refreshed.

## What makes it efficient

- **Hourly runs only read what changed**: simulations that are running, finished recently, or not synced for a month.
- **User profiles in batches**: 20 users per Graph `$batch` call, and only users not refreshed in the last 7 days.
- **Catalogues once a day**: Microsoft's 5,000+ global payloads and trainings are refreshed every 24 hours, not every hour.
- **Throttling-aware**: honors Graph `Retry-After`, with backoff.
- **Batched writes**: up to 100 rows per Table Storage transaction.

In testing, a full first run took about 2 minutes; a normal hourly run took **6 seconds and 3 Graph calls**.

## Deploy

**[Build it in the portal](docs/build-in-the-portal.md)**: a step-by-step guide with screenshots. It covers the storage account, the app registration, the Function App, the role assignment, the settings, the code upload and connecting the Power BI report.

Download from the [AttackSimulator v1.0.0 release](https://github.com/Muatazawad2/Email/releases/tag/attacksimulator-v1.0.0):

| File | What it is |
|---|---|
| `ast-sync-ready-to-run.zip` | The code plus its Python packages (Linux x86-64, Python 3.12), for the portal's **Deployment Center > Publish files** |
| `ASTReporting.pbit` | The ten-page Power BI report template (also in [`powerbi/`](powerbi)) |

To build the zip yourself, run `.\build-package.ps1` from this folder.

## Power BI report

`powerbi/ASTReporting.pbit` asks for the storage account name when it opens, then for the storage **account key** (the Power BI Table Storage connector only supports account keys). It has ten pages, 56 measures and two row-level security roles:

| Role | Sees |
|---|---|
| **Security Team** | Everyone |
| **End User Self Service** | Only the signed-in user's own results (`Users[Mail] = USERPRINCIPALNAME()`) |

### Publish and schedule refresh

1. In Power BI Desktop, select **Home > Publish** and choose a shared workspace. This needs Power BI Pro or Premium Per User, unless the workspace is on a Premium or Fabric capacity.
2. In the Power BI service, open the semantic model's **Settings > Data source credentials > Edit credentials**. Choose **Key**, paste the storage account key, and set the privacy level to **Organizational**.
3. Under **Refresh**, turn on a schedule. The sync writes hourly, so 2–4 refreshes a day is plenty.
4. Under **Security**, add the security team to **Security Team** and employees to **End User Self Service**. Give employees the workspace **Viewer** role or share through an app: Admins, Members and Contributors bypass row-level security.

No gateway is needed. When the storage key rotates, update it in step 2.

## Settings

| Setting | Required | Description |
|---|---|---|
| `SYNC_SCHEDULE` | Yes | CRON schedule, for example `0 0 * * * *` (top of every hour) |
| `STORAGE_ACCOUNT_NAME` | Yes | Table Storage account. The Function App's managed identity needs **Storage Table Data Contributor** on it. |
| `GRAPH_TENANT_ID` | Cross-tenant only | Tenant that holds the simulation data |
| `GRAPH_CLIENT_ID` | Cross-tenant only | App registration with `AttackSimulation.Read.All`, `Reports.Read.All` and `User.Read.All` (application) |
| `GRAPH_CLIENT_SECRET` | Cross-tenant only | Secret for that app registration |
| `SYNC_ENTRA_USERS` | No | `false` to skip user profiles (default `true`) |
| `USER_REFRESH_DAYS` | No | Re-read a user's profile after this many days (default `7`) |
| `SIM_RESYNC_DAYS` | No | Re-read users of simulations completed within this many days (default `7`) |
| `CATALOGUE_REFRESH_HOURS` | No | Refresh Microsoft's catalogues this often (default `24`) |
| `MAX_PARALLEL_SIMULATIONS` | No | Simulations read at the same time (default `4`) |

When the three `GRAPH_*` settings are omitted, the Function App's own managed identity is used for Graph (same-tenant deployments).

## Run locally

```powershell
cd AttackSimulator
python -m venv .venv; .venv\Scripts\activate
pip install -r requirements.txt
$env:STORAGE_CONNECTION_STRING = "<connection string>"   # or STORAGE_ACCOUNT_NAME + az login
$env:GRAPH_TENANT_ID = "..."; $env:GRAPH_CLIENT_ID = "..."; $env:GRAPH_CLIENT_SECRET = "..."
python ast_sync.py
```

## Credits

Table design and Graph mapping follow [Cam Murray's ASTSync](https://github.com/cammurray/ASTSync).

---

**Developer**: Dr. Muataz Awad

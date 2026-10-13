# SecurePulse

Multi-tenant Microsoft 365 security posture platform. It runs open-source engines
(Maester, ScubaGear, later Wazuh and GoPhish) against client tenants, normalizes every
result into one `Finding` model, and turns it into a single score, a prioritized fix list
and a client-ready report.

> Working name. Phase 1 focuses on **Assess**: connect tenants, scan, score, report.

## Solution layout

```
SecurePulse.slnx
├── samples/maester-results.sample.json   Example Maester output used for testing the parser
└── src/
    ├── SecurePulse.Core        Domain models (Finding, Tenant, ManagedDevice, RiskScore) + interfaces
    ├── SecurePulse.Data        EF Core + PostgreSQL repositories, migrations, dev seeder
    ├── SecurePulse.Engines     Engine adapters. Maester: out-of-process runner + JSON parser
    ├── SecurePulse.Intune      Intune device inventory over Microsoft Graph (certificate auth)
    ├── SecurePulse.Reporting   RiskScoreCalculator (0–100 score, grade, top risks)
    ├── SecurePulse.Web         Blazor Server portal (MudBlazor, M3 Expressive-style theme)
    └── SecurePulse.Worker      Background service: scheduled Intune device sync
tests/
    └── SecurePulse.Tests       xUnit: parser, scoring, Graph client, sync, PostgreSQL repositories
```

## Run it

Requirements: .NET 10 SDK. PostgreSQL 14+ for the database mode.

```bash
dotnet restore
dotnet run --project src/SecurePulse.Web
dotnet test
```

Without a connection string the portal runs on **in-memory sample data** (five fictional
tenants), so you can design and demo the UI with nothing else installed. Pages: Overview (`/`),
Findings (`/findings`), Endpoints (`/endpoints`, device detail at `/endpoints/{tenant}/{device}`),
Tenants (`/tenants`). Dark mode toggle is in the top bar.

### With PostgreSQL and the Worker

Connection strings carry a password, so keep them out of `appsettings.json`: use user-secrets
in development or the `ConnectionStrings__SecurePulse` environment variable elsewhere.

```bash
CS="Host=localhost;Database=securepulse;Username=securepulse;Password=..."
dotnet user-secrets set ConnectionStrings:SecurePulse "$CS" --project src/SecurePulse.Web
dotnet user-secrets set ConnectionStrings:SecurePulse "$CS" --project src/SecurePulse.Worker
dotnet user-secrets set Intune:AppClientId "<multi-tenant app client ID>" --project src/SecurePulse.Worker

dotnet run --project src/SecurePulse.Web      # Development: migrates, seeds demo data if empty
dotnet run --project src/SecurePulse.Worker   # migrates, then syncs Intune devices every 4 hours
```

The Worker syncs tenants that have granted consent **and** have a certificate thumbprint in
`CredentialReference`. The certificate (with private key) must be in the Worker's
`CurrentUser\My` or `LocalMachine\My` store. Settings live under `DeviceSync` (interval,
parallel tenants) and `Intune` (Graph and authority URLs for national clouds, retries,
timeout) in `src/SecurePulse.Worker/appsettings.json`.

Graph application permissions (read-only, admin consent in each client tenant):

- `DeviceManagementManagedDevices.Read.All`: device inventory and compliance state
- `DeviceManagementConfiguration.Read.All`: per-setting compliance results for devices that
  aren't compliant (one extra call per such device; turn off with `Intune:FetchComplianceSettings`)

A failed sync keeps the tenant's last good inventory and shows a warning on the Endpoints
page. Defender health is not available from Graph v1.0 `managedDevice` and shows as
"Unknown" for synced devices.

To run the PostgreSQL repository tests, point `SECUREPULSE_TEST_POSTGRES` at a server
(no `Database=`) with a role that can create databases. Each test class creates and drops its
own database. Without the variable those tests are reported as skipped.

## How scoring works

Each evaluated check is weighted by severity (Critical 10, High 6, Medium 3, Low 1, Info 0).
Score = share of weight that passed; "Investigate" earns half credit; skipped or unlicensed
checks are excluded. Any open **Critical** caps the grade at C.

## Status

| Area | State |
|---|---|
| Core models, scoring, Maester parser | Built; covered by `SecurePulse.Tests` |
| Maester engine runner | Built; needs a real tenant + certificate to exercise |
| Portal (Overview, Findings, Tenants) | Built; sample data or PostgreSQL |
| Endpoints (Intune device inventory, device detail) | Built; remote actions disabled until approval + audit log exist |
| PostgreSQL persistence (`SecurePulse.Data`) | Built; tested against PostgreSQL 16 |
| Worker: Intune device sync | Built and tested against stubbed Graph; needs a real tenant + certificate to exercise |
| Worker: scheduled engine scans | Next |
| Multi-tenant admin-consent onboarding | Next |
| ScubaGear adapter, PDF report | Next |

## Security notes

- Scans use app-only auth with **certificates**, never client secrets in code or config.
- `Tenant.CredentialReference` holds only a certificate thumbprint / vault reference.
- Engines run **out of process** with arguments passed via `ArgumentList`, so tenant data
  can't inject PowerShell and a hung scan can't crash the portal.
- Request **read-only** Graph permissions for assessment; remediation is a separate consent.
- Check each engine's license before redistributing modified versions (Wazuh is GPLv2).

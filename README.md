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
    ├── SecurePulse.Core        Domain models (Finding, Tenant, ScanResult, RiskScore) + interfaces
    ├── SecurePulse.Engines     Engine adapters. Maester: out-of-process runner + JSON parser
    ├── SecurePulse.Reporting   RiskScoreCalculator (0–100 score, grade, top risks)
    └── SecurePulse.Web         Blazor Server portal (MudBlazor, M3 Expressive-style theme)
tests/
    └── SecurePulse.Tests       xUnit: Maester parser (against samples/) and scoring rules
```

## Run it

Requirements: .NET 10 SDK.

```bash
dotnet restore
dotnet run --project src/SecurePulse.Web
dotnet test
```

The portal starts with **sample data** (five fictional tenants) so you can design and demo
the UI before connecting any real tenant. Pages: Overview (`/`), Findings (`/findings`),
Endpoints (`/endpoints`, device detail at `/endpoints/{tenant}/{device}`), Tenants (`/tenants`). Dark mode toggle is in the top bar.

## How scoring works

Each evaluated check is weighted by severity (Critical 10, High 6, Medium 3, Low 1, Info 0).
Score = share of weight that passed; "Investigate" earns half credit; skipped or unlicensed
checks are excluded. Any open **Critical** caps the grade at C.

## Status

| Area | State |
|---|---|
| Core models, scoring, Maester parser | Built; covered by `SecurePulse.Tests` |
| Maester engine runner | Built; needs a real tenant + certificate to exercise |
| Portal (Overview, Findings, Tenants) | Built on sample data; builds clean on MudBlazor 8 |
| Endpoints (Intune device inventory, device detail) | Built on sample data; Graph device sync and remote actions not wired |
| Worker service, EF Core persistence | Next |
| Multi-tenant admin-consent onboarding | Next |
| ScubaGear adapter, PDF report | Next |

## Security notes

- Scans use app-only auth with **certificates**, never client secrets in code or config.
- `Tenant.CredentialReference` holds only a certificate thumbprint / vault reference.
- Engines run **out of process** with arguments passed via `ArgumentList`, so tenant data
  can't inject PowerShell and a hung scan can't crash the portal.
- Request **read-only** Graph permissions for assessment; remediation is a separate consent.
- Check each engine's license before redistributing modified versions (Wazuh is GPLv2).

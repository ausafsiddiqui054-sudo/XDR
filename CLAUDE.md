# CLAUDE.md — SecurePulse

Context for Claude Code working in this repository.

## What this is
A multi-tenant M365/Entra security posture platform for SMBs and MSPs, with a focus on
GCC healthcare (UAE IA, DoH ADHICS mappings). Engines: Maester, ScubaGear (Phase 1);
Wazuh, GoPhish, n8n-style remediation (later phases). Read README.md for layout and status.

## Stack
- .NET 10, C#, `SecurePulse.slnx`
- Blazor Server (interactive server render mode, set globally on `<Routes>` in App.razor)
- MudBlazor 8 with the theme in `src/SecurePulse.Web/Theme/SecurePulseTheme.cs`
  (Material 3 Expressive look: tonal surfaces, 16–24px radii, Roboto Flex)
- PowerShell 7 engines launched out of process from .NET

## Architecture rules
1. Every engine implements `IScanEngine` and returns normalized `Finding`s. Never let
   engine-specific shapes leak past `SecurePulse.Engines`.
2. Engines run out of process. Pass arguments with `ProcessStartInfo.ArgumentList`,
   never string concatenation. Validate tenant inputs (GUIDs, thumbprints) before use.
3. No secrets in code, config or the database. Certificates live in a vault/cert store;
   `Tenant.CredentialReference` is only a reference.
4. Scoring lives only in `RiskScoreCalculator`. UI never re-implements scoring.
5. Assessment uses read-only Graph permissions; any write/remediation action needs
   separate consent, an explicit approval step and an audit log entry.
6. `SecurePulse.Core` has no external package dependencies.

## Naming collision
MudBlazor has its own `Severity` (snackbars). In Razor, `_Imports.razor` aliases
`Severity` to `SecurePulse.Core.Models.Severity`; use `MudBlazor.Severity` explicitly for
snackbars. Do the same alias in any .cs file that imports both namespaces.

## Commands
```bash
dotnet build SecurePulse.slnx
dotnet run --project src/SecurePulse.Web
```

## Next steps (in order)
1. First local build of SecurePulse.Web — fix any MudBlazor 8 API mismatches.
2. Add `SecurePulse.Tests` (xUnit): parser tests using `samples/`, scoring tests
   (critical caps grade, Investigate = half credit, NotEvaluated excluded).
3. `SecurePulse.Data`: EF Core + PostgreSQL repositories replacing `SampleDataStore`.
4. `SecurePulse.Worker`: scheduled scans (Hangfire or Quartz.NET) calling `IScanEngine`.
5. Multi-tenant Entra app + admin-consent onboarding flow (Microsoft.Identity.Web),
   portal login with roles (Owner, MSP admin, Client viewer).
6. ScubaGear adapter (check current OS/PowerShell requirements; may need a Windows worker).
7. Branded PDF report (QuestPDF; check its license tier).

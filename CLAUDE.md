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
- PostgreSQL via EF Core (`SecurePulse.Data`); repositories use `IDbContextFactory`
- `SecurePulse.Worker` (generic host) runs background jobs; the portal never calls Graph

## Architecture rules
1. Every engine implements `IScanEngine` and returns normalized `Finding`s. Never let
   engine-specific shapes leak past `SecurePulse.Engines`. Likewise Graph shapes stay inside
   `SecurePulse.Intune`, which returns normalized `ManagedDevice`s via `IDeviceInventorySource`.
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
dotnet run --project src/SecurePulse.Worker   # needs ConnectionStrings:SecurePulse
dotnet test SecurePulse.slnx                  # set SECUREPULSE_TEST_POSTGRES for DB tests
dotnet tool restore && dotnet ef migrations add <Name> --project src/SecurePulse.Data
```

Never edit an applied migration; add a new one. Enums are stored as strings.

## Onboarding invariants
- A consent callback alone never connects a tenant: the Worker must get a real app-only token
  and check its `roles` (all of `AssessmentPermissions.Required`, nothing outside
  `AssessmentPermissions.IsReadOnly`).
- Consent links are single-use, expiring, bound to the domain's Entra tenant; only a SHA-256
  of `state` is stored for lookup. The portal holds no certificate and never calls Graph.

## Sign-in invariants
- Authorization reads only claims SecurePulse issues (`PortalClaims`, issuer "SecurePulse"),
  added per request from `portal_users`. Never use `IsInRole` or token `roles` claims.
- Tenant scoping lives in the services (`IUserContextAccessor` + `UserContext.CanSee`); a new
  page or service that reads tenant data must filter through it. Return not-found, not forbidden.
- New pages are protected by `Pages/_Imports.razor`; public ones need `[AllowAnonymous]` and
  `[ExcludeFromInteractiveRouting]` (anonymous users have no circuit).

## Next steps (in order)
1. Worker: scheduled engine scans calling `IScanEngine` and `IFindingRepository.SaveScanAsync`
   (add Quartz.NET when per-tenant schedules are needed; device sync uses a PeriodicTimer).
   Add the Maester permissions to `AssessmentPermissions.Required` when scans go live.
2. ScubaGear adapter (check current OS/PowerShell requirements; may need a Windows worker).
3. Branded PDF report (QuestPDF; check its license tier).
4. Device remote actions (sync/restart/retire/wipe): approval queue + audit log, then a
   separate write-consent app and Graph client. The UI dialog is built and disabled until then.
5. Defender health per device via the Defender for Endpoint API (not in Graph v1.0 managedDevice).
6. Persist the data-protection key ring (shared store) before running more than one portal
   instance: it protects consent-link state and the sign-in cookie.
7. Audit log table for security events (sign-ins, invitations, role changes, onboarding); today
   they go to the application log only.

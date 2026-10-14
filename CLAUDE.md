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

## Audit invariants
- Security-relevant actions record an `AuditEvent` (portal: `AuditTrail`; Worker: `IAuditLog`).
  Add new actions to `AuditActions` with a label and a category; never rename stored action strings.
- `audit_events` is append-only (DB trigger). Don't add update/delete paths or foreign keys.
- Don't audit unauthenticated input that isn't tied to a real record (public endpoints would let
  anyone flood the table).
- Portal events record after the action and log Critical if the write fails. Remote/write
  actions must be fail-closed: write the audit entry first and abort if it fails.

## Scan invariants
- The portal only queues scans (`IScanRunRepository.EnqueueAsync`, operators only, audited);
  the Worker claims and runs them. Never run an engine from the portal.
- One queued-or-running run per tenant and engine (unique index `IX_scan_runs_active`); claims
  use `FOR UPDATE SKIP LOCKED`, so keep both if you change the queue.
- Before each scan the Worker checks the token's `roles` (same rules as onboarding) against
  `AssessmentPermissions.RequiredFor(engine)`. Adding a permission to `AssessmentPermissions.Required`
  means existing tenants must re-consent; list it under the engine that needs it.
- A failed scan never replaces stored findings; only `SaveScanAsync` on success does, and only that
  engine's (`Source`) findings. An engine that evaluated nothing must report failure, not success.
- Each Worker runs the engines in its `Scans:Engines` (ScubaGear needs Windows PowerShell 5.1, so a
  Windows Worker); the portal's `Scans:Engines` must list every engine some Worker runs.
- ScubaGear runs only `aad`: its other products need Exchange.ManageAsApp, Sites.FullControl.All or
  directory roles, which break the read-only rule. Don't add products without that decision.
- Shared out-of-process plumbing (validation, work folder, timeout) is in `Engines/OutOfProcessScan.cs`.

## Report invariants
- PDF reports use QuestPDF. Its license tier is an organisational decision: it comes only from
  `Reports:QuestPdfLicense` (`ReportLicense.Apply`); never default or hard-code a tier. Tests set
  Community for development in the `QuestPDF` test collection (the setting is process-wide).
- Reports show `RiskScoreCalculator`'s score and weights; the document never computes its own.
- The download endpoint builds `UserContext` from `HttpContext.User` (no Blazor circuit there),
  filters with `CanSee` (404 for other tenants) and audits `report.downloaded`.
- Engine text in reports is untrusted: only https links become hyperlinks.
- Fonts are embedded (`ReportFonts`: Lato + Noto Sans Arabic); QuestPDF 2026.9+ ignores system fonts.
  Missing glyphs print placeholders (`ThrowOnMissingTextGlyphs = false`) instead of failing a report.

## Next steps (in order)
1. Device remote actions (sync/restart/retire/wipe): approval queue + audit log, then a
   separate write-consent app and Graph client. The UI dialog is built and disabled until then.
2. Defender health per device via the Defender for Endpoint API (not in Graph v1.0 managedDevice).
3. Persist the data-protection key ring (shared store) before running more than one portal
   instance: it protects consent-link state and the sign-in cookie.
4. Audit retention: a maintenance role allowed to purge `audit_events` older than a configured
   period (the trigger blocks the app). Optionally ship events to a SIEM (Sentinel) as well.

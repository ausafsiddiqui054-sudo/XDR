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
2. PowerShell engines run out of process. Pass arguments with `ProcessStartInfo.ArgumentList`,
   never string concatenation. API engines (Wazuh, GoPhish) make bounded, read-only HTTP calls from the Worker.
   Validate tenant inputs (GUIDs, thumbprints, group names) before use.
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
  of `state` is stored for lookup. The portal holds no Graph certificate and never calls Graph.

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
- `audit_events` is append-only (DB trigger). Don't add update/delete paths or foreign keys. The one
  exception is retention: only the NOLOGIN role `securepulse_audit_purge` may delete, only rows older than
  90 days (`AuditRetention.Minimum`, enforced in the trigger too), through `PostgresAuditPurger` on the
  Worker's separate `ConnectionStrings:AuditMaintenance` login. The app's login is never a member of it.
- Retention is off until `AuditRetention:RetainFor` is set (an organisational decision; never default it).
  The purge is fail-closed: `audit.purge-started` is written first and nothing is deleted if that fails.
- Sentinel export (`Worker/Siem`): events go in `RecordedAt` order (database clock, not the writer's),
  skipping the last `ExportLag`; the checkpoint (`audit_export_checkpoints`) moves only after Sentinel
  accepted a call. At least once, never lost: don't advance it before the send or skip failed batches.
  The purge never deletes events after any destination's checkpoint (`PostgresAuditPurger.NotYetExported`).
- The export authenticates with a certificate or managed identity (no secrets) and sends only to
  Azure Monitor ingestion hosts (`SentinelOptions.AllowedHostSuffixes`). Don't audit export runs
  (each would create an event to export); log them.
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
- The Graph role check before a scan applies to Graph engines only (`ScanEngines.UsesGraph`); an engine that
  doesn't apply to a tenant (`ScanEngines.AppliesTo`) is neither scheduled nor queued for it.

## Wazuh invariants
- One shared manager; a tenant's agents are its `Tenant.WazuhAgentGroup` (unique index, Owner-only, audited
  `onboarding.wazuh-group-changed`, `default` refused). The engine reads only agents whose own group list
  contains that group and leaves out agents also in another tenant's group. Never widen this.
- The API user must be read-only: `WazuhRbac.Problem` refuses black RBAC mode and any allowed non-`:read`
  action before each scan. Only GETs after the sign-in POST.
- The password comes from Key Vault (`IWazuhPasswordProvider`), never config or the database. TLS is pinned
  (`Wazuh:CertificateSha256`) or validated normally; no redirects.
- SCA checks have no severity: every finding gets `Wazuh:FindingSeverity`. Only https references become links.
  A scan with no agents, no SCA results or any unreadable agent fails (stored findings stay).

## GoPhish invariants
- Import only: SecurePulse never creates, launches or changes campaigns and never sends email. Its GoPhish
  client goes through `ReadOnlyHttpHandler` (GET/HEAD only); keep it there, since GoPhish keys can write.
- Aggregates only: read `/api/campaigns/summary`, never `/api/campaigns/{id}/results` or anything that names
  recipients. People's names, addresses and IPs never enter SecurePulse.
- A tenant's campaigns come from its own GoPhish user. The key's secret name is derived
  (`GoPhishSecrets.ApiKeySecretName`); don't make it configurable per tenant. The tenant opt-in
  (`Tenant.GoPhishEnabled`) is Owner-only and audited `onboarding.gophish-changed`.
- Admin keys are refused before any campaign is read (`HEAD /api/users/` must be 403). The key is sent in the
  `Authorization` header, never the URL. TLS pinned (`GoPhish:CertificateSha256`) or validated; no redirects.
- A campaign fails when anyone entered data; severity is `GoPhish:FindingSeverity`. No campaign in the lookback,
  or none finished, fails the import (stored findings stay).

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

## Device action invariants
- Writes go only through the separate remediation app (`Remediation:*`, `IRemediationTokenProvider`),
  which may hold exactly `RemediationPermissions.Required`. The assessment app never gets a write
  permission, and remediation consent never connects a tenant (`CompleteRemediationAsync`).
- `DeviceActionPolicy` is the approval policy: never the requester; retire/wipe need an Owner. The
  portal enforces it in `DeviceActionRequestService`, and the Worker re-checks it, plus remediation
  access and the token's roles, before every send.
- Approval and sending are fail-closed: the audit entry is written first (`RecordOrThrowAsync` in
  the portal, `IAuditLog` before the Graph call in the Worker) and nothing happens if that fails.
- State changes are conditional updates on the current status; one open action per device
  (`IX_device_actions_open`); claims use `FOR UPDATE SKIP LOCKED`. Writes are never retried.

## Defender health invariants
- Defender data comes through Graph with the assessment app's existing read-only permissions:
  `windowsProtectionState` (DeviceManagementManagedDevices.Read.All) and advanced hunting
  `DeviceInfo` (ThreatHunting.Read.All). Don't add the WindowsDefenderATP API: its permissions
  would need a separate consent, and requiring them breaks consent for tenants without Defender for Endpoint.
- The hunting query is a constant (`DefenderHealthMapper.DeviceInfoQuery`); never interpolate into KQL.
- `DefenderHealthEvaluator` is the only place that turns raw data into `DefenderState`; the UI only displays it.
- Defender reads never fail a sync: skip what failed, set `DeviceSyncResult.Warning`, and mark sensor data
  unavailable so missing sensors aren't reported as "not onboarded".
- Match Defender devices to Intune by Entra device ID; a host-name fallback only when unique on both sides.

## Data protection invariants
- With PostgreSQL the key ring is shared through `data_protection_keys` (`DatabaseXmlRepository`), always
  encrypted with the key-encryption certificate (`DataProtection:CertificateThumbprint`). The repository
  refuses elements still marked `requiresEncryption`; never store keys unencrypted or add a plaintext fallback.
- Startup fails rather than silently giving each instance its own keys: database store without a
  certificate, a malformed thumbprint, or a missing (current or previous) certificate. `Local` is an
  explicit single-instance choice.
- Keep `SetApplicationName(KeyRing.ApplicationName)`; changing it invalidates every cookie and stored consent state.
- The key-encryption certificate is the portal's own; it is not the Graph app's certificate and the
  portal still never calls Graph.

## Next steps (in order)
1. n8n-style remediation from "What this is": build on the device action queue (separate remediation app,
   approval policy, fail-closed audit); which actions and who approves them is a decision to make before any code.
2. Launching GoPhish campaigns from SecurePulse is deliberately not built: it sends email to people, so it
   needs its own approval and consent decision first. The GoPhish engine only imports results.

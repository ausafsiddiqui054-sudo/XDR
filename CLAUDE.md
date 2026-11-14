# CLAUDE.md — Hasinix

Context for Claude Code working in this repository.

## What this is
A multi-tenant M365/Entra security posture platform for SMBs and MSPs, with a focus on
GCC healthcare (UAE IA, DoH ADHICS mappings). Engines: Maester, ScubaGear (Phase 1);
Wazuh, GoPhish, n8n-style remediation (later phases). Read README.md for layout and status.

## Stack
- .NET 10, C#, `Hasinix.slnx`
- Blazor Server (interactive server render mode, set globally on `<Routes>` in App.razor)
- MudBlazor 8 with the theme in `src/Hasinix.Web/Theme/HasinixTheme.cs`
  (Material 3 Expressive look: navy-and-orange palette taken from the falcon logo, tonal surfaces, 12–28px radii and pill buttons,
  Google Sans Flex served from `wwwroot/fonts`: no font or other third-party requests from pages).
  Shared styles and tokens (`--sp-shape-*`, `--sp-hero-*`, `--sp-text-min`: no text under 11px) are in `wwwroot/app.css`.
  Page titles use `Class="sp-page-title"`; loading states use `<ExpressiveLoading />`
- PowerShell 7 engines launched out of process from .NET
- PostgreSQL via EF Core (`Hasinix.Data`); repositories use `IDbContextFactory`
- `Hasinix.Worker` (generic host) runs background jobs; the portal never calls Graph

## Architecture rules
1. Every engine implements `IScanEngine` and returns normalized `Finding`s. Never let
   engine-specific shapes leak past `Hasinix.Engines`. Likewise Graph shapes stay inside
   `Hasinix.Intune`, which returns normalized `ManagedDevice`s via `IDeviceInventorySource`.
2. PowerShell engines run out of process. Pass arguments with `ProcessStartInfo.ArgumentList`,
   never string concatenation. API engines (Wazuh, GoPhish) make bounded, read-only HTTP calls from the Worker.
   Validate tenant inputs (GUIDs, thumbprints, group names) before use.
3. No secrets in code, config or the database. Certificates live in a vault/cert store;
   `Tenant.CredentialReference` is only a reference.
4. Scoring lives only in `RiskScoreCalculator`. UI never re-implements scoring.
5. Assessment uses read-only Graph permissions; any write/remediation action needs
   separate consent, an explicit approval step and an audit log entry.
6. `Hasinix.Core` has no external package dependencies.

## Naming collision
MudBlazor has its own `Severity` (snackbars). In Razor, `_Imports.razor` aliases
`Severity` to `Hasinix.Core.Models.Severity`; use `MudBlazor.Severity` explicitly for
snackbars. Do the same alias in any .cs file that imports both namespaces.

## Names kept from before the rename
The product was renamed from SecurePulse to Hasinix (solution, projects, namespaces, config keys).
These identifiers keep the old name on purpose, because they are tied to stored or external state.
Don't rename them without that decision:
- `KeyRing.ApplicationName` and the `SecurePulse.Auth` cookie: changing either signs everyone out and
  invalidates stored consent state. Likewise the `SecurePulse.Onboarding.ConsentState.v1` protector purpose.
- `PortalClaims.Issuer` / `AuthenticationType` ("SecurePulse").
- Sentinel export: stream `Custom-SecurePulseAudit`, column `SecurePulseTenantId`, `Source` value. A client's
  data collection rule and table are built to these names.
- `ConfigurationFixes` policy prefix `SecurePulse - `: policies are found again by name, so a new prefix
  would create duplicates in tenants that already have them.
- Lowercase and uppercase forms: PostgreSQL roles (`securepulse_audit_purge`, `securepulse_maintenance`),
  the `SECUREPULSE_TEST_*` environment variables, `UserSecretsId`s and the `@securepulse.dev` dev personas.

## Commands
```bash
dotnet build Hasinix.slnx
dotnet run --project src/Hasinix.Web
dotnet run --project src/Hasinix.Worker   # needs ConnectionStrings:Hasinix
dotnet test Hasinix.slnx                  # set SECUREPULSE_TEST_POSTGRES for DB tests
dotnet tool restore && dotnet ef migrations add <Name> --project src/Hasinix.Data
```

Never edit an applied migration; add a new one. Enums are stored as strings.

## Onboarding invariants
- A consent callback alone never connects a tenant: the Worker must get a real app-only token
  and check its `roles` (all of `AssessmentPermissions.Required`, nothing outside
  `AssessmentPermissions.IsReadOnly`).
- Consent links are single-use, expiring, bound to the domain's Entra tenant; only a SHA-256
  of `state` is stored for lookup. The portal holds no Graph certificate and never calls Graph.

## Sign-in invariants
- Authorization reads only claims Hasinix issues (`PortalClaims`, issuer "SecurePulse"),
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
- Past scores exist only as `score_snapshots` (`IScoreHistory`, append-only): after each successful scan the Worker
  records `RiskScoreCalculator.Calculate` over all the tenant's stored findings. Findings are replaced by the next
  scan, so a score can't be rebuilt later; there is no backfill. A snapshot failure is logged and never fails the scan.
  Trends (`ScoreTrend` in `Hasinix.Reporting`, one point per day in `Reports:TimeZone`) carry the last score forward
  and combine tenants the way the portfolio score does; `ScoreTrendService` filters by `CanSee`.
- Each Worker runs the engines in its `Scans:Engines` (ScubaGear needs Windows PowerShell 5.1, so a
  Windows Worker); the portal's `Scans:Engines` must list every engine some Worker runs.
- ScubaGear runs only `aad`: its other products need Exchange.ManageAsApp, Sites.FullControl.All or
  directory roles, which break the read-only rule. Don't add products without that decision.
- Shared out-of-process plumbing (validation, work folder, timeout) is in `Engines/OutOfProcessScan.cs`.
- The Graph role check before a scan applies to Graph engines only (`ScanEngines.UsesGraph`); an engine that
  doesn't apply to a tenant (`ScanEngines.AppliesTo`) is neither scheduled nor queued for it.

## Finding tracking invariants
- Owners, due dates and risk acceptances live in `finding_tracking`, keyed by tenant and finding ID with no foreign key to
  `findings`: every scan deletes and re-adds findings, and tracking must survive that. It relies on engines keeping finding
  IDs stable across scans (a Maester test without an ID falls back to its position, which isn't stable).
- Accepting a risk never changes a finding, its status or the score (owner's decision, 2026-11-14): `RiskScoreCalculator`
  doesn't know about tracking. It only labels the finding and lists it under "Accepted risks" in the report.
- Every acceptance has an end date (at most `FindingTrackingPolicy.MaxAcceptanceDays`); past it, it reads as expired
  (`IsExpired`, computed, no job). Four eyes: operators request, an Owner other than the requester decides
  (`WhyCannotDecide`). Approval is fail-closed on the audit entry, since the table keeps only the current state and the
  audit log is the history. Any operator may withdraw or end one.
- All rules are in `FindingTrackingService` (not the UI); changes are audited under `finding.*`. Client viewers read
  their own tenant's tracking and change nothing. Names are stored as "Name <sign-in name>"; show `Person(...)` on screen.

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
- Import only: Hasinix never creates, launches or changes campaigns and never sends email. Its GoPhish
  client goes through `ReadOnlyHttpHandler` (GET/HEAD only); keep it there, since GoPhish keys can write.
- Aggregates only: read `/api/campaigns/summary`, never `/api/campaigns/{id}/results` or anything that names
  recipients. People's names, addresses and IPs never enter Hasinix.
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

## Playbook invariants
- Playbooks only propose: `PlaybookRunner` adds `PendingApproval` requests (with `PlaybookId`) after a successful
  device sync. Never approve, auto-approve or send from a playbook; the device action rules above apply unchanged.
- Proposals are requested as the playbook's last editor (`UpdatedByUserId`), so `DeviceActionPolicy` keeps four eyes.
  Keep `PlaybookRules.ActionsFor` free of destructive actions (retire, wipe); `PlaybookRules.Problem` refuses them too.
- Matching lives in `PlaybookEvaluator` (pure); limits are per playbook: tenant scope, `MaxPerRun`, per-device `Cooldown`
  (any status counts), and one open action per device. Defender actions are Windows only (`DeviceActionPolicy.AppliesTo`).
- New actions must use `RemediationPermissions.Required` only; one needing another permission means re-consent for every
  tenant and is an organisational decision. Playbook edits are Owner-only, audited, and conditional on `UpdatedAt`.
- Pre-approval (`PlaybookPreApproval`) is the only path around a per-action approval: Sync and the Defender actions only
  (`IsEligible`; never Restart), granted by an Owner other than `UpdatedByUserId` for the version they saw, valid 90 days,
  withdrawn by any save, and dead once the granter isn't an Owner. `IsActive` is the single check; the runner and the
  Worker's send path both use it. Auto-approval is fail-closed (audit first) and capped by `DailyAutoLimit` per tenant.

## Configuration fix invariants
- Tenant configuration changes go only through the separate configuration app (`Configuration:*`, `IConfigurationTokenProvider`),
  which may hold exactly `ConfigurationPermissions.Required` (Policy.Read.All + Policy.ReadWrite.ConditionalAccess). Its consent
  never connects a tenant (`CompleteConfigurationAsync`) and is independent of remediation access.
- Only catalog fixes (`ConfigurationFixes`): constant, report-only Conditional Access policies named with `PolicyNamePrefix`. Never
  interpolate tenant or finding data into a policy, never create an enforced policy, never switch one on. `GraphConditionalAccessWriter`
  refuses anything not in the catalog or not report-only, skips a policy that already exists by name, and never retries.
- Every change needs an Owner other than the requester (`ConfigurationChangePolicy`), every time; no pre-approval. Approval and the
  Worker's send are fail-closed (audit first); the Worker re-checks access, approval and token roles before each send.
- Finding playbooks (`FindingPlaybook`) only propose, after a successful scan (`ScanService` → `FindingPlaybookRunner`), as their last
  editor, at most once per tenant and fix per `FindingPlaybookRules.Cooldown`; one open change per tenant and fix
  (`IX_configuration_changes_open`). Adding a fix or a permission is an organisational decision.

## Demo invariants
- `DemoSimulator` stands in for the Worker only with sample data (no connection string), so a demo runs end to end. It changes
  only the in-memory `SampleDataStore`: never call Graph, an engine or any network from it, and keep its audit entries marked
  simulated (actor `DemoSimulator.Actor`, summaries "Simulated: ..."). Proposals go through the shared runners in
  `Hasinix.Playbooks` (also used by the Worker); don't copy their logic into the portal.
- `SampleDataStore(fullDemo: true)` is the portal's demo set (Wazuh/GoPhish findings, scan history, sample certificate
  references, a configuration tenant). Tests use the plain set. `Snapshot()` (the development database seed) strips the
  sample references so a real Worker never tries to use them.
- Both sets seed 90 days of made-up score history per scanned tenant (`SeedScoreHistory`, ending at the tenant's real
  current score; `ScoreHistory()` seeds it into a development database). It is sample data: never write invented
  snapshots for a real tenant.

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
1. Every engine from "What this is" is built. Open decisions: more catalog fixes (each a reviewed policy, and anything beyond
   Conditional Access needs new configuration-app permissions and re-consent) and whether Hasinix may ever enforce a policy.
2. Launching GoPhish campaigns from Hasinix is deliberately not built: it sends email to people, so it
   needs its own approval and consent decision first. The GoPhish engine only imports results.

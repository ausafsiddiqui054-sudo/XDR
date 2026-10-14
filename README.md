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
├── samples/scubagear-results.sample.json ScubaGear 1.8.0's own sample report (CC0; raw tenant export removed)
└── src/
    ├── SecurePulse.Core        Domain models (Finding, Tenant, ManagedDevice, RiskScore) + interfaces
    ├── SecurePulse.Data        EF Core + PostgreSQL repositories, migrations, dev seeder
    ├── SecurePulse.Engines     Engine adapters (Maester, ScubaGear): out-of-process runners + JSON parsers
    ├── SecurePulse.Intune      Intune device inventory over Microsoft Graph (certificate auth)
    ├── SecurePulse.Reporting   RiskScoreCalculator (0–100 score, grade, top risks) and the branded PDF report (QuestPDF)
    ├── SecurePulse.Web         Blazor Server portal (MudBlazor, M3 Expressive-style theme), consent links
    └── SecurePulse.Worker      Background service: consent verification, Intune device sync, scheduled engine scans
tests/
    └── SecurePulse.Tests       xUnit: parser, scoring, Graph client, onboarding, sync, scans, PostgreSQL repositories
```

## Run it

Requirements: .NET 10 SDK. PostgreSQL 14+ for the database mode.

```bash
dotnet restore
dotnet run --project src/SecurePulse.Web
dotnet test
```

Without a connection string the portal runs on **in-memory sample data** (five fictional
tenants), so you can design and demo the UI with nothing else installed. Without
`AzureAd:ClientId`, Development offers a **development sign-in** page to pick a persona
(Owner, MSP admin, a client viewer, or someone without access); outside Development the portal
refuses to start without Entra sign-in. Pages: Overview (`/`),
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
dotnet run --project src/SecurePulse.Worker   # migrates, syncs Intune devices every 4 hours, scans daily
```

The Worker syncs tenants that have granted consent **and** have a certificate thumbprint in
`CredentialReference`. The certificate (with private key) must be in the Worker's
`CurrentUser\My` or `LocalMachine\My` store. Settings live under `DeviceSync` (interval,
parallel tenants) and `Intune` (Graph and authority URLs for national clouds, retries,
timeout) in `src/SecurePulse.Worker/appsettings.json`.

Graph application permissions (read-only, admin consent in each client tenant):

- `DeviceManagementManagedDevices.Read.All`: device inventory, compliance state and Defender
  Antivirus state
- `DeviceManagementConfiguration.Read.All`: per-setting compliance results for devices that
  aren't compliant (one extra call per such device; turn off with `Intune:FetchComplianceSettings`)
- `ThreatHunting.Read.All`: Defender for Endpoint sensor health (one advanced hunting query per
  tenant). Maester needs it too, so connected tenants already have it.

A failed sync keeps the tenant's last good inventory and shows a warning on the Endpoints
page.

### Defender health

Each sync also reads Microsoft Defender health for every device, with no extra consent:

- **Antivirus** (Windows): Intune's `windowsProtectionState` per device (Graph v1.0): antivirus
  and real-time protection on, tamper protection, security intelligence up to date, threat state,
  versions and last scan.
- **EDR sensor** (all platforms): the latest `DeviceInfo` row per device from advanced hunting
  (`POST /security/runHuntingQuery`, last 30 days): onboarding status, sensor health and
  exposure level. Devices are matched by Entra device ID, falling back to the host name only
  when the name is unique on both sides. The KQL is a fixed constant; nothing from a tenant is
  put into it.

`DefenderHealthEvaluator` (in Core) turns that into the device's state, and the sample data
uses the same rules:

| State | When |
|---|---|
| Unhealthy | Antivirus or real-time protection off, tamper protection off, signatures out of date, a threat waiting on remediation, or an onboarded sensor that isn't active |
| Not onboarded | Defender for Endpoint data was read and a Windows, macOS or Linux device isn't onboarded (or a device was only discovered on the network). Phones aren't flagged: mobile onboarding is optional |
| Protected | No issues, and antivirus is confirmed on or the sensor is active |
| Unknown | Nothing to go on (e.g. a phone without mobile Defender, or no data yet) |

Defender data never fails a sync. If the tenant has no Defender for Endpoint licence, or the
hunting query fails, the inventory is still saved, a missing sensor counts as "not checked"
rather than "not onboarded", and the Endpoints page shows the sync's warning. Antivirus calls
that return 404 (not reported yet) aren't errors. Turn the extra calls off with
`Intune:FetchDefenderHealth`.

The Endpoints page shows Protected / Unhealthy / Not onboarded / Unknown tiles and the most
common issues. Click a tile or an issue to filter the device list. Each device page has a
Defender card with the issues, antivirus settings and sensor details. PDF reports include the
same counts and top issues.

To run the PostgreSQL repository tests, point `SECUREPULSE_TEST_POSTGRES` at a server
(no `Database=`) with a role that can create databases. Each test class creates and drops its
own database. Without the variable those tests are reported as skipped.

## Running more than one portal instance

The portal uses ASP.NET Core data protection for the sign-in cookie, antiforgery tokens and the
state behind consent links. Every instance needs the same keys, otherwise a user signed in on one
instance is signed out on the next and consent links can't be shown again. With PostgreSQL the key
ring lives in the `data_protection_keys` table, shared by all instances.

The database never holds the keys in the clear: each key is encrypted with a **key-encryption
certificate** before it's stored, and the repository refuses to store a key that isn't encrypted.
Use a certificate of its own (not the Graph app's), with its private key, in `CurrentUser\My` or
`LocalMachine\My` on every portal host:

| Setting | Default | |
|---|---|---|
| `DataProtection:Store` | `Auto` | `Auto`: the database when PostgreSQL is configured (local in Development without a certificate), otherwise local. `Database` or `Local` to choose. |
| `DataProtection:CertificateThumbprint` | | The key-encryption certificate. Required for the database store. |
| `DataProtection:PreviousCertificateThumbprints` | `[]` | Certificates rotated out, kept until the keys they encrypted have expired (keys live 90 days). |

The portal won't start if the database store is used without a certificate, the thumbprint is
malformed, or a certificate (current or previous) isn't found with its private key. It logs which
store it uses, and warns when a certificate expires within 30 days. `Local` keeps ASP.NET Core's
per-machine folder, for a single instance only; outside Development the portal warns about it.

To rotate the certificate: install the new one on every host, set it as
`CertificateThumbprint`, move the old thumbprint to `PreviousCertificateThumbprints`, and restart
the instances. Remove the old one after 90 days. Switching an existing deployment to the shared
store signs everyone out once, and consent links made before the switch can't be shown again
(create new ones). The Worker applies the migration that creates the table, so update it first.
Blazor Server keeps each user's session on one instance, so the load balancer needs sticky
sessions as well.

## Connecting a client tenant

Tenants → **Connect tenant** creates an Entra admin-consent link for the client's domain. Send
it to the client's Global Administrator (or open it yourself if you are one). After they
approve, Entra redirects to `/onboarding/consent-callback`, and the Worker verifies the consent
before the tenant counts as connected:

1. The portal resolves the domain to its Entra tenant ID through the public OpenID discovery
   document, and builds a link bound to that tenant with a random, single-use `state` (stored
   only as a SHA-256 hash; an encrypted copy lets the link be shown again). Links expire after
   `Onboarding:LinkLifetime` (7 days).
2. The callback accepts consent only for a known, unexpired state from the expected tenant.
   It never connects anything by itself, because its query string comes from a browser.
3. The Worker gets an app-only token for the tenant with its certificate and reads the granted
   permissions (`roles`). It requires every permission in `AssessmentPermissions.Required` and
   rejects anything that isn't read-only. New consent can take minutes to propagate, so it
   retries for `Onboarding:VerificationWindow` (30 minutes).
4. On success it creates the tenant (or updates the existing one on re-consent) with the
   Worker's certificate thumbprint as `CredentialReference`, then runs the first device sync.
   The Connect page updates live through each step.

App registration setup (one multi-tenant app):

- **Supported account types:** accounts in any organizational directory (multi-tenant).
- **Redirect URI (Web):** `https://<portal>/onboarding/consent-callback` (shown on the Connect page).
- **API permissions (Application):** every permission listed on the Connect page (the two Intune
  ones above plus Maester's, see [Security scans](#security-scans)). All are read-only. Nothing
  with Write, Send or FullControl; verification fails if any are granted.
- **Certificates:** upload the public key; install the certificate with its private key only on
  the Worker. Portal: `Onboarding:AppClientId`. Worker: `Intune:AppClientId` and
  `Onboarding:CertificateThumbprint`.

The consent callback and result page are the only portal pages that work without signing in;
the result page shows no tenant data.

## Device remote actions

Sync, restart, retire and wipe for Intune devices, from a device's page. They are write actions,
so each one needs three things: remediation consent on the tenant, a second person's approval,
and audit entries from request to result.

**Remediation consent (a separate app).** Device actions use a second Entra app registration that
holds only `DeviceManagementManagedDevices.PrivilegedOperations.All` (Graph, application), with its
own certificate. The read-only assessment app never gets write permissions. On a connected tenant,
an Owner chooses **Enable remediation**, which creates a consent link for the remediation app (the
same single-use, expiring, tenant-bound link as onboarding). After the admin approves, the Worker
gets a token for the remediation app and checks its `roles`: it must hold that one permission and
nothing else, or verification fails. Only then does the tenant become *Remediation access*, with
the remediation certificate's thumbprint stored as a reference next to the read-only one.
**Turn off remediation** (Owner) moves the tenant back to read-only and cancels open requests; the
tenant's admin should also remove the remediation app under Enterprise applications.

**Request and approval.**

| | Who |
|---|---|
| Request (with a reason) | Owner or MSP admin, on a tenant with remediation access |
| Approve sync or restart | Another Owner or MSP admin |
| Approve retire or wipe | Another Owner (typing the device name to confirm) |
| Reject (with a reason) | Another Owner or MSP admin |
| Cancel | Any Owner or MSP admin, until the Worker starts sending |

Nobody approves their own request. A device has one open request at a time. Requests not approved
within 24 hours expire, and approved ones not sent within an hour expire rather than going out
late. Approval is fail-closed: its audit entry is written first, and if that fails the approval
isn't applied. Pending requests appear under **Device actions**, with a count of the ones waiting
for you in the menu.

**Sending (Worker).** Every 15 seconds (`DeviceActions:PollInterval`) the Worker claims approved
actions (`FOR UPDATE SKIP LOCKED`, so several Workers never send one twice) and for each:

1. re-checks that the tenant still has remediation access and that the stored approval meets the
   policy above (it doesn't trust the queue alone);
2. gets a fresh token for the remediation app and checks its tenant and `roles` again;
3. writes the *sending* audit entry, and sends nothing if that write fails;
4. calls Graph v1.0 once (`syncDevice`, `rebootNow`, `retire`, or `wipe` with no data kept).

Failures are recorded with the reason and never retried; request it again if it's still needed.
A timeout or a Worker that stopped mid-call is reported as *outcome unknown: check the device in
Intune*, since the action may have reached it. *Sent* means Intune accepted it; it runs when the
device next checks in.

Setup:

- **Remediation app registration:** multi-tenant, the same redirect URI as the main app, API
  permission `DeviceManagementManagedDevices.PrivilegedOperations.All` (Application) only, and a
  certificate of its own (private key only on the Worker).
- **Portal:** `Onboarding:RemediationAppClientId` (must differ from `Onboarding:AppClientId`).
- **Worker:** `Remediation:AppClientId`, `Remediation:CertificateThumbprint` (in the Worker user's
  store), optionally `Remediation:SendTimeout` (60 seconds), `DeviceActions:Enabled`,
  `DeviceActions:PollInterval` and `DeviceActions:StuckSendingAfter` (10 minutes).

## Security scans

The Worker runs [Maester](https://maester.dev) and, on a Windows Worker,
[ScubaGear](https://github.com/cisagov/ScubaGear) (CISA's SCuBA baselines) against each connected
tenant (consent granted and a certificate in `CredentialReference`). Results are stored as
findings, which drive the score and the fix list; each engine replaces only its own findings.

`Scans:Engines` (default `["Maester"]`) says which engines a Worker runs. ScubaGear needs
Windows PowerShell 5.1, so a typical setup is a Linux Worker with `Maester` and a Windows Worker
with `ScubaGear` (device sync and onboarding turned off there with `DeviceSync:Enabled` and
`Onboarding:Enabled`); both share the queue and each claims only its own engines' runs. Set the
portal's `Scans:Engines` to all the engines your Workers run: the portal shows one status line per
engine and queues **Scan now** for each. In environment variables: `Scans__Engines__0=Maester`,
`Scans__Engines__1=ScubaGear`.

- **Schedule:** a tenant is scanned when it has never been scanned, `Scans:Interval` (1 day)
  after its last scan, or `Scans:RetryFailedAfter` (2 hours) after a failed one. A new tenant
  gets its first scan within `Scans:PollInterval` (1 minute) of connecting.
- **Queue:** runs live in the `scan_runs` table (Queued → Running → Succeeded/Failed), so they
  survive restarts and several Workers can share the work. A tenant has at most one queued or
  running scan per engine (enforced by a unique index); claims use `FOR UPDATE SKIP LOCKED`.
  Manual scans go ahead of scheduled ones. Up to `Scans:MaxParallelScans` (2) run at once; a run
  stuck in Running for `Scans:StaleAfter` (45 minutes, longer than every engine's `Timeout`) is
  failed so it can be retried.
- **Portal:** Owners and MSP admins can **Run scan** (Overview, all ready tenants) or **Scan
  now** (Tenants, one tenant). The portal only queues the run and records *Scan requested* in the
  audit log; the Worker does the work. Each tenant card shows the latest run (queued, running
  with start time, failed with the error, or the last result) and updates while a scan runs.
- **Failures** keep the tenant's previous findings. Before each scan the Worker gets a token
  and checks its `roles` like onboarding does: anything that isn't read-only stops the scan, and
  missing permissions for *that engine* fail it with "Re-consent needed: …" (so a tenant that
  hasn't re-consented for ScubaGear keeps its Maester scans).
- **Re-consent:** tenants connected before a permission was added must approve again. **Re-consent**
  on the tenant card opens the Connect page filled in; the new consent updates the same tenant.

### Maester

Worker setup (Windows or Linux):

```powershell
# PowerShell 7 on the Worker host
Install-Module Maester -Scope AllUsers            # also installs Pester and Microsoft.Graph.Authentication
Install-MaesterTests -Path /srv/securepulse/maester-tests
```

Then set `Maester:TestsPath` to that folder and, optionally, `Maester:PwshPath` and
`Maester:ModuleVersion` (pin a tested version, e.g. `2.3.0`; empty loads the newest installed).
`Maester:AppClientId` defaults to `Intune:AppClientId`. The scan signs in with the same
certificate as device sync (`Connect-MgGraph -CertificateThumbprint`), so it must be in the
Worker user's certificate store. Each run gets its own owner-only work folder under
`Maester:WorkRoot`, deleted afterwards; arguments go through `ArgumentList`, and tenant names
never reach the command line.

Graph application permissions Maester needs for unattended runs (2.3.0), all read-only:
`AuditLog.Read.All`, `DeviceManagementConfiguration.Read.All`,
`DeviceManagementManagedDevices.Read.All`, `DeviceManagementRBAC.Read.All`,
`DeviceManagementServiceConfig.Read.All`, `Directory.Read.All`,
`DirectoryRecommendations.Read.All`, `EntitlementManagement.Read.All`,
`IdentityRiskEvent.Read.All`, `NetworkAccess.Read.All`,
`OnPremDirectorySynchronization.Read.All`, `OrgSettings-AppsAndServices.Read.All`,
`OrgSettings-Forms.Read.All`, `Policy.Read.All`, `Policy.Read.ConditionalAccess`,
`Reports.Read.All`, `ReportSettings.Read.All`, `RoleEligibilitySchedule.Read.Directory`,
`RoleManagement.Read.All`, `RoleManagementAlert.Read.Directory`,
`SecurityIdentitiesHealth.Read.All`, `SecurityIdentitiesSensors.Read.All`,
`SharePointTenantSettings.Read.All`, `ThreatHunting.Read.All`,
`UserAuthenticationMethod.Read.All`.

Maester's optional extras are not requested because they aren't read-only:
`ReportSettings.ReadWrite.All`, `Sites.FullControl.All` and the Exchange `Exchange.ManageAsApp`
role. Checks that need them (Exchange Online, Teams, some SharePoint settings) are reported as
skipped, and skipped checks don't count toward the score.

### ScubaGear

ScubaGear assesses the tenant's **Entra ID** configuration against CISA's SCuBA baseline
(`-ProductNames aad`). Its other products aren't run, because unattended runs need permissions
SecurePulse's read-only consent doesn't grant: Exchange Online and Defender need
`Exchange.ManageAsApp` plus the Global Reader role, Teams needs Global Reader, SharePoint needs
`Sites.FullControl.All`, and Power Platform needs an interactive registration. A token with
`Exchange.ManageAsApp` or `Sites.FullControl.All` would also stop every scan at the read-only
check. Maester covers some of the same Exchange and Teams settings when they're licensed.

Worker setup (Windows only, Windows PowerShell 5.1, ScubaGear 1.8.0):

```powershell
# Windows PowerShell 5.1 (not pwsh), as the account the Worker runs under
Install-Module ScubaGear -Scope CurrentUser
Install-ScubaDependencies                         # Graph auth + powershell-yaml modules and OPA (~/.scubagear/Tools)
```

Then add `ScubaGear` to the Windows Worker's `Scans:Engines` and, optionally, set
`ScubaGear:ModuleVersion` (pin e.g. `1.8.0`; the parser is written against its output),
`ScubaGear:OpaPath`, `ScubaGear:PowerShellPath` (default `powershell.exe`) and
`ScubaGear:Timeout` (30 minutes). `ScubaGear:AppClientId` defaults to `Intune:AppClientId`. The
certificate must be in the Worker user's `Cert:\CurrentUser\My`. The script runs with
`-ExecutionPolicy RemoteSigned` (a Group Policy setting still wins). Each run gets its own work
folder, deleted afterwards because ScubaGear exports the tenant's configuration there.

Extra Graph application permissions (ScubaGear 1.8.0, Entra ID), all read-only, on top of
`Directory.Read.All` and `Policy.Read.All`: `PrivilegedAccess.Read.AzureADGroup`,
`PrivilegedEligibilitySchedule.Read.AzureADGroup`, `RoleManagement.Read.Directory`,
`RoleManagementPolicy.Read.AzureADGroup`, `User.Read.All`. Add them to the app registration;
tenants connected earlier need **Re-consent** before their ScubaGear scans succeed.

How results map: each control becomes a finding with the control ID (e.g. `MS.AAD.1.1v1`), the
requirement as its title and a link to its section of the baseline. *SHALL* controls are High,
*SHOULD* Medium and *MAY* Low; Fail and Warning (a SHOULD not met) count as failed; N/A (manual
or third-party checks), errors and omissions aren't evaluated. Findings carry the framework
"CISA SCuBA" and a "BOD 25-01" tag where CISA marks the control as required by that directive. If
ScubaGear can't evaluate any control (for example, sign-in failed), the scan fails and the
previous results are kept.

## Sign-in and roles

The portal signs people in with Microsoft Entra ID (Microsoft.Identity.Web, multi-tenant).
**Access is decided by SecurePulse, not by Entra app roles:** a client tenant's admin could
assign our app's roles in their own tenant, so role claims in tokens are stripped at sign-in and
never trusted. Roles live in the `portal_users` table:

| Role | Sees | Can |
|---|---|---|
| Owner | All tenants | Everything, including inviting and removing anyone |
| MSP admin | All tenants | Onboard tenants, invite and remove client viewers |
| Client viewer | Their own tenant only | Read-only; no onboarding, remote actions or people management |

- **Invitations** name a sign-in name and the Entra tenant the person must sign in from (your own
  tenant for Owners and MSP admins, the client's tenant for viewers). The first matching
  sign-in binds the invitation to the person's immutable object ID; after that only
  (tenant, object ID) counts, so a renamed account keeps access and a new account reusing the
  name doesn't get it.
- **Scoping** happens in the data services, so a viewer can't reach another tenant's data by
  URL; other tenants' devices read as "not found".
- **Every page and endpoint** requires a portal role by default (fallback policy plus a default
  `[Authorize]` on pages). Public: the consent callback and result page, sign-in, static assets.
- **Changes reach open sessions** within a minute: Blazor circuits re-check the database.
- **At least one signed-in Owner** must always remain (enforced in a serializable transaction).

Setup:

1. Register an app for portal sign-in (separate from the assessment app is cleanest):
   multi-tenant, Web redirect URI `https://<portal>/signin-oidc`, front-channel logout
   `https://<portal>/signout-callback-oidc`, **ID tokens** enabled. It needs no API permissions
   and no secret or certificate: the portal only signs people in.
2. Set `AzureAd:ClientId`, `Auth:OperatorTenantId` (your own Entra tenant ID) and
   `Auth:BootstrapOwners` (sign-in names in your tenant invited as Owner at startup).
3. Sign in as a bootstrap Owner and invite everyone else under **People**.

## Audit log

Security events go to an append-only `audit_events` table, shown under **Audit log** to Owners
and MSP admins (filters by period, area, outcome, tenant and text; **Export CSV** with the same
filters).

| Area | Events |
|---|---|
| Sign-in | Sign-ins (incl. people without access, as *Denied*), invitation accepted, sign-outs |
| People | Invited, role changed, access removed, including refused attempts (*Denied*) and last-Owner refusals (*Failure*) |
| Onboarding | Consent link created or cancelled; consent received, declined, from the wrong tenant, or on an expired/used link; tenant connected or verification failed (Worker) |
| Devices | Remote actions: requested, approved (or an approval that didn't apply), rejected, cancelled, expired, *sending* (written by the Worker before the Graph call) and the result |
| Scans | Scan requested from the portal (scheduled scans are in `scan_runs`, not the audit log) |
| Audit log | Each CSV export |
| Reports | Each PDF report download |

- **Append-only in the database:** a trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on
  `audit_events`, so entries can't be changed through the app or with its credentials. No
  foreign keys, so entries outlive the tenants and people they mention.
- **Not recorded on purpose:** consent callbacks with an unknown `state` (the endpoint is public,
  so they go to the application log rather than letting anyone fill the table) and the Worker's
  verification retries (only the final result).
- **Actors** are stored as shown at the time ("Name <sign-in name>", "SecurePulse Worker",
  "Client admin (not signed in to SecurePulse)") plus the portal user ID.
- **IP addresses** are recorded for sign-in, sign-out, export and the consent callback (HTTP
  requests). Behind a reverse proxy, enable forwarded headers so this is the client's address.
  Actions inside an open Blazor session don't carry one.
- If writing an audit entry fails, the action stands and the failure is logged at Critical
  level. CSV cells that start with `=`, `+`, `-`, `@` or a tab are prefixed with `'` so
  spreadsheets don't run them as formulas.

## Client reports (PDF)

**Report** on a tenant card, **Download report** on the Findings page (with a tenant selected) and
on a client viewer's Overview download a branded PDF for one tenant:

- a cover with the brand, tenant, score ring and grade;
- a summary (open findings by severity, pass rate, device compliance);
- the ten things to fix first, linked to their details;
- results by area, with Intune device compliance, Defender health and the longest-unseen non-compliant devices;
- every finding to fix, with evidence, remediation and a link to the check's documentation (https only);
- the checks that pass, and how the score is calculated (weights read from `RiskScoreCalculator`).

The score is `RiskScoreCalculator`'s, the same as in the portal. Client viewers can download
only their own tenant's report; any other tenant returns 404. A tenant without scan results
returns 409. Each download is recorded as *Report downloaded* in the audit log. The file is
generated per request and not stored.

**License (required).** Reports use [QuestPDF](https://www.questpdf.com), which must be told which
license tier your organisation holds. Reports stay off (buttons disabled, the endpoint returns
503) until `Reports:QuestPdfLicense` is set:

- `Community`: free only for organisations under USD 1M annual gross revenue, individuals,
  charities, academic institutions and OSI open-source projects. Public-sector bodies and listed
  companies never qualify.
- `Professional` or `Enterprise`: paid; needed before production use otherwise.

See QuestPDF's [license guide](https://www.questpdf.com/license/guide.html). SecurePulse never picks
a tier for you.

Branding settings:

| Setting | Default | |
|---|---|---|
| `Reports:Branding:CompanyName` | `SecurePulse` | Shown on reports for tenants without a partner. A tenant's `PartnerName` (its MSP) is used instead when set. |
| `Reports:Branding:LogoPath` | (shield) | PNG, JPEG or SVG, at most 1 MB, relative to the portal's content root. |
| `Reports:Branding:AccentColor` | `#4F46C8` | Headings, rules and the brand bar. |
| `Reports:Branding:ContactLine` | | E.g. `security@msp.example · +971 4 000 0000`, under the brand on the cover. |
| `Reports:TimeZone` | `UTC` | For printed dates, e.g. `Asia/Dubai`. |

Invalid settings stop the portal at startup rather than producing broken reports. Text uses
QuestPDF's bundled Lato with Noto Sans Arabic (SIL OFL 1.1, embedded in `SecurePulse.Reporting`)
as fallback, so Arabic tenant, device and user names render without fonts on the host. Other
scripts (e.g. CJK, emoji) print as placeholders rather than failing the report; add a Noto font
to `src/SecurePulse.Reporting/Fonts` and to `ReportFonts.Families` if you need them.

## How scoring works

Each evaluated check is weighted by severity (Critical 10, High 6, Medium 3, Low 1, Info 0).
Score = share of weight that passed; "Investigate" earns half credit; skipped or unlicensed
checks are excluded. Any open **Critical** caps the grade at C.

## Status

| Area | State |
|---|---|
| Core models, scoring, Maester parser | Built; covered by `SecurePulse.Tests` |
| Maester engine runner | Built; tested with a stand-in `pwsh`; needs a real tenant + certificate to exercise |
| Portal (Overview, Findings, Tenants) | Built; sample data or PostgreSQL |
| Endpoints (Intune device inventory, device detail) | Built |
| Defender health per device (Intune antivirus state, Defender for Endpoint sensor via advanced hunting) | Built; tested with stubbed Graph and against PostgreSQL 16; needs a real tenant with Defender for Endpoint to exercise |
| Device remote actions (remediation consent, approval queue, Worker sending via Graph) | Built; tested with stubbed Graph and against PostgreSQL 16; needs the remediation app registration and a real tenant to exercise |
| PostgreSQL persistence (`SecurePulse.Data`) | Built; tested against PostgreSQL 16 |
| Shared data-protection key ring (PostgreSQL, certificate-encrypted) | Built; tested against PostgreSQL 16 and with two portal instances |
| Worker: Intune device sync | Built and tested against stubbed Graph; needs a real tenant + certificate to exercise |
| Tenant onboarding (admin consent, verification, first sync) | Built; tested with stubbed Entra; needs the app registration to exercise |
| Worker: scheduled Maester scans (queue, retries, permission check, Run scan / Scan now) | Built; tested against PostgreSQL 16 and end to end with a stand-in `pwsh` |
| ScubaGear engine (Entra ID baseline, Windows Worker) | Built; parser tested against ScubaGear 1.8.0's sample report, runner end to end with a stand-in; needs a Windows Worker, a real tenant and certificate to exercise |
| Portal sign-in with roles (Entra ID, Owner / MSP admin / Client viewer) | Built; tested with development sign-in and the real Entra redirect |
| Security audit log (append-only, page + CSV export) | Built; tested against PostgreSQL 16 |
| Branded PDF client report (QuestPDF) | Built; content checked by extracting the PDF's text; off until `Reports:QuestPdfLicense` is set |

## Security notes

- Scans use app-only auth with **certificates**, never client secrets in code or config.
- `Tenant.CredentialReference` holds only a certificate thumbprint / vault reference.
- Engines run **out of process** with arguments passed via `ArgumentList`, so tenant data
  can't inject PowerShell and a hung scan can't crash the portal.
- Request **read-only** Graph permissions for assessment; remediation is a separate app with one
  write permission, its own certificate and its own consent, and every action needs a second
  person's approval.
- Portal access comes from SecurePulse's own user table, never from token role claims.
- Security events are kept in an append-only audit table the app can't modify.
- Data-protection keys (sign-in cookie, consent-link state) are shared through PostgreSQL only
  after encryption with a certificate; the portal refuses a shared key store without one.
- Check each engine's license before redistributing modified versions (Wazuh is GPLv2).

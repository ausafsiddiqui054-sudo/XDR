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
    ├── SecurePulse.Web         Blazor Server portal (MudBlazor, M3 Expressive-style theme), consent links
    └── SecurePulse.Worker      Background service: consent verification, scheduled Intune device sync
tests/
    └── SecurePulse.Tests       xUnit: parser, scoring, Graph client, onboarding, sync, PostgreSQL repositories
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
- **API permissions (Application):** the read-only Graph permissions above. Nothing with Write,
  Send or FullControl; verification fails if any are granted.
- **Certificates:** upload the public key; install the certificate with its private key only on
  the Worker. Portal: `Onboarding:AppClientId`. Worker: `Intune:AppClientId` and
  `Onboarding:CertificateThumbprint`.

The consent callback and result page are the only portal pages that work without signing in;
the result page shows no tenant data.

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
| Devices | Remote action requests (currently recorded as not sent) |
| Audit log | Each CSV export |

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
| Tenant onboarding (admin consent, verification, first sync) | Built; tested with stubbed Entra; needs the app registration to exercise |
| Worker: scheduled engine scans | Next |
| Portal sign-in with roles (Entra ID, Owner / MSP admin / Client viewer) | Built; tested with development sign-in and the real Entra redirect |
| Security audit log (append-only, page + CSV export) | Built; tested against PostgreSQL 16 |
| ScubaGear adapter, PDF report | Next |

## Security notes

- Scans use app-only auth with **certificates**, never client secrets in code or config.
- `Tenant.CredentialReference` holds only a certificate thumbprint / vault reference.
- Engines run **out of process** with arguments passed via `ArgumentList`, so tenant data
  can't inject PowerShell and a hung scan can't crash the portal.
- Request **read-only** Graph permissions for assessment; remediation is a separate consent.
- Portal access comes from SecurePulse's own user table, never from token role claims.
- Security events are kept in an append-only audit table the app can't modify.
- Check each engine's license before redistributing modified versions (Wazuh is GPLv2).

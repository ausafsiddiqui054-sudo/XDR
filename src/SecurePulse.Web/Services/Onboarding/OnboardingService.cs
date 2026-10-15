using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services.Onboarding;

public sealed class ConnectTenantForm
{
    public string? DisplayName { get; set; }
    public string? PrimaryDomain { get; set; }
    public string? PartnerName { get; set; }
    public string Industry { get; set; } = "Healthcare";
}

/// <param name="Request">The new request, or the one already in progress for this tenant.</param>
/// <param name="Reused">True if an in-progress request for the same tenant was returned instead.</param>
public sealed record StartOnboardingResult(OnboardingRequest? Request, string? Error, bool Reused = false);

public enum ConsentCallbackOutcome
{
    Received,
    Declined,
    WrongTenant,
    ExpiredOrUsed,
    Invalid
}

/// <summary>
/// Admin-consent onboarding, portal side: creates consent links and records the callback.
/// The callback alone never connects a tenant; the Worker verifies the consent with a real
/// app-only token first. The portal holds no certificate and never calls Graph.
/// </summary>
public sealed partial class OnboardingService(
    IOnboardingRepository requests,
    ITenantRepository tenants,
    IDeviceActionRepository deviceActions,
    IConfigurationChangeRepository configurationChanges,
    IEntraTenantResolver resolver,
    IDataProtectionProvider protection,
    OnboardingOptions options,
    TimeProvider time,
    IUserContextAccessor users,
    AuditTrail audit,
    ILogger<OnboardingService> logger)
{
    public const string CallbackPath = "onboarding/consent-callback";

    public static readonly IReadOnlyList<string> Industries =
        ["Healthcare", "Professional services", "Financial services", "Education", "Retail", "Government", "General"];

    private IDataProtector Protector => protection.CreateProtector("SecurePulse.Onboarding.ConsentState.v1");

    public bool IsConfigured => Guid.TryParse(options.AppClientId, out var id) && id != Guid.Empty;

    public bool IsRemediationConfigured => Guid.TryParse(options.RemediationAppClientId, out var id) && id != Guid.Empty
                                           && !string.Equals(options.RemediationAppClientId, options.AppClientId, StringComparison.OrdinalIgnoreCase);

    public bool IsConfigurationConfigured => Guid.TryParse(options.ConfigurationAppClientId, out var id) && id != Guid.Empty
                                             && !string.Equals(options.ConfigurationAppClientId, options.AppClientId, StringComparison.OrdinalIgnoreCase)
                                             && !string.Equals(options.ConfigurationAppClientId, options.RemediationAppClientId, StringComparison.OrdinalIgnoreCase);

    /// <summary>The connected tenant this request would update (re-consent), if any.</summary>
    public async Task<Tenant?> GetConnectedTenantAsync(OnboardingRequest request, CancellationToken ct = default) =>
        (await tenants.GetAllAsync(ct)).FirstOrDefault(t => t.EntraTenantId == request.EntraTenantId
            && t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted);

    // Onboarding is for operators only. Pages enforce that with a policy; these checks keep
    // the service safe if it's ever called from somewhere else.

    public async Task<OnboardingRequest?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await RequireOperatorAsync();
        return await requests.GetAsync(id, ct);
    }

    public async Task<IReadOnlyList<OnboardingRequest>> GetOpenAsync(CancellationToken ct = default) =>
        (await users.GetAsync()).IsOperator ? await requests.GetOpenAsync(ct) : [];

    public async Task CancelAsync(Guid id, CancellationToken ct = default)
    {
        var actor = await RequireOperatorAsync();
        if (await requests.GetAsync(id, ct) is not { Status: OnboardingStatus.AwaitingConsent or OnboardingStatus.Failed } request) return;
        await requests.CancelAsync(id, ct);
        await audit.RecordAsync(AuditActions.LinkCancelled, AuditOutcome.Success, $"Cancelled the connection for {request.PrimaryDomain}",
            targetType: "OnboardingRequest", targetId: id.ToString(), details: Details(request), actor: actor);
    }

    private static Dictionary<string, string> Details(OnboardingRequest r)
    {
        var details = new Dictionary<string, string>
        {
            ["domain"] = r.PrimaryDomain,
            ["entraTenantId"] = r.EntraTenantId.ToString(),
            ["clientName"] = r.DisplayName
        };
        if (r.Kind == OnboardingKind.Remediation) details["kind"] = "remediation";
        if (r.Kind == OnboardingKind.Configuration) details["kind"] = "configuration";
        return details;
    }

    private async Task<UserContext> RequireOwnerAsync()
    {
        var user = await users.GetAsync();
        return user.IsOwner ? user : throw new UnauthorizedAccessException("Only Owners can change remediation access.");
    }

    /// <summary>
    /// Starts write consent to the separate remediation app for a connected tenant (Owners only).
    /// Like assessment consent, the callback alone changes nothing: the Worker verifies the grant.
    /// </summary>
    public async Task<StartOnboardingResult> StartRemediationAsync(Guid tenantId, CancellationToken ct = default)
    {
        var actor = await RequireOwnerAsync();
        if (!IsRemediationConfigured)
            return new(null, "Onboarding:RemediationAppClientId isn't set to the remediation app's client ID (a different app from the assessment one).");
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant)
            return new(null, "Tenant not found.");
        if (tenant.ConsentState != TenantConsentState.ReadOnlyGranted)
            return new(null, tenant.ConsentState == TenantConsentState.RemediationGranted
                ? $"{tenant.DisplayName} already has remediation access."
                : $"{tenant.DisplayName} has to be connected for assessment first.");

        var now = time.GetUtcNow();
        var inProgress = (await requests.GetOpenAsync(ct)).FirstOrDefault(r => r.Kind == OnboardingKind.Remediation
            && r.EntraTenantId == tenant.EntraTenantId && r.Status is OnboardingStatus.AwaitingConsent or OnboardingStatus.Verifying && !r.IsExpired(now));
        if (inProgress is not null)
            return new(inProgress, null, Reused: true);

        var state = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(),
            Kind = OnboardingKind.Remediation,
            DisplayName = tenant.DisplayName,
            PrimaryDomain = tenant.PrimaryDomain,
            PartnerName = tenant.PartnerName,
            Industry = tenant.Industry,
            EntraTenantId = tenant.EntraTenantId,
            Status = OnboardingStatus.AwaitingConsent,
            CreatedAt = now,
            ExpiresAt = now + options.LinkLifetime,
            ProtectedState = Protector.Protect(state),
            StartedBy = actor.Name
        };
        await requests.AddAsync(request, HashState(state), ct);
        logger.LogInformation("Remediation consent {RequestId} started for {Tenant} by {User}", request.Id, tenant.DisplayName, actor.Name);
        await audit.RecordAsync(AuditActions.LinkCreated, AuditOutcome.Success, $"Created a remediation consent link for {tenant.DisplayName}",
            tenant.Id, "OnboardingRequest", request.Id.ToString(),
            new Dictionary<string, string>(Details(request)) { ["expiresAt"] = request.ExpiresAt.ToString("O") }, actor);
        return new(request, null);
    }

    /// <summary>
    /// Starts consent to the separate configuration app (report-only Conditional Access fixes) for a connected tenant,
    /// Owners only. Independent of remediation access; the Worker verifies the grant before anything changes.
    /// </summary>
    public async Task<StartOnboardingResult> StartConfigurationAsync(Guid tenantId, CancellationToken ct = default)
    {
        var actor = await RequireOwnerAsync();
        if (!IsConfigurationConfigured)
            return new(null, "Onboarding:ConfigurationAppClientId isn't set to the configuration app's client ID (a different app from the other two).");
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant)
            return new(null, "Tenant not found.");
        if (tenant.ConsentState is not (TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted))
            return new(null, $"{tenant.DisplayName} has to be connected for assessment first.");
        if (tenant.CanConfigure)
            return new(null, $"{tenant.DisplayName} already has configuration access.");

        var now = time.GetUtcNow();
        var inProgress = (await requests.GetOpenAsync(ct)).FirstOrDefault(r => r.Kind == OnboardingKind.Configuration
            && r.EntraTenantId == tenant.EntraTenantId && r.Status is OnboardingStatus.AwaitingConsent or OnboardingStatus.Verifying && !r.IsExpired(now));
        if (inProgress is not null)
            return new(inProgress, null, Reused: true);

        var state = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(),
            Kind = OnboardingKind.Configuration,
            DisplayName = tenant.DisplayName,
            PrimaryDomain = tenant.PrimaryDomain,
            PartnerName = tenant.PartnerName,
            Industry = tenant.Industry,
            EntraTenantId = tenant.EntraTenantId,
            Status = OnboardingStatus.AwaitingConsent,
            CreatedAt = now,
            ExpiresAt = now + options.LinkLifetime,
            ProtectedState = Protector.Protect(state),
            StartedBy = actor.Name
        };
        await requests.AddAsync(request, HashState(state), ct);
        logger.LogInformation("Configuration consent {RequestId} started for {Tenant} by {User}", request.Id, tenant.DisplayName, actor.Name);
        await audit.RecordAsync(AuditActions.LinkCreated, AuditOutcome.Success, $"Created a configuration consent link for {tenant.DisplayName}",
            tenant.Id, "OnboardingRequest", request.Id.ToString(),
            new Dictionary<string, string>(Details(request)) { ["expiresAt"] = request.ExpiresAt.ToString("O") }, actor);
        return new(request, null);
    }

    /// <summary>Turns configuration fixes off (Owners only) and cancels open changes. The client's admin should also remove the app in Entra.</summary>
    public async Task<bool> DisableConfigurationAsync(Guid tenantId, CancellationToken ct = default)
    {
        var actor = await RequireOwnerAsync();
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant || !await requests.DisableConfigurationAsync(tenantId, ct))
            return false;

        var cancelled = await configurationChanges.CancelOpenForTenantAsync(tenantId, actor.Name, "Configuration access was turned off.", time.GetUtcNow(), ct);
        await audit.RecordAsync(AuditActions.ConfigurationDisabled, AuditOutcome.Success, $"Turned off configuration access for {tenant.DisplayName}",
            tenant.Id, "Tenant", tenant.Id.ToString(), new Dictionary<string, string> { ["cancelledChanges"] = cancelled.Count.ToString() }, actor);
        foreach (var c in cancelled)
            await audit.RecordAsync(AuditActions.ConfigChangeCancelled, AuditOutcome.Success,
                $"{ConfigurationFixes.Find(c.FixId)?.Title ?? c.FixId} cancelled: configuration access was turned off", tenant.Id, "ConfigurationChange",
                c.Id.ToString(), new Dictionary<string, string> { ["fix"] = c.FixId }, actor);
        return true;
    }

    /// <summary>
    /// Turns remediation off (Owners only): the tenant goes back to read-only, the remediation
    /// credential reference is cleared and open device actions are cancelled. The client's admin
    /// should also remove the remediation app in Entra; SecurePulse stops using it either way.
    /// </summary>
    public async Task<bool> DisableRemediationAsync(Guid tenantId, CancellationToken ct = default)
    {
        var actor = await RequireOwnerAsync();
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant || !await requests.DisableRemediationAsync(tenantId, ct))
            return false;

        var cancelled = await deviceActions.CancelOpenForTenantAsync(tenantId, actor.Name, "Remediation access was turned off.", time.GetUtcNow(), ct);
        await audit.RecordAsync(AuditActions.RemediationDisabled, AuditOutcome.Success, $"Turned off remediation access for {tenant.DisplayName}",
            tenant.Id, "Tenant", tenant.Id.ToString(), new Dictionary<string, string> { ["cancelledActions"] = cancelled.Count.ToString() }, actor);
        foreach (var a in cancelled)
        {
            await audit.RecordAsync(AuditActions.DeviceActionCancelled, AuditOutcome.Success,
                $"{a.Action} of {a.DeviceName} cancelled: remediation access was turned off", tenant.Id, "DeviceAction", a.Id.ToString(),
                new Dictionary<string, string> { ["action"] = a.Action.ToString(), ["deviceId"] = a.DeviceId }, actor);
        }
        return true;
    }

    /// <summary>
    /// Sets or clears (null/blank) the Wazuh agent group a tenant's Wazuh findings come from. Owners only:
    /// a wrong group would show one client another client's endpoints. Each group belongs to one tenant.
    /// </summary>
    public async Task<(bool Ok, string Message)> SetWazuhAgentGroupAsync(Guid tenantId, string? group, CancellationToken ct = default)
    {
        var actor = await RequireOwnerAsync();
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant) return (false, "Tenant not found.");
        var value = string.IsNullOrWhiteSpace(group) ? null : group.Trim();
        if (value is not null && WazuhAgentGroups.Problem(value) is { } problem) return (false, problem);
        if (value == tenant.WazuhAgentGroup) return (true, "No change.");

        if (!await requests.SetWazuhAgentGroupAsync(tenantId, value, ct))
            return (false, $"The Wazuh group '{value}' already belongs to another tenant. Each tenant's agents need their own group.");

        await audit.RecordAsync(AuditActions.WazuhGroupChanged, AuditOutcome.Success,
            value is null
                ? $"Stopped reading Wazuh agents for {tenant.DisplayName} (was group '{tenant.WazuhAgentGroup}')"
                : $"Set {tenant.DisplayName}'s Wazuh agent group to '{value}'{(tenant.WazuhAgentGroup is { } old ? $" (was '{old}')" : "")}",
            tenant.Id, "Tenant", tenant.Id.ToString(),
            new Dictionary<string, string> { ["group"] = value ?? "", ["previousGroup"] = tenant.WazuhAgentGroup ?? "" }, actor);
        return (true, value is null ? $"{tenant.DisplayName} is no longer scanned by Wazuh." : $"{tenant.DisplayName} now reads Wazuh agents in '{value}'.");
    }

    /// <summary>
    /// Turns the import of a tenant's GoPhish results on or off. Owners only: the key in the tenant's Key Vault
    /// secret decides whose campaigns show up in the tenant's findings and report.
    /// </summary>
    public async Task<(bool Ok, string Message)> SetGoPhishEnabledAsync(Guid tenantId, bool enabled, CancellationToken ct = default)
    {
        var actor = await RequireOwnerAsync();
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant) return (false, "Tenant not found.");
        if (tenant.GoPhishEnabled == enabled) return (true, "No change.");

        await requests.SetGoPhishEnabledAsync(tenantId, enabled, ct);
        var secret = GoPhishSecrets.ApiKeySecretName(tenant.Id);
        await audit.RecordAsync(AuditActions.GoPhishChanged, AuditOutcome.Success,
            enabled
                ? $"Turned on GoPhish results for {tenant.DisplayName} (API key in Key Vault secret '{secret}')"
                : $"Turned off GoPhish results for {tenant.DisplayName}",
            tenant.Id, "Tenant", tenant.Id.ToString(),
            new Dictionary<string, string> { ["enabled"] = enabled ? "true" : "false", ["secretName"] = secret }, actor);
        return (true, enabled
            ? $"GoPhish results are on for {tenant.DisplayName}. Store its GoPhish user's API key in Key Vault as '{secret}'."
            : $"GoPhish results are off for {tenant.DisplayName}.");
    }

    private async Task<UserContext> RequireOperatorAsync()
    {
        var user = await users.GetAsync();
        return user.IsOperator ? user : throw new UnauthorizedAccessException("Only Owners and MSP admins can onboard tenants.");
    }

    public async Task<StartOnboardingResult> StartAsync(ConnectTenantForm form, CancellationToken ct = default)
    {
        var actor = await RequireOperatorAsync();
        if (!IsConfigured)
            return new(null, "Onboarding:AppClientId isn't set, so a consent link can't be created.");

        var name = form.DisplayName?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > 256)
            return new(null, "Enter the client's name (up to 256 characters).");

        if (NormalizeDomain(form.PrimaryDomain) is not { } domain)
            return new(null, "Enter the client's domain, like contoso.com or contoso.onmicrosoft.com.");

        var partner = string.IsNullOrWhiteSpace(form.PartnerName) ? null : form.PartnerName.Trim();
        if (partner is { Length: > 256 })
            return new(null, "The partner name can be up to 256 characters.");

        Guid? entraTenantId;
        try
        {
            entraTenantId = await resolver.ResolveAsync(domain, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Could not resolve {Domain} with Entra", domain);
            return new(null, "Couldn't reach Microsoft Entra to look up the domain. Try again in a moment.");
        }

        if (entraTenantId is not { } tid)
            return new(null, $"{domain} isn't a Microsoft 365 / Entra domain. Check the spelling, or use the tenant's .onmicrosoft.com domain.");

        // An already-connected tenant may consent again (e.g. after the app gained permissions);
        // completion updates that tenant instead of creating another.

        var now = time.GetUtcNow();
        var inProgress = (await requests.GetOpenAsync(ct)).FirstOrDefault(r => r.Kind == OnboardingKind.Assessment
            && r.EntraTenantId == tid && r.Status is OnboardingStatus.AwaitingConsent or OnboardingStatus.Verifying && !r.IsExpired(now));
        if (inProgress is not null)
            return new(inProgress, null, Reused: true);

        var state = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(),
            DisplayName = name,
            PrimaryDomain = domain,
            PartnerName = partner,
            Industry = Industries.Contains(form.Industry) ? form.Industry : "General",
            EntraTenantId = tid,
            Status = OnboardingStatus.AwaitingConsent,
            CreatedAt = now,
            ExpiresAt = now + options.LinkLifetime,
            ProtectedState = Protector.Protect(state),
            StartedBy = actor.Name
        };
        await requests.AddAsync(request, HashState(state), ct);
        logger.LogInformation("Onboarding {RequestId} started for {Domain} ({EntraTenantId}) by {User}", request.Id, domain, tid, actor.Name);
        await audit.RecordAsync(AuditActions.LinkCreated, AuditOutcome.Success, $"Created a consent link for {name} ({domain})",
            targetType: "OnboardingRequest", targetId: request.Id.ToString(),
            details: new Dictionary<string, string>(Details(request)) { ["expiresAt"] = request.ExpiresAt.ToString("O") }, actor: actor);
        return new(request, null);
    }

    /// <summary>The admin-consent link, or null once the request is no longer awaiting consent.</summary>
    public string? GetConsentUrl(OnboardingRequest request, string portalBaseUri)
    {
        if (request.Status != OnboardingStatus.AwaitingConsent || request.IsExpired(time.GetUtcNow()) || request.ProtectedState is null)
            return null;

        string state;
        try
        {
            state = Protector.Unprotect(request.ProtectedState);
        }
        catch (CryptographicException)
        {
            return null; // data-protection keys changed since the link was made
        }

        var url = $"{options.AuthorityHost.TrimEnd('/')}/{request.EntraTenantId}/v2.0/adminconsent";
        return QueryHelpers.AddQueryString(url, new Dictionary<string, string?>
        {
            ["client_id"] = request.Kind switch
            {
                OnboardingKind.Remediation => options.RemediationAppClientId,
                OnboardingKind.Configuration => options.ConfigurationAppClientId,
                _ => options.AppClientId
            },
            ["scope"] = $"{options.GraphBaseUrl.TrimEnd('/')}/.default",
            ["redirect_uri"] = GetRedirectUri(portalBaseUri),
            ["state"] = state
        });
    }

    public string GetRedirectUri(string portalBaseUri) =>
        string.IsNullOrWhiteSpace(options.RedirectUri) ? new Uri(new Uri(portalBaseUri), CallbackPath).ToString() : options.RedirectUri;

    /// <summary>
    /// Handles Entra's redirect after the admin-consent prompt. Every value here comes from the
    /// browser, so it is matched against a stored, unexpired, single-use request and the
    /// tenant it was created for. Success only means "consent reported"; the Worker verifies it.
    /// </summary>
    /// <remarks>
    /// Audited only when the state matches a real request: the endpoint is public, so unknown
    /// states go to the application log instead of letting anyone fill the audit table.
    /// </remarks>
    public async Task<ConsentCallbackOutcome> HandleCallbackAsync(
        string? state, string? tenant, string? adminConsent, string? error, string? errorDescription, CancellationToken ct = default,
        string? ipAddress = null)
    {
        if (string.IsNullOrEmpty(state) || state.Length > 128)
            return ConsentCallbackOutcome.Invalid;

        var request = await requests.FindByStateHashAsync(HashState(state), ct);
        if (request is null)
        {
            logger.LogWarning("Consent callback with an unknown state");
            return ConsentCallbackOutcome.Invalid;
        }

        Task Audit(string action, AuditOutcome outcome, string summary, Dictionary<string, string>? extra = null)
        {
            var details = Details(request);
            foreach (var (k, v) in extra ?? []) details[k] = v;
            return audit.RecordAsync(action, outcome, summary, request.TenantId, "OnboardingRequest", request.Id.ToString(), details,
                AuditTrail.ConsentingAdmin, ipAddress);
        }

        var now = time.GetUtcNow();
        if (request.Status != OnboardingStatus.AwaitingConsent || request.IsExpired(now))
        {
            await Audit(AuditActions.ConsentLinkUnusable, AuditOutcome.Failure,
                $"Consent link for {request.PrimaryDomain} used after it expired or was already used");
            return ConsentCallbackOutcome.ExpiredOrUsed;
        }

        if (!string.IsNullOrEmpty(error))
        {
            var reason = FirstLine(errorDescription) ?? FirstLine(error);
            await requests.SetErrorAsync(request.Id, $"The admin didn't grant consent: {reason}", ct);
            await Audit(AuditActions.ConsentDeclined, AuditOutcome.Failure, $"Admin didn't grant consent for {request.PrimaryDomain}",
                new() { ["reason"] = reason ?? "" });
            return ConsentCallbackOutcome.Declined;
        }

        if (!string.Equals(adminConsent, "True", StringComparison.OrdinalIgnoreCase) || !Guid.TryParse(tenant, out var consentedTenant))
            return ConsentCallbackOutcome.Invalid;

        if (consentedTenant != request.EntraTenantId)
        {
            await requests.SetErrorAsync(request.Id,
                $"Consent came from a different Microsoft 365 tenant ({consentedTenant}) than {request.PrimaryDomain}. " +
                $"The admin needs to sign in with an account from {request.PrimaryDomain}.", ct);
            logger.LogWarning("Onboarding {RequestId}: consent from {Actual}, expected {Expected}", request.Id, consentedTenant, request.EntraTenantId);
            await Audit(AuditActions.ConsentWrongTenant, AuditOutcome.Denied,
                $"Consent for {request.PrimaryDomain} came from a different tenant and was rejected",
                new() { ["consentedTenantId"] = consentedTenant.ToString() });
            return ConsentCallbackOutcome.WrongTenant;
        }

        if (!await requests.MarkConsentReceivedAsync(request.Id, now, ct))
        {
            await Audit(AuditActions.ConsentLinkUnusable, AuditOutcome.Failure,
                $"Consent link for {request.PrimaryDomain} used after it expired or was already used");
            return ConsentCallbackOutcome.ExpiredOrUsed;
        }

        await Audit(AuditActions.ConsentReceived, AuditOutcome.Success,
            $"Admin granted consent for {request.PrimaryDomain}; waiting for verification");

        logger.LogInformation("Onboarding {RequestId}: consent reported for {EntraTenantId}; waiting for Worker verification", request.Id, consentedTenant);
        return ConsentCallbackOutcome.Received;
    }

    public static string? NormalizeDomain(string? input)
    {
        var domain = input?.Trim().TrimEnd('.').ToLowerInvariant();
        return domain is not null && DomainPattern().IsMatch(domain) ? domain : null;
    }

    internal static string HashState(string state) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(state)));

    private static string? FirstLine(string? s)
    {
        var line = s?.Split('\n', 2)[0].Trim();
        return string.IsNullOrEmpty(line) ? null : line.Length > 300 ? line[..300] + "…" : line;
    }

    // DNS name with at least one dot, labels 1-63 chars, no leading/trailing hyphen.
    [GeneratedRegex(@"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")]
    private static partial Regex DomainPattern();
}

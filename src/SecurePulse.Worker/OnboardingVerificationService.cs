using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>
/// Turns a reported admin consent into a connected tenant. The portal's callback only says the
/// browser came back with "admin_consent=True"; this proves it by getting a real app-only token
/// for the tenant and checking which permissions it carries.
/// </summary>
public sealed class OnboardingVerificationService(
    IOnboardingRepository requests,
    IGraphTokenProvider tokens,
    IRemediationTokenProvider remediationTokens,
    RemediationOptions remediation,
    IConfigurationTokenProvider configurationTokens,
    ConfigurationOptions configuration,
    DeviceSyncService deviceSync,
    IAuditLog audit,
    IOptions<OnboardingVerificationOptions> options,
    TimeProvider time,
    ILogger<OnboardingVerificationService> logger)
{
    /// <returns>Number of tenants connected in this pass.</returns>
    public async Task<int> VerifyPendingAsync(CancellationToken ct = default)
    {
        var connected = 0;
        foreach (var request in await requests.GetVerifyingAsync(ct))
        {
            if (await VerifyAsync(request, ct)) connected++;
        }
        return connected;
    }

    public async Task<bool> VerifyAsync(OnboardingRequest request, CancellationToken ct = default)
    {
        var o = options.Value;
        var now = time.GetUtcNow();
        var windowOver = now - (request.ConsentReceivedAt ?? request.CreatedAt) > o.VerificationWindow;
        if (request.Kind == OnboardingKind.Remediation)
            return await VerifyRemediationAsync(request, now, windowOver, ct);
        if (request.Kind == OnboardingKind.Configuration)
            return await VerifyConfigurationAsync(request, now, windowOver, ct);

        if (!Thumbprints.IsValid(o.CertificateThumbprint))
            return await FailAsync(request, "Onboarding:CertificateThumbprint isn't set to a valid certificate thumbprint in the Worker.", windowOver, ct);

        var probe = new Tenant
        {
            Id = Guid.Empty,
            EntraTenantId = request.EntraTenantId,
            DisplayName = request.DisplayName,
            PrimaryDomain = request.PrimaryDomain,
            CredentialReference = o.CertificateThumbprint
        };

        string token;
        try
        {
            token = await tokens.GetTokenAsync(probe, ct);
        }
        catch (GraphAuthException ex)
        {
            // Usually propagation right after consent; retried until the window closes.
            return await FailAsync(request, $"Microsoft Entra didn't issue a token for this tenant yet. {ex.Message}", windowOver, ct);
        }

        AccessTokenClaims claims;
        try
        {
            claims = AccessTokenClaims.Parse(token);
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
        {
            return await FailAsync(request, $"Couldn't read the access token: {ex.Message}", final: true, ct);
        }

        if (claims.TenantId != request.EntraTenantId)
            return await FailAsync(request, $"The token was issued for tenant {claims.TenantId}, not {request.EntraTenantId}.", final: true, ct, denied: true);

        var notReadOnly = AssessmentPermissions.NotReadOnly(claims.Roles);
        if (notReadOnly.Count > 0)
        {
            return await FailAsync(request,
                $"The app was granted permissions that aren't read-only ({string.Join(", ", notReadOnly)}). Assessment access must be read-only: " +
                "remove them from the app registration, revoke them in the tenant, and consent again.", final: true, ct, denied: true);
        }

        var missing = AssessmentPermissions.MissingFrom(claims.Roles);
        if (missing.Count > 0)
        {
            return await FailAsync(request,
                $"These permissions weren't granted: {string.Join(", ", missing)}. Add them to the app registration and have the admin consent again.",
                windowOver, ct);
        }

        var tenant = await requests.CompleteAsync(request.Id, new Tenant
        {
            Id = Guid.NewGuid(),
            EntraTenantId = request.EntraTenantId,
            DisplayName = request.DisplayName,
            PrimaryDomain = request.PrimaryDomain,
            PartnerName = request.PartnerName,
            Industry = request.Industry,
            CredentialReference = o.CertificateThumbprint,
            ConsentState = TenantConsentState.ReadOnlyGranted
        }, claims.Roles.Order(StringComparer.OrdinalIgnoreCase).ToList(), now, ct);

        logger.LogInformation("Onboarding {RequestId}: verified consent for {Tenant} ({EntraTenantId}); running first device sync",
            request.Id, tenant.DisplayName, tenant.EntraTenantId);
        await AuditAsync(request, AuditActions.TenantConnected, AuditOutcome.Success,
            $"Verified read-only consent and connected {tenant.DisplayName} ({request.PrimaryDomain})", tenant.Id,
            new() { ["permissions"] = string.Join(", ", claims.Roles.Order(StringComparer.OrdinalIgnoreCase)) }, ct);

        // The tenant is connected either way; a failed first sync shows on the Endpoints page.
        await deviceSync.SyncTenantAsync(tenant, ct);
        return true;
    }

    /// <summary>One of the separate write apps: what its token must carry and what verifying it grants.</summary>
    private sealed record WriteApp(
        string Name,
        string Kind,
        string? Thumbprint,
        string ThumbprintSetting,
        Func<Guid, string, CancellationToken, Task<string>> GetToken,
        IReadOnlyList<string> Required,
        Func<IEnumerable<string>, IReadOnlyList<string>> Unexpected,
        Func<IEnumerable<string>, IReadOnlyList<string>> Missing,
        Func<Guid, string, IReadOnlyList<string>, DateTimeOffset, CancellationToken, Task<Tenant?>> Complete,
        string EnabledAction,
        string EnabledSummary);

    /// <summary>
    /// Remediation consent: the separate remediation app's token must carry the one Intune
    /// permission remote actions need and nothing else. Only then does an already connected tenant
    /// get remediation access, with the remediation certificate recorded as a reference.
    /// </summary>
    private Task<bool> VerifyRemediationAsync(OnboardingRequest request, DateTimeOffset now, bool windowOver, CancellationToken ct) =>
        VerifyWriteAppAsync(request, new WriteApp("remediation", "remediation", remediation.CertificateThumbprint, "Remediation:CertificateThumbprint",
            (tid, thumb, token) => remediationTokens.GetTokenAsync(tid, thumb, token), RemediationPermissions.Required,
            RemediationPermissions.Unexpected, RemediationPermissions.MissingFrom, requests.CompleteRemediationAsync,
            AuditActions.RemediationEnabled, "device actions can now be requested"), now, windowOver, ct);

    /// <summary>
    /// Configuration consent: the separate configuration app's token must carry exactly the Conditional Access
    /// permissions (<see cref="ConfigurationPermissions.Required"/>). Independent of remediation access.
    /// </summary>
    private Task<bool> VerifyConfigurationAsync(OnboardingRequest request, DateTimeOffset now, bool windowOver, CancellationToken ct) =>
        VerifyWriteAppAsync(request, new WriteApp("configuration", "configuration", configuration.CertificateThumbprint, "Configuration:CertificateThumbprint",
            (tid, thumb, token) => configurationTokens.GetTokenAsync(tid, thumb, token), ConfigurationPermissions.Required,
            ConfigurationPermissions.Unexpected, ConfigurationPermissions.MissingFrom, requests.CompleteConfigurationAsync,
            AuditActions.ConfigurationEnabled, "report-only Conditional Access fixes can now be requested"), now, windowOver, ct);

    private async Task<bool> VerifyWriteAppAsync(OnboardingRequest request, WriteApp app, DateTimeOffset now, bool windowOver, CancellationToken ct)
    {
        if (!Thumbprints.IsValid(app.Thumbprint))
            return await FailAsync(request, $"{app.ThumbprintSetting} isn't set to a valid certificate thumbprint in the Worker.", windowOver, ct);

        string token;
        try
        {
            token = await app.GetToken(request.EntraTenantId, app.Thumbprint!, ct);
        }
        catch (GraphAuthException ex)
        {
            return await FailAsync(request, $"Microsoft Entra didn't issue a {app.Name} token for this tenant yet. {ex.Message}", windowOver, ct);
        }

        AccessTokenClaims claims;
        try
        {
            claims = AccessTokenClaims.Parse(token);
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
        {
            return await FailAsync(request, $"Couldn't read the access token: {ex.Message}", final: true, ct);
        }

        if (claims.TenantId != request.EntraTenantId)
            return await FailAsync(request, $"The token was issued for tenant {claims.TenantId}, not {request.EntraTenantId}.", final: true, ct, denied: true);

        var unexpected = app.Unexpected(claims.Roles);
        if (unexpected.Count > 0)
        {
            return await FailAsync(request,
                $"The {app.Name} app was granted more than it needs ({string.Join(", ", unexpected)}). It may hold only " +
                $"{string.Join(" and ", app.Required)}: remove the others from the app registration, revoke them in the tenant, and consent again.",
                final: true, ct, denied: true);
        }

        var missing = app.Missing(claims.Roles);
        if (missing.Count > 0)
        {
            return await FailAsync(request,
                $"These permissions weren't granted: {string.Join(", ", missing)}. Add them to the {app.Name} app and have the admin consent again.",
                windowOver, ct);
        }

        var granted = claims.Roles.Order(StringComparer.OrdinalIgnoreCase).ToList();
        var tenant = await app.Complete(request.Id, app.Thumbprint!, granted, now, ct);
        if (tenant is null)
        {
            await AuditAsync(request, AuditActions.VerificationFailed, AuditOutcome.Failure,
                $"Couldn't add {app.Name} access for {request.PrimaryDomain}: the tenant isn't connected any more", null, new() { ["kind"] = app.Kind }, ct);
            return false;
        }

        logger.LogInformation("Onboarding {RequestId}: {App} access verified for {Tenant} ({EntraTenantId})", request.Id, app.Name, tenant.DisplayName,
            tenant.EntraTenantId);
        await AuditAsync(request, app.EnabledAction, AuditOutcome.Success,
            $"Verified {app.Name} consent for {tenant.DisplayName}; {app.EnabledSummary}", tenant.Id,
            new() { ["permissions"] = string.Join(", ", granted), ["kind"] = app.Kind }, ct);
        return true;
    }

    private async Task<bool> FailAsync(OnboardingRequest request, string error, bool final, CancellationToken ct, bool denied = false)
    {
        await requests.RecordVerificationFailureAsync(request.Id, error, final, ct);
        if (final)
        {
            logger.LogWarning("Onboarding {RequestId} for {Domain} failed: {Error}", request.Id, request.PrimaryDomain, error);
            // Only the final outcome is audited; retries every few seconds would bury real events.
            await AuditAsync(request, AuditActions.VerificationFailed, denied ? AuditOutcome.Denied : AuditOutcome.Failure,
                $"Couldn't verify consent for {request.PrimaryDomain}: {error}", null, new(), ct);
        }
        else
        {
            logger.LogInformation("Onboarding {RequestId} for {Domain} not verified yet: {Error}", request.Id, request.PrimaryDomain, error);
        }
        return false;
    }

    private async Task AuditAsync(OnboardingRequest request, string action, AuditOutcome outcome, string summary, Guid? tenantId,
        Dictionary<string, string> details, CancellationToken ct)
    {
        details["domain"] = request.PrimaryDomain;
        details["entraTenantId"] = request.EntraTenantId.ToString();
        details["startedBy"] = request.StartedBy ?? "";
        try
        {
            await audit.RecordAsync(new AuditEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = time.GetUtcNow(),
                Action = action,
                Outcome = outcome,
                ActorName = "SecurePulse Worker",
                TenantId = tenantId,
                TargetType = "OnboardingRequest",
                TargetId = request.Id.ToString(),
                Summary = summary,
                Details = details
            }, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed for {Action} ({Outcome}): {Summary}", action, outcome, summary);
        }
    }
}

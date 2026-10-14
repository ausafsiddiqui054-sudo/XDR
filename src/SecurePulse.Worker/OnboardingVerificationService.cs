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

    /// <summary>
    /// Remediation consent: the separate remediation app's token must carry the one Intune
    /// permission remote actions need and nothing else. Only then does an already connected tenant
    /// get remediation access, with the remediation certificate recorded as a reference.
    /// </summary>
    private async Task<bool> VerifyRemediationAsync(OnboardingRequest request, DateTimeOffset now, bool windowOver, CancellationToken ct)
    {
        if (!Thumbprints.IsValid(remediation.CertificateThumbprint))
            return await FailAsync(request, "Remediation:CertificateThumbprint isn't set to a valid certificate thumbprint in the Worker.", windowOver, ct);

        string token;
        try
        {
            token = await remediationTokens.GetTokenAsync(request.EntraTenantId, remediation.CertificateThumbprint, ct);
        }
        catch (GraphAuthException ex)
        {
            return await FailAsync(request, $"Microsoft Entra didn't issue a remediation token for this tenant yet. {ex.Message}", windowOver, ct);
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

        var unexpected = RemediationPermissions.Unexpected(claims.Roles);
        if (unexpected.Count > 0)
        {
            return await FailAsync(request,
                $"The remediation app was granted more than it needs ({string.Join(", ", unexpected)}). It may hold only " +
                $"{RemediationPermissions.PrivilegedOperations}: remove the others from the app registration, revoke them in the tenant, and consent again.",
                final: true, ct, denied: true);
        }

        var missing = RemediationPermissions.MissingFrom(claims.Roles);
        if (missing.Count > 0)
        {
            return await FailAsync(request,
                $"These permissions weren't granted: {string.Join(", ", missing)}. Add them to the remediation app and have the admin consent again.",
                windowOver, ct);
        }

        var granted = claims.Roles.Order(StringComparer.OrdinalIgnoreCase).ToList();
        var tenant = await requests.CompleteRemediationAsync(request.Id, remediation.CertificateThumbprint, granted, now, ct);
        if (tenant is null)
        {
            await AuditAsync(request, AuditActions.VerificationFailed, AuditOutcome.Failure,
                $"Couldn't add remediation access for {request.PrimaryDomain}: the tenant isn't connected any more", null, new() { ["kind"] = "remediation" }, ct);
            return false;
        }

        logger.LogInformation("Onboarding {RequestId}: remediation access verified for {Tenant} ({EntraTenantId})", request.Id, tenant.DisplayName, tenant.EntraTenantId);
        await AuditAsync(request, AuditActions.RemediationEnabled, AuditOutcome.Success,
            $"Verified remediation consent for {tenant.DisplayName}; device actions can now be requested", tenant.Id,
            new() { ["permissions"] = string.Join(", ", granted), ["kind"] = "remediation" }, ct);
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

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
    DeviceSyncService deviceSync,
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
            return await FailAsync(request, $"The token was issued for tenant {claims.TenantId}, not {request.EntraTenantId}.", final: true, ct);

        var notReadOnly = claims.Roles.Where(r => !AssessmentPermissions.IsReadOnly(r)).Order().ToList();
        if (notReadOnly.Count > 0)
        {
            return await FailAsync(request,
                $"The app was granted permissions that aren't read-only ({string.Join(", ", notReadOnly)}). Assessment access must be read-only: " +
                "remove them from the app registration, revoke them in the tenant, and consent again.", final: true, ct);
        }

        var missing = AssessmentPermissions.Required.Select(p => p.Name)
            .Where(p => !claims.Roles.Contains(p, StringComparer.OrdinalIgnoreCase)).ToList();
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

        // The tenant is connected either way; a failed first sync shows on the Endpoints page.
        await deviceSync.SyncTenantAsync(tenant, ct);
        return true;
    }

    private async Task<bool> FailAsync(OnboardingRequest request, string error, bool final, CancellationToken ct)
    {
        await requests.RecordVerificationFailureAsync(request.Id, error, final, ct);
        if (final)
            logger.LogWarning("Onboarding {RequestId} for {Domain} failed: {Error}", request.Id, request.PrimaryDomain, error);
        else
            logger.LogInformation("Onboarding {RequestId} for {Domain} not verified yet: {Error}", request.Id, request.PrimaryDomain, error);
        return false;
    }
}

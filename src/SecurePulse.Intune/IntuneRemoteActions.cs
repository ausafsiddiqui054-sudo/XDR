using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SecurePulse.Core.Models;

namespace SecurePulse.Intune;

/// <summary>
/// The separate remediation app: a different Entra app registration from the read-only one, holding
/// only <see cref="RemediationPermissions.PrivilegedOperations"/>, with its own certificate.
/// </summary>
public sealed class RemediationOptions
{
    /// <summary>Client ID of the remediation app (must differ from Intune:AppClientId).</summary>
    public string AppClientId { get; set; } = string.Empty;

    /// <summary>Thumbprint of the remediation app's certificate in the Worker's store; recorded on tenants when they consent.</summary>
    public string CertificateThumbprint { get; set; } = string.Empty;

    /// <summary>How long to wait for Intune to accept one action.</summary>
    public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(60);
}

/// <summary>App-only tokens for the remediation app.</summary>
public interface IRemediationTokenProvider
{
    Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default);
}

public sealed class CertificateRemediationTokenProvider(RemediationOptions remediation, IntuneOptions intune, ICertificateLoader certificates)
    : IRemediationTokenProvider
{
    public Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(remediation.AppClientId, out var clientId) || clientId == Guid.Empty)
            throw new GraphAuthException("Remediation:AppClientId is not configured as a valid GUID.");
        if (string.Equals(remediation.AppClientId, intune.AppClientId, StringComparison.OrdinalIgnoreCase))
            throw new GraphAuthException("Remediation:AppClientId must be a separate app from Intune:AppClientId.");
        if (!Thumbprints.IsValid(thumbprint))
            throw new GraphAuthException("The remediation credential reference is not a valid certificate thumbprint.");
        return AppOnlyToken.AcquireAsync(entraTenantId, clientId, thumbprint, certificates, intune, cancellationToken);
    }
}

public sealed record DeviceActionSendResult(bool Succeeded, string? Error)
{
    public static readonly DeviceActionSendResult Ok = new(true, null);
}

/// <summary>Sends one remote action to Intune. Never retries: a write is sent at most once per approval.</summary>
public interface IDeviceActionSender
{
    Task<DeviceActionSendResult> SendAsync(Guid entraTenantId, string deviceId, DeviceAction action, string accessToken,
        CancellationToken cancellationToken = default);
}

public sealed class IntuneDeviceActionSender(HttpClient http, IntuneOptions intune, RemediationOptions remediation) : IDeviceActionSender
{
    /// <summary>Graph v1.0 managedDevice actions; all need DeviceManagementManagedDevices.PrivilegedOperations.All and return 204.</summary>
    public static string PathFor(DeviceAction action) => action switch
    {
        DeviceAction.Sync => "syncDevice",
        DeviceAction.Restart => "rebootNow",
        DeviceAction.Retire => "retire",
        DeviceAction.Wipe => "wipe",
        _ => throw new ArgumentOutOfRangeException(nameof(action))
    };

    public async Task<DeviceActionSendResult> SendAsync(Guid entraTenantId, string deviceId, DeviceAction action, string accessToken,
        CancellationToken cancellationToken = default)
    {
        // Intune managed device IDs are GUIDs; anything else never reaches a URL.
        if (!Guid.TryParse(deviceId, out var id))
            return new(false, "The device ID isn't a valid Intune managed device ID; nothing was sent.");

        var url = $"{intune.GraphBaseUrl.TrimEnd('/')}/v1.0/deviceManagement/managedDevices/{id}/{PathFor(action)}";
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (action == DeviceAction.Wipe)
        {
            // A full wipe, as the portal describes it: no enrollment data or user data kept.
            request.Content = new StringContent("""{"keepEnrollmentData":false,"keepUserData":false}""", Encoding.UTF8, "application/json");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(remediation.SendTimeout);
        try
        {
            using var response = await http.SendAsync(request, timeout.Token);
            if (response.IsSuccessStatusCode) return DeviceActionSendResult.Ok;

            var body = await response.Content.ReadAsStringAsync(CancellationToken.None);
            var detail = body.Length > 300 ? body[..300] + "…" : body;
            return new(false, response.StatusCode switch
            {
                HttpStatusCode.NotFound => "Intune doesn't know this device any more (it may have been removed). Nothing was done.",
                HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized =>
                    $"Intune refused the action ({(int)response.StatusCode}). Check the remediation app's consent and the tenant's Intune license. {detail}",
                HttpStatusCode.TooManyRequests => "Intune is throttling requests (429), so the action wasn't accepted. Request it again later.",
                _ => $"Intune returned {(int)response.StatusCode}. {detail}"
            });
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, $"No answer from Microsoft Graph within {remediation.SendTimeout.TotalSeconds:0} seconds. The action may still have " +
                              "reached Intune: check the device in Intune before requesting it again.");
        }
        catch (HttpRequestException ex)
        {
            return new(false, $"Couldn't reach Microsoft Graph ({ex.Message}). The action may not have been sent: check the device in Intune " +
                              "before requesting it again.");
        }
    }
}

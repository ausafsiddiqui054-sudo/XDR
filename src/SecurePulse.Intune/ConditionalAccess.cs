using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SecurePulse.Core.Models;

namespace SecurePulse.Intune;

/// <summary>
/// The separate configuration app: a third Entra app registration (not the read-only one, not the remediation
/// one) holding only <see cref="ConfigurationPermissions.Required"/>, with its own certificate.
/// </summary>
public sealed class ConfigurationOptions
{
    public string AppClientId { get; set; } = string.Empty;

    /// <summary>Thumbprint of the configuration app's certificate in the Worker's store; recorded on tenants when they consent.</summary>
    public string CertificateThumbprint { get; set; } = string.Empty;

    public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(60);
}

public interface IConfigurationTokenProvider
{
    Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default);
}

public sealed class CertificateConfigurationTokenProvider(ConfigurationOptions configuration, RemediationOptions remediation, IntuneOptions intune,
    ICertificateLoader certificates) : IConfigurationTokenProvider
{
    public Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(configuration.AppClientId, out var clientId) || clientId == Guid.Empty)
            throw new GraphAuthException("Configuration:AppClientId is not configured as a valid GUID.");
        if (string.Equals(configuration.AppClientId, intune.AppClientId, StringComparison.OrdinalIgnoreCase)
            || string.Equals(configuration.AppClientId, remediation.AppClientId, StringComparison.OrdinalIgnoreCase))
            throw new GraphAuthException("Configuration:AppClientId must be a separate app from the assessment and remediation apps.");
        if (!Thumbprints.IsValid(thumbprint))
            throw new GraphAuthException("The configuration credential reference is not a valid certificate thumbprint.");
        return AppOnlyToken.AcquireAsync(entraTenantId, clientId, thumbprint, certificates, intune, cancellationToken);
    }
}

/// <param name="AlreadyPresent">A policy with the fix's name existed, so nothing was created.</param>
public sealed record ConditionalAccessResult(bool Succeeded, string? PolicyId, string? Error, bool AlreadyPresent = false);

/// <summary>Creates a catalog fix's Conditional Access policy. Never retries: a write is sent at most once per approval.</summary>
public interface IConditionalAccessWriter
{
    Task<ConditionalAccessResult> ApplyAsync(ConfigurationFix fix, string accessToken, CancellationToken cancellationToken = default);
}

public sealed class GraphConditionalAccessWriter(HttpClient http, IntuneOptions intune, ConfigurationOptions configuration) : IConditionalAccessWriter
{
    private const int MaxPages = 20;

    private string PoliciesUrl => $"{intune.GraphBaseUrl.TrimEnd('/')}/v1.0/identity/conditionalAccess/policies";

    public async Task<ConditionalAccessResult> ApplyAsync(ConfigurationFix fix, string accessToken, CancellationToken cancellationToken = default)
    {
        // Only catalog fixes, and only report-only ones, ever reach Graph.
        if (ConfigurationFixes.Find(fix.Id) is not { } known || !ReferenceEquals(known, fix))
            return new(false, null, "Not a catalog fix; nothing was sent.");
        if (ReportOnlyProblem(fix) is { } problem)
            return new(false, null, $"{problem} Nothing was sent.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(configuration.SendTimeout);
        try
        {
            // A policy with this name means an earlier approval already created it (or someone did by hand): don't add a second.
            var (existing, listError) = await FindByNameAsync(fix.PolicyDisplayName, accessToken, timeout.Token);
            if (listError is not null) return new(false, null, $"{listError} Nothing was created.");
            if (existing is not null) return new(true, existing, null, AlreadyPresent: true);

            using var request = new HttpRequestMessage(HttpMethod.Post, PoliciesUrl)
            {
                Content = new StringContent(fix.PolicyJson, Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await http.SendAsync(request, timeout.Token);
            var body = await response.Content.ReadAsStringAsync(CancellationToken.None);
            if (!response.IsSuccessStatusCode)
                return new(false, null, Describe(response.StatusCode, body));

            using var created = JsonDocument.Parse(body);
            var id = created.RootElement.TryGetProperty("id", out var idElement) ? idElement.GetString() : null;
            var state = created.RootElement.TryGetProperty("state", out var s) ? s.GetString() : null;
            if (state != ConfigurationFixes.ReportOnly)
                return new(false, id, $"Graph created policy {id} in state '{state}', not report-only. Check it in Entra Conditional Access now.");
            return new(true, id, null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, null, $"No answer from Microsoft Graph within {configuration.SendTimeout.TotalSeconds:0} seconds. The policy may still " +
                                    "have been created: check Conditional Access in Entra before requesting it again.");
        }
        catch (HttpRequestException ex)
        {
            return new(false, null, $"Couldn't reach Microsoft Graph ({ex.Message}). Check Conditional Access in Entra before requesting it again.");
        }
        catch (JsonException ex)
        {
            return new(false, null, $"Graph's answer couldn't be read ({ex.Message}). Check Conditional Access in Entra before requesting it again.");
        }
    }

    /// <summary>Why the fix's policy body isn't a report-only policy with its own name, or null.</summary>
    public static string? ReportOnlyProblem(ConfigurationFix fix)
    {
        try
        {
            using var doc = JsonDocument.Parse(fix.PolicyJson);
            var root = doc.RootElement;
            if (!root.TryGetProperty("state", out var state) || state.GetString() != ConfigurationFixes.ReportOnly)
                return "The fix's policy isn't report-only.";
            if (!root.TryGetProperty("displayName", out var name) || name.GetString() != fix.PolicyDisplayName)
                return "The fix's policy name doesn't match the catalog.";
            return null;
        }
        catch (JsonException)
        {
            return "The fix's policy isn't valid JSON.";
        }
    }

    private async Task<(string? Id, string? Error)> FindByNameAsync(string displayName, string accessToken, CancellationToken ct)
    {
        string? url = $"{PoliciesUrl}?$select=id,displayName";
        for (var page = 0; url is not null && page < MaxPages; page++)
        {
            // Follow nextLink only on the Graph host we were configured with.
            if (!url.StartsWith(intune.GraphBaseUrl.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase))
                return (null, "Graph returned a next page on another host.");
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await http.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(CancellationToken.None);
            if (!response.IsSuccessStatusCode) return (null, Describe(response.StatusCode, body));
            using var doc = JsonDocument.Parse(body);
            foreach (var p in doc.RootElement.GetProperty("value").EnumerateArray())
                if (p.TryGetProperty("displayName", out var n) && string.Equals(n.GetString(), displayName, StringComparison.OrdinalIgnoreCase))
                    return (p.GetProperty("id").GetString(), null);
            url = doc.RootElement.TryGetProperty("@odata.nextLink", out var next) ? next.GetString() : null;
        }
        return url is null ? (null, null) : (null, "The tenant has more Conditional Access policies than SecurePulse reads.");
    }

    private static string Describe(HttpStatusCode status, string body)
    {
        var detail = body.Length > 300 ? body[..300] + "…" : body;
        return status switch
        {
            HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized =>
                $"Graph refused ({(int)status}). Check the configuration app's consent and the tenant's Entra ID P1 licence (Conditional Access needs it). {detail}",
            HttpStatusCode.TooManyRequests => "Graph is throttling requests (429). Request it again later.",
            _ => $"Graph returned {(int)status}. {detail}"
        };
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace SecurePulse.Web.Services.Onboarding;

/// <summary>Finds the Entra tenant ID behind a domain.</summary>
public interface IEntraTenantResolver
{
    /// <returns>The tenant ID, or null if the domain isn't an Entra tenant.</returns>
    Task<Guid?> ResolveAsync(string domain, CancellationToken ct = default);
}

/// <summary>
/// Uses the tenant's public OpenID discovery document, so no credentials or permissions are
/// needed: {authority}/{domain}/v2.0/.well-known/openid-configuration has issuer
/// {authority}/{tenantId}/v2.0.
/// </summary>
public sealed class EntraTenantResolver(HttpClient http, OnboardingOptions options) : IEntraTenantResolver
{
    public async Task<Guid?> ResolveAsync(string domain, CancellationToken ct = default)
    {
        var url = $"{options.AuthorityHost.TrimEnd('/')}/{Uri.EscapeDataString(domain)}/v2.0/.well-known/openid-configuration";
        using var response = await http.GetAsync(url, ct);

        // Entra answers 400 for names it doesn't know.
        if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();

        var doc = await response.Content.ReadFromJsonAsync<Discovery>(ct);
        if (!Uri.TryCreate(doc?.Issuer, UriKind.Absolute, out var issuer)) return null;
        var segment = issuer.Segments.Skip(1).FirstOrDefault()?.Trim('/');
        return Guid.TryParse(segment, out var tenantId) && tenantId != Guid.Empty ? tenantId : null;
    }

    private sealed class Discovery
    {
        [JsonPropertyName("issuer")] public string? Issuer { get; set; }
    }
}

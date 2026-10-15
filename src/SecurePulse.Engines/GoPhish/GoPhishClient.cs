using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurePulse.Engines.GoPhish;

public sealed class GoPhishException(string message, Exception? inner = null) : Exception(message, inner);

// Subsets of the GoPhish API's responses. Internal: GoPhish shapes never leave SecurePulse.Engines.

internal sealed class GoPhishCampaignSummaries
{
    public long Total { get; set; }
    public List<GoPhishCampaignSummary>? Campaigns { get; set; }
}

internal sealed class GoPhishCampaignSummary
{
    public long Id { get; set; }
    public string? Name { get; set; }
    public string? Status { get; set; }
    [JsonPropertyName("launch_date")] public DateTimeOffset LaunchDate { get; set; }
    [JsonPropertyName("completed_date")] public DateTimeOffset CompletedDate { get; set; }
    public GoPhishCampaignStats? Stats { get; set; }
}

/// <summary>Counts only: GoPhish computes them per campaign, so no recipient is ever named in what SecurePulse reads.</summary>
internal sealed class GoPhishCampaignStats
{
    public long Total { get; set; }
    public long Sent { get; set; }
    public long Opened { get; set; }
    public long Clicked { get; set; }
    [JsonPropertyName("submitted_data")] public long SubmittedData { get; set; }
    [JsonPropertyName("email_reported")] public long EmailReported { get; set; }
    public long Error { get; set; }
}

/// <summary>
/// The two calls the GoPhish engine makes, with one tenant's API key: a HEAD that tells an admin key from a
/// standard user's, and GET /api/campaigns/summary (aggregate counts per campaign). Never the per-recipient
/// results, never a write; the handler refuses anything but GET and HEAD.
/// </summary>
internal sealed class GoPhishClient(HttpClient http, GoPhishOptions options, string apiKey, string keyName)
{
    private Uri ApiUri => new(options.Url.TrimEnd('/') + "/api/");

    /// <summary>
    /// GoPhish allows /api/users/ only to admins, so a 403 here means a standard user. HEAD returns no body,
    /// so an admin key wouldn't even read the user list (which includes everyone's API keys).
    /// </summary>
    public async Task EnsureStandardUserAsync(CancellationToken ct)
    {
        using var response = await SendAsync(HttpMethod.Head, "users/", ct);
        switch (response.StatusCode)
        {
            case HttpStatusCode.Forbidden:
                return;
            case HttpStatusCode.OK:
                throw new GoPhishException($"Not importing: the key in Key Vault secret '{keyName}' belongs to a GoPhish admin, who can manage " +
                    "every user and see their API keys. Give the tenant its own GoPhish user with the standard \"User\" role, run its campaigns as that user, and store that user's key.");
            case HttpStatusCode.NotFound:
                throw new GoPhishException($"The GoPhish server at {ApiUri.Host} has no user roles. Upgrade it to GoPhish 0.9 or later.");
            default:
                await EnsureSuccessAsync(response, ct);
                throw new GoPhishException($"GoPhish answered {(int)response.StatusCode} when checking the key's role.");
        }
    }

    public async Task<List<GoPhishCampaignSummary>> GetCampaignSummariesAsync(CancellationToken ct)
    {
        using var response = await SendAsync(HttpMethod.Get, "campaigns/summary", ct);
        await EnsureSuccessAsync(response, ct);
        var body = await response.Content.ReadFromJsonAsync<GoPhishCampaignSummaries>(JsonSerializerOptions.Web, ct)
                   ?? throw new GoPhishException("GoPhish returned an empty campaign summary.");
        return body.Campaigns ?? [];
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, new Uri(ApiUri, path));
            // A header, not ?api_key=, so the key never lands in a URL or proxy log.
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            HttpResponseMessage response;
            try
            {
                response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
            {
                throw new GoPhishException($"The GoPhish server at {ApiUri.Host} presented a TLS certificate that isn't trusted or doesn't match " +
                    "GoPhish:CertificateSha256. Pin its certificate (SHA-256 fingerprint) or give it a trusted one.", ex);
            }
            catch (HttpRequestException ex)
            {
                throw new GoPhishException($"Couldn't reach the GoPhish server at {ApiUri.Host}: {ex.Message}", ex);
            }
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Dispose();
                throw new GoPhishException($"GoPhish rejected the API key in Key Vault secret '{keyName}' (401). Store the current key of the tenant's GoPhish user there.");
            }
            if (response.StatusCode is (HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable or HttpStatusCode.BadGateway
                    or HttpStatusCode.GatewayTimeout) && attempt < options.MaxRetries)
            {
                var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Pow(2, attempt + 1));
                response.Dispose();
                await Task.Delay(delay > TimeSpan.FromSeconds(60) ? TimeSpan.FromSeconds(60) : delay, ct);
                continue;
            }
            return response;
        }
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;
        string? detail = null;
        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                detail = m.GetString() is { Length: > 300 } text ? text[..300] + "…" : m.GetString();
        }
        catch (JsonException) { /* not JSON */ }
        throw new GoPhishException($"GoPhish returned {(int)response.StatusCode} {response.ReasonPhrase}{(string.IsNullOrWhiteSpace(detail) ? "" : $" ({detail})")}.");
    }
}

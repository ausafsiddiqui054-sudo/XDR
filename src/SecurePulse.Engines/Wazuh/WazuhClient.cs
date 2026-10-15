using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurePulse.Engines.Wazuh;

public sealed class WazuhException(string message, Exception? inner = null) : Exception(message, inner);

// Subsets of the Wazuh server API 4.x responses. Internal: Wazuh shapes never leave SecurePulse.Engines.

internal sealed class WazuhEnvelope<T>
{
    public T? Data { get; set; }
    public int Error { get; set; }
    public string? Message { get; set; }
}

internal sealed class WazuhItems<T>
{
    [JsonPropertyName("affected_items")] public List<T> AffectedItems { get; set; } = [];
    [JsonPropertyName("total_affected_items")] public int TotalAffectedItems { get; set; }
    [JsonPropertyName("failed_items")] public List<JsonElement> FailedItems { get; set; } = [];
}

internal sealed class WazuhToken
{
    public string? Token { get; set; }
}

internal sealed class WazuhAgent
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Status { get; set; }
    public List<string>? Group { get; set; }
    public WazuhOs? Os { get; set; }
}

internal sealed class WazuhOs
{
    public string? Name { get; set; }
    public string? Platform { get; set; }
}

internal sealed class WazuhScaPolicy
{
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    public string? Name { get; set; }
    [JsonPropertyName("end_scan")] public DateTimeOffset? EndScan { get; set; }
}

internal sealed class WazuhScaCheck
{
    public long Id { get; set; }
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    public string? Title { get; set; }
    public string? Description { get; set; }
    public string? Rationale { get; set; }
    public string? Remediation { get; set; }
    public string? References { get; set; }
    public string? Result { get; set; }
    public string? Reason { get; set; }
    public List<WazuhCompliance>? Compliance { get; set; }
}

internal sealed class WazuhCompliance
{
    public string? Key { get; set; }
    public string? Value { get; set; }
}

/// <summary>
/// Read-only calls to the Wazuh server API: sign in with the read-only user, then GETs only.
/// Retries 429/5xx, signs in again once if the token expires mid-scan.
/// </summary>
internal sealed class WazuhClient(HttpClient http, WazuhOptions options, IWazuhPasswordProvider passwords)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private string? _token;

    private Uri BaseUri => new(options.Url.TrimEnd('/') + "/");

    public async Task SignInAsync(CancellationToken ct)
    {
        var password = await passwords.GetPasswordAsync(ct);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseUri, "security/user/authenticate?raw=false"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.Username}:{password}")));
        using var response = await SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            throw new WazuhException($"Wazuh rejected the user '{options.Username}' (401). Check the user and the password in Key Vault.");
        await EnsureSuccessAsync(response, ct);
        var body = await response.Content.ReadFromJsonAsync<WazuhEnvelope<WazuhToken>>(Json, ct);
        _token = body?.Data?.Token is { Length: > 0 } token ? token : throw new WazuhException("Wazuh didn't return a token.");
    }

    /// <summary>The user's effective RBAC policies: action → resource → allow/deny, plus rbac_mode.</summary>
    public Task<JsonElement> GetEffectivePoliciesAsync(CancellationToken ct) =>
        GetAsync<JsonElement>("security/users/me/policies", ct);

    public Task<List<WazuhAgent>> GetAgentsAsync(string group, CancellationToken ct) =>
        GetAllAsync<WazuhAgent>($"agents?group={Uri.EscapeDataString(group)}&select=id,name,status,group,os.name,os.platform", ct);

    public Task<List<WazuhScaPolicy>> GetScaPoliciesAsync(string agentId, CancellationToken ct) =>
        GetAllAsync<WazuhScaPolicy>($"sca/{Uri.EscapeDataString(agentId)}?select=policy_id,name,end_scan", ct);

    public Task<List<WazuhScaCheck>> GetChecksAsync(string agentId, string policyId, CancellationToken ct) =>
        GetAllAsync<WazuhScaCheck>(
            $"sca/{Uri.EscapeDataString(agentId)}/checks/{Uri.EscapeDataString(policyId)}" +
            "?select=id,policy_id,title,description,rationale,remediation,references,result,reason,compliance", ct);

    private async Task<List<T>> GetAllAsync<T>(string path, CancellationToken ct)
    {
        var items = new List<T>();
        for (var offset = 0; ; offset += options.PageSize)
        {
            var separator = path.Contains('?') ? '&' : '?';
            var page = await GetAsync<WazuhItems<T>>($"{path}{separator}offset={offset}&limit={options.PageSize}", ct);
            if (page.FailedItems.Count > 0)
                throw new WazuhException($"Wazuh couldn't return {path.Split('?')[0]}: {Describe(page.FailedItems[0])}");
            items.AddRange(page.AffectedItems);
            if (page.AffectedItems.Count < options.PageSize || items.Count >= page.TotalAffectedItems) return items;
        }
    }

    private async Task<T> GetAsync<T>(string path, CancellationToken ct)
    {
        for (var reauthenticated = false; ; reauthenticated = true)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseUri, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token ?? throw new InvalidOperationException("Not signed in."));
            using var response = await SendAsync(request, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized && !reauthenticated)
            {
                await SignInAsync(ct); // tokens last 15 minutes by default; a long scan outlives one
                continue;
            }
            await EnsureSuccessAsync(response, ct);
            var body = await response.Content.ReadFromJsonAsync<WazuhEnvelope<T>>(Json, ct)
                       ?? throw new WazuhException($"Wazuh returned an empty response for {path.Split('?')[0]}.");
            if (body.Error != 0 && body.Data is null)
                throw new WazuhException($"Wazuh returned error {body.Error} for {path.Split('?')[0]}: {body.Message}");
            return body.Data ?? throw new WazuhException($"Wazuh returned no data for {path.Split('?')[0]}.");
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            HttpResponseMessage response;
            try
            {
                response = await http.SendAsync(Clone(request), HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
            {
                throw new WazuhException($"The Wazuh API at {BaseUri.Host} presented a TLS certificate that isn't trusted or doesn't match " +
                    "Wazuh:CertificateSha256. Pin the API's certificate (its SHA-256 fingerprint) or give it a trusted one.", ex);
            }
            catch (HttpRequestException ex)
            {
                throw new WazuhException($"Couldn't reach the Wazuh API at {BaseUri.Host}: {ex.Message}", ex);
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

    // A request message can be sent once; retries send a fresh copy.
    private static HttpRequestMessage Clone(HttpRequestMessage request)
    {
        var copy = new HttpRequestMessage(request.Method, request.RequestUri);
        copy.Headers.Authorization = request.Headers.Authorization;
        return copy;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;
        string? detail = null;
        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            detail = Describe(doc.RootElement);
        }
        catch (JsonException) { /* not JSON */ }
        var hint = response.StatusCode == HttpStatusCode.Forbidden ? " The Wazuh user's role must allow agent:read and sca:read on the tenant's group." : "";
        throw new WazuhException($"Wazuh returned {(int)response.StatusCode} {response.ReasonPhrase}{(detail is null ? "" : $" ({detail})")}.{hint}");
    }

    private static string? Describe(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Object) return null;
        foreach (var name in new[] { "detail", "message", "title" })
            if (e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String) return Trim(v.GetString());
        if (e.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object) return Describe(error);
        return null;
    }

    private static string? Trim(string? s) => s is { Length: > 300 } ? s[..300] + "…" : s;
}

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Intune;

/// <summary>
/// Reads a tenant's Intune managed devices through Microsoft Graph v1.0 with read-only
/// application permissions: DeviceManagementManagedDevices.Read.All, plus
/// DeviceManagementConfiguration.Read.All for per-setting compliance results.
/// </summary>
public sealed class IntuneDeviceSource(
    HttpClient http,
    IGraphTokenProvider tokens,
    IntuneOptions options,
    ILogger<IntuneDeviceSource> logger) : IDeviceInventorySource
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string Name => "Intune";

    public async Task<DeviceSyncResult> GetDevicesAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.UtcNow;

        if (tenant.ConsentState is not (TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted))
            return Fail(tenant, started, "Tenant has not granted consent.");
        if (tenant.EntraTenantId == Guid.Empty)
            return Fail(tenant, started, "Tenant has no Entra tenant ID.");
        if (!Thumbprints.IsValid(tenant.CredentialReference))
            return Fail(tenant, started, "Tenant credential reference is not a valid certificate thumbprint.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        var ct = timeout.Token;

        try
        {
            var token = await tokens.GetTokenAsync(tenant, ct);
            var raw = await ListDevicesAsync(token, ct);
            var settings = await GetComplianceSettingsAsync(tenant, raw, token, ct);

            var devices = raw
                .Where(d => !string.IsNullOrWhiteSpace(d.Id))
                .DistinctBy(d => d.Id)
                .Select(d => IntuneDeviceMapper.Map(d, tenant.Id, settings.GetValueOrDefault(d.Id!)))
                .ToList();

            logger.LogInformation("Intune sync for {Tenant} ({TenantId}) read {Count} devices", tenant.DisplayName, tenant.Id, devices.Count);

            return new DeviceSyncResult
            {
                TenantId = tenant.Id,
                Source = Name,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Devices = devices
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Fail(tenant, started, $"Intune sync timed out after {options.Timeout.TotalMinutes:0} minutes.");
        }
        catch (Exception ex) when (ex is GraphRequestException or GraphAuthException or HttpRequestException or JsonException)
        {
            logger.LogWarning("Intune sync for {Tenant} ({TenantId}) failed: {Error}", tenant.DisplayName, tenant.Id, ex.Message);
            return Fail(tenant, started, ex.Message);
        }
    }

    private async Task<List<GraphManagedDevice>> ListDevicesAsync(string token, CancellationToken ct)
    {
        var devices = new List<GraphManagedDevice>();
        string? url = $"{BaseUrl}/v1.0/deviceManagement/managedDevices?$select={GraphManagedDevice.Select}";

        while (url is not null)
        {
            var page = await GetAsync<GraphPage<GraphManagedDevice>>(url, token, ct);
            devices.AddRange(page.Value);
            url = page.NextLink is null ? null : CheckNextLink(page.NextLink);
        }

        return devices;
    }

    /// <summary>
    /// Per-setting results for devices that aren't compliant. A failure here doesn't fail the sync:
    /// the device keeps its overall compliance state with no setting detail.
    /// </summary>
    private async Task<Dictionary<string, IReadOnlyList<DeviceComplianceSetting>>> GetComplianceSettingsAsync(
        Tenant tenant, List<GraphManagedDevice> devices, string token, CancellationToken ct)
    {
        var results = new Dictionary<string, IReadOnlyList<DeviceComplianceSetting>>();
        if (!options.FetchComplianceSettings) return results;

        var targets = devices
            .Where(d => !string.IsNullOrWhiteSpace(d.Id)
                        && IntuneDeviceMapper.MapCompliance(d.ComplianceState) != DeviceComplianceState.Compliant)
            .Select(d => d.Id!)
            .Distinct()
            .ToList();

        var failures = 0;
        string? firstError = null;
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.MaxConcurrentRequests), CancellationToken = ct },
            async (id, token2) =>
            {
                try
                {
                    var url = $"{BaseUrl}/v1.0/deviceManagement/managedDevices/{Uri.EscapeDataString(id)}/deviceCompliancePolicyStates";
                    var page = await GetAsync<GraphPage<GraphCompliancePolicyState>>(url, token, token2);
                    var mapped = IntuneDeviceMapper.MapSettings(page.Value);
                    lock (results) results[id] = mapped;
                }
                catch (Exception ex) when (ex is GraphRequestException or HttpRequestException or JsonException)
                {
                    Interlocked.Increment(ref failures);
                    Interlocked.CompareExchange(ref firstError, ex.Message, null);
                }
            });

        if (failures > 0)
            logger.LogWarning("Intune sync for {Tenant} ({TenantId}): compliance settings unavailable for {Failures} of {Total} devices. First error: {Error}",
                tenant.DisplayName, tenant.Id, failures, targets.Count, firstError);

        return results;
    }

    private async Task<T> GetAsync<T>(string url, string token, CancellationToken ct) where T : new()
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.IsSuccessStatusCode)
                return await response.Content.ReadFromJsonAsync<T>(Json, ct) ?? new T();

            if (IsTransient(response.StatusCode) && attempt < options.MaxRetries)
            {
                await Task.Delay(RetryDelay(response, attempt), ct);
                continue;
            }

            throw await GraphRequestException.FromResponseAsync(response, ct);
        }
    }

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    private TimeSpan RetryDelay(HttpResponseMessage response, int attempt)
    {
        var retryAfter = response.Headers.RetryAfter;
        var delay = retryAfter?.Delta
                    ?? (retryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : (TimeSpan?)null)
                    ?? TimeSpan.FromSeconds(Math.Pow(2, attempt + 1));
        return delay < TimeSpan.Zero ? TimeSpan.Zero : delay > options.MaxRetryDelay ? options.MaxRetryDelay : delay;
    }

    /// <summary>The bearer token goes with every request, so only follow nextLinks back to the Graph host.</summary>
    private string CheckNextLink(string nextLink)
    {
        var expected = new Uri(BaseUrl);
        if (!Uri.TryCreate(nextLink, UriKind.Absolute, out var next)
            || next.Scheme != expected.Scheme
            || !string.Equals(next.Host, expected.Host, StringComparison.OrdinalIgnoreCase)
            || next.Port != expected.Port)
        {
            throw new GraphRequestException("Graph returned a nextLink to an unexpected host; stopped paging.");
        }
        return nextLink;
    }

    private string BaseUrl => options.GraphBaseUrl.TrimEnd('/');

    private DeviceSyncResult Fail(Tenant tenant, DateTimeOffset started, string error) => new()
    {
        TenantId = tenant.Id,
        Source = Name,
        StartedAt = started,
        CompletedAt = DateTimeOffset.UtcNow,
        Devices = [],
        Succeeded = false,
        Error = error.Length > 500 ? error[..500] + "…" : error
    };
}

public sealed class GraphRequestException(string message, HttpStatusCode? status = null) : Exception(message)
{
    public HttpStatusCode? StatusCode { get; } = status;

    internal static async Task<GraphRequestException> FromResponseAsync(HttpResponseMessage response, CancellationToken ct)
    {
        string? detail = null;
        try
        {
            var body = await response.Content.ReadFromJsonAsync<GraphErrorResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web), ct);
            if (body?.Error is { } e) detail = string.Join(": ", new[] { e.Code, e.Message }.Where(s => !string.IsNullOrWhiteSpace(s)));
        }
        catch (JsonException) { /* non-JSON error body */ }
        catch (NotSupportedException) { /* unexpected content type */ }

        var status = (int)response.StatusCode;
        var hint = response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized
            ? " Check admin consent for DeviceManagementManagedDevices.Read.All and DeviceManagementConfiguration.Read.All."
            : "";
        return new GraphRequestException(
            $"Graph returned {status} {response.ReasonPhrase}{(detail is null ? "" : $" ({detail})")}.{hint}", response.StatusCode);
    }
}

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
/// application permissions: DeviceManagementManagedDevices.Read.All (inventory and Defender
/// Antivirus state), DeviceManagementConfiguration.Read.All for per-setting compliance results,
/// and ThreatHunting.Read.All for Defender for Endpoint sensor health (advanced hunting).
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
            var unique = raw.Where(d => !string.IsNullOrWhiteSpace(d.Id)).DistinctBy(d => d.Id).ToList();
            var settings = await GetComplianceSettingsAsync(tenant, unique, token, ct);
            var warnings = new List<string>();
            var defender = options.FetchDefenderHealth ? await GetDefenderDataAsync(tenant, unique, token, warnings, ct) : null;

            var devices = unique
                .Select(d => IntuneDeviceMapper.Map(d, tenant.Id, settings.GetValueOrDefault(d.Id!), defender))
                .ToList();

            logger.LogInformation("Intune sync for {Tenant} ({TenantId}) read {Count} devices", tenant.DisplayName, tenant.Id, devices.Count);

            return new DeviceSyncResult
            {
                TenantId = tenant.Id,
                Source = Name,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Devices = devices,
                Warning = warnings.Count == 0 ? null : Truncate(string.Join(" ", warnings), 1000)
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

    /// <summary>
    /// Defender Antivirus state for Windows devices and Defender for Endpoint sensor state for all.
    /// Never fails the sync: what couldn't be read is left out and described in <paramref name="warnings"/>.
    /// </summary>
    private async Task<DefenderData> GetDefenderDataAsync(Tenant tenant, List<GraphManagedDevice> devices, string token,
        List<string> warnings, CancellationToken ct)
    {
        var antivirus = await GetAntivirusAsync(tenant, devices, token, warnings, ct);

        IReadOnlyDictionary<string, DefenderSensorStatus> sensors = new Dictionary<string, DefenderSensorStatus>();
        var sensorDataAvailable = false;
        try
        {
            var url = $"{BaseUrl}/v1.0/security/runHuntingQuery";
            var body = new Dictionary<string, string>
            {
                ["Query"] = DefenderHealthMapper.DeviceInfoQuery,
                ["Timespan"] = DefenderHealthMapper.HuntingTimespan
            };
            var results = await SendAsync<GraphHuntingResults<HuntingDeviceRow>>(HttpMethod.Post, url, token, ct, body, ThreatHuntingHint);
            sensors = DefenderHealthMapper.Match(devices, results.Results);
            sensorDataAvailable = true;
        }
        catch (Exception ex) when (ex is GraphRequestException or HttpRequestException or JsonException)
        {
            logger.LogWarning("Intune sync for {Tenant} ({TenantId}): Defender for Endpoint sensor data unavailable: {Error}",
                tenant.DisplayName, tenant.Id, ex.Message);
            warnings.Add($"Defender for Endpoint sensor health wasn't read: {ex.Message}");
        }

        return new DefenderData(antivirus, sensors, sensorDataAvailable);
    }

    private async Task<Dictionary<string, DefenderAntivirusStatus>> GetAntivirusAsync(Tenant tenant, List<GraphManagedDevice> devices, string token,
        List<string> warnings, CancellationToken ct)
    {
        var results = new Dictionary<string, DefenderAntivirusStatus>();
        var targets = devices
            .Where(d => IntuneDeviceMapper.MapPlatform(d.OperatingSystem) == DevicePlatform.Windows)
            .Select(d => d.Id!)
            .ToList();

        var failures = 0;
        string? firstError = null;
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.MaxConcurrentRequests), CancellationToken = ct },
            async (id, token2) =>
            {
                try
                {
                    var url = $"{BaseUrl}/v1.0/deviceManagement/managedDevices/{Uri.EscapeDataString(id)}/windowsProtectionState";
                    var state = await SendAsync<GraphWindowsProtectionState>(HttpMethod.Get, url, token, token2);
                    lock (results) results[id] = DefenderHealthMapper.MapAntivirus(state);
                }
                catch (GraphRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    // Not reported yet (new enrollment, or not a Defender device): no antivirus data, not an error.
                }
                catch (Exception ex) when (ex is GraphRequestException or HttpRequestException or JsonException)
                {
                    Interlocked.Increment(ref failures);
                    Interlocked.CompareExchange(ref firstError, ex.Message, null);
                }
            });

        if (failures > 0)
        {
            logger.LogWarning("Intune sync for {Tenant} ({TenantId}): Defender Antivirus state unavailable for {Failures} of {Total} Windows devices. First error: {Error}",
                tenant.DisplayName, tenant.Id, failures, targets.Count, firstError);
            warnings.Add($"Defender Antivirus state wasn't read for {failures} of {targets.Count} Windows devices: {firstError}");
        }

        return results;
    }

    private const string ThreatHuntingHint =
        " Check admin consent for ThreatHunting.Read.All, and that the tenant has Microsoft Defender for Endpoint (Business, P1 or P2).";

    private Task<T> GetAsync<T>(string url, string token, CancellationToken ct) where T : new() =>
        SendAsync<T>(HttpMethod.Get, url, token, ct);

    /// <summary>A read-only Graph call (GET, or the hunting query POST), retried when throttled.</summary>
    private async Task<T> SendAsync<T>(HttpMethod method, string url, string token, CancellationToken ct, object? body = null, string? forbiddenHint = null)
        where T : new()
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (body is not null) request.Content = JsonContent.Create(body, options: Json);

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.IsSuccessStatusCode)
                return await response.Content.ReadFromJsonAsync<T>(Json, ct) ?? new T();

            if (IsTransient(response.StatusCode) && attempt < options.MaxRetries)
            {
                await Task.Delay(RetryDelay(response, attempt), ct);
                continue;
            }

            throw await GraphRequestException.FromResponseAsync(response, ct, forbiddenHint);
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
        Error = Truncate(error, 500)
    };

    private static string Truncate(string s, int max) => s.Length > max ? s[..max] + "…" : s;
}

public sealed class GraphRequestException(string message, HttpStatusCode? status = null) : Exception(message)
{
    public HttpStatusCode? StatusCode { get; } = status;

    internal static async Task<GraphRequestException> FromResponseAsync(HttpResponseMessage response, CancellationToken ct, string? forbiddenHint = null)
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
            ? forbiddenHint ?? " Check admin consent for DeviceManagementManagedDevices.Read.All and DeviceManagementConfiguration.Read.All."
            : "";
        return new GraphRequestException(
            $"Graph returned {status} {response.ReasonPhrase}{(detail is null ? "" : $" ({detail})")}.{hint}", response.StatusCode);
    }
}

using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Worker.Siem;

public sealed class AuditExportException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>A bearer token for the Logs Ingestion API.</summary>
public interface ISentinelTokenProvider
{
    Task<string> GetTokenAsync(CancellationToken ct);
}

/// <summary>Certificate (app registration in your own tenant) or managed identity. Never a client secret.</summary>
public sealed class AzureSentinelTokenProvider : ISentinelTokenProvider
{
    private readonly TokenCredential _credential;
    private readonly string[] _scopes;

    public AzureSentinelTokenProvider(SentinelOptions options, ICertificateLoader certificates)
    {
        _scopes = [$"{options.Audience.TrimEnd('/')}/.default"];
        if (options.UseManagedIdentity)
        {
            _credential = string.IsNullOrWhiteSpace(options.ClientId)
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(options.ClientId));
            return;
        }

        var certificate = certificates.Find(options.CertificateThumbprint!)
            ?? throw new InvalidOperationException(
                $"AuditExport:Sentinel certificate {options.CertificateThumbprint} wasn't found with its private key in CurrentUser\\My or LocalMachine\\My.");
        _credential = new ClientCertificateCredential(options.TenantId, options.ClientId, certificate,
            new ClientCertificateCredentialOptions { AuthorityHost = new Uri(options.AuthorityHost) });
    }

    public async Task<string> GetTokenAsync(CancellationToken ct)
    {
        try
        {
            return (await _credential.GetTokenAsync(new TokenRequestContext(_scopes), ct)).Token;
        }
        catch (AuthenticationFailedException ex)
        {
            throw new AuditExportException($"Couldn't get a token for Azure Monitor: {Describe(ex)}", ex);
        }
    }

    /// <summary>Azure.Identity puts the useful part (e.g. an AADSTS code) in inner exceptions; keep it on one line.</summary>
    public static string Describe(Exception ex)
    {
        var parts = new List<string>();
        for (var e = ex; e is not null; e = e.InnerException)
        {
            var line = string.Join(' ', e.Message.Split((char[])['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).Trim().TrimEnd(':');
            if (line.Length > 0 && !parts.Any(p => p.Contains(line, StringComparison.Ordinal))) parts.Add(line);
        }
        var text = string.Join(": ", parts);
        return text.Length > 1000 ? text[..1000] + "…" : text;
    }
}

/// <summary>
/// One audit event as a row of the Sentinel table. Column names avoid Log Analytics' reserved ones
/// (TenantId, Type, id...), so SecurePulse's tenant is <see cref="SecurePulseTenantId"/>.
/// </summary>
public sealed record SentinelAuditRecord
{
    public required DateTimeOffset TimeGenerated { get; init; }
    public required Guid EventId { get; init; }
    public required string Action { get; init; }
    public required string ActionLabel { get; init; }
    public required string Category { get; init; }
    public required string Outcome { get; init; }
    public Guid? ActorUserId { get; init; }
    public required string ActorName { get; init; }
    public Guid? SecurePulseTenantId { get; init; }
    public string? TargetType { get; init; }
    public string? TargetId { get; init; }
    public required string Summary { get; init; }
    public required IReadOnlyDictionary<string, string> Details { get; init; }
    public string? IpAddress { get; init; }
    public DateTimeOffset? RecordedAt { get; init; }
    public string Source { get; init; } = "SecurePulse";

    public static SentinelAuditRecord From(AuditEvent e) => new()
    {
        TimeGenerated = e.OccurredAt,
        EventId = e.Id,
        Action = e.Action,
        ActionLabel = AuditActions.Label(e.Action),
        Category = e.Category,
        Outcome = e.Outcome.ToString(),
        ActorUserId = e.ActorUserId,
        ActorName = e.ActorName,
        SecurePulseTenantId = e.TenantId,
        TargetType = e.TargetType,
        TargetId = e.TargetId,
        Summary = e.Summary,
        Details = e.Details,
        IpAddress = e.IpAddress,
        RecordedAt = e.RecordedAt
    };
}

public interface ISentinelAuditSink
{
    /// <summary>Sends the records in one call; throws <see cref="AuditExportException"/> if Sentinel doesn't accept them.</summary>
    Task SendAsync(IReadOnlyList<SentinelAuditRecord> records, CancellationToken ct);
}

/// <summary>Sends audit records to Microsoft Sentinel through the Azure Monitor Logs Ingestion API.</summary>
public sealed class SentinelAuditSink(HttpClient http, SentinelOptions options, ISentinelTokenProvider tokens, ILogger<SentinelAuditSink> logger)
    : ISentinelAuditSink
{
    /// <summary>The API takes at most 1 MB per call; stay under it with room for the array syntax.</summary>
    public const int MaxBodyBytes = 1_000_000 - 4_096;

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// How many of <paramref name="events"/> (from the start) fit in one call. A single event too large
    /// on its own goes with its details replaced, so it can never block the export.
    /// </summary>
    public static (List<SentinelAuditRecord> Records, int Count) Take(IReadOnlyList<AuditEvent> events, int maxBytes = MaxBodyBytes)
    {
        var records = new List<SentinelAuditRecord>();
        var size = 2; // [ ]
        foreach (var e in events)
        {
            var record = SentinelAuditRecord.From(e);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(record, Json).Length + 1;
            if (records.Count == 0 && size + bytes > maxBytes)
            {
                record = record with { Details = new Dictionary<string, string> { ["truncated"] = "Details were too large to export; see SecurePulse." } };
                bytes = JsonSerializer.SerializeToUtf8Bytes(record, Json).Length + 1;
            }
            if (records.Count > 0 && size + bytes > maxBytes) break;
            records.Add(record);
            size += bytes;
        }
        return (records, records.Count);
    }

    public async Task SendAsync(IReadOnlyList<SentinelAuditRecord> records, CancellationToken ct)
    {
        if (records.Count == 0) return;
        var body = Gzip(JsonSerializer.SerializeToUtf8Bytes(records, Json));
        var uri = options.IngestionUri();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.Timeout);
        try
        {
            var token = await tokens.GetTokenAsync(timeout.Token);
            for (var attempt = 0; ; attempt++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Headers.Add("x-ms-client-request-id", Guid.NewGuid().ToString());
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                request.Content.Headers.ContentEncoding.Add("gzip");

                using var response = await http.SendAsync(request, timeout.Token);
                if (response.IsSuccessStatusCode) return;

                if (IsTransient(response.StatusCode) && attempt < options.MaxRetries)
                {
                    var delay = RetryDelay(response, attempt);
                    logger.LogWarning("Sentinel returned {Status}; retrying in {Delay}", (int)response.StatusCode, delay);
                    await Task.Delay(delay, timeout.Token);
                    continue;
                }
                throw new AuditExportException(await DescribeAsync(response, timeout.Token));
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new AuditExportException($"Sentinel didn't answer within {options.Timeout.TotalSeconds:0} seconds.");
        }
        catch (HttpRequestException ex)
        {
            throw new AuditExportException($"Couldn't reach {uri.Host}: {ex.Message}", ex);
        }
    }

    private static bool IsTransient(HttpStatusCode status) => status is HttpStatusCode.TooManyRequests or HttpStatusCode.InternalServerError
        or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    private static TimeSpan RetryDelay(HttpResponseMessage response, int attempt)
    {
        var delay = response.Headers.RetryAfter?.Delta
                    ?? (response.Headers.RetryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : (TimeSpan?)null)
                    ?? TimeSpan.FromSeconds(Math.Pow(2, attempt + 1));
        return delay < TimeSpan.Zero ? TimeSpan.Zero : delay > TimeSpan.FromSeconds(60) ? TimeSpan.FromSeconds(60) : delay;
    }

    private static async Task<string> DescribeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var status = (int)response.StatusCode;
        string? detail = null;
        try
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("error", out var error))
                detail = string.Join(": ", new[] { Str(error, "code"), Str(error, "message") }.Where(s => !string.IsNullOrWhiteSpace(s)));
        }
        catch (JsonException) { /* not JSON */ }

        var hint = response.StatusCode switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => " Give the Worker's identity the Monitoring Metrics Publisher role on the data collection rule.",
            HttpStatusCode.NotFound => " Check AuditExport:Sentinel:DcrImmutableId and StreamName against the data collection rule.",
            HttpStatusCode.BadRequest => " The data collection rule's stream doesn't match SecurePulse's records; see the README for its columns.",
            _ => ""
        };
        var shown = detail is { Length: > 500 } ? detail[..500] + "…" : detail;
        return $"Sentinel returned {status} {response.ReasonPhrase}{(shown is null ? "" : $" ({shown})")}.{hint}";

        static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    private static byte[] Gzip(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
            gzip.Write(data);
        return output.ToArray();
    }
}

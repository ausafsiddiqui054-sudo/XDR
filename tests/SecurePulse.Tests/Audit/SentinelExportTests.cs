using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Worker.Siem;

namespace SecurePulse.Tests.Audit;

public class SentinelOptionsTests
{
    public static SentinelOptions Valid() => new()
    {
        Enabled = true,
        Endpoint = "https://securepulse-audit-ab12.uaenorth-1.ingest.monitor.azure.com",
        DcrImmutableId = "dcr-0123456789abcdef0123456789abcdef",
        TenantId = "6f7c1d5e-0a3b-4c2d-9e8f-112233445566",
        ClientId = "11111111-2222-3333-4444-555555555555",
        CertificateThumbprint = "0123456789ABCDEF0123456789ABCDEF01234567"
    };

    [Fact]
    public void AValidConfiguration_HasNoProblems_AndBuildsTheIngestionUri()
    {
        Assert.Empty(Valid().Problems());
        Assert.Equal(
            "https://securepulse-audit-ab12.uaenorth-1.ingest.monitor.azure.com/dataCollectionRules/dcr-0123456789abcdef0123456789abcdef/streams/Custom-SecurePulseAudit?api-version=2023-01-01",
            Valid().IngestionUri().ToString());
    }

    [Fact]
    public void Disabled_IsNeverAProblem() => Assert.Empty(new SentinelOptions().Problems());

    [Theory]
    [InlineData("http://x.uaenorth-1.ingest.monitor.azure.com")]
    [InlineData("https://attacker.example")]
    [InlineData("https://ingest.monitor.azure.com.attacker.example")]
    [InlineData("https://x.uaenorth-1.ingest.monitor.azure.com/dataCollectionRules/x")]
    [InlineData("https://user:pw@x.uaenorth-1.ingest.monitor.azure.com")]
    [InlineData("")]
    public void TheTokenAndDataOnlyGoToAzureMonitorIngestion(string endpoint)
    {
        var problems = Valid().WithEndpoint(endpoint).Problems();

        Assert.Contains(problems, p => p.Contains("AuditExport:Sentinel:Endpoint"));
    }

    [Theory]
    [InlineData("https://x.usgovvirginia-1.ingest.monitor.azure.us")]
    [InlineData("https://X.UAENORTH-1.INGEST.MONITOR.AZURE.COM/")]
    public void NationalCloudAndCaseVariants_AreAccepted(string endpoint) => Assert.Empty(Valid().WithEndpoint(endpoint).Problems());

    [Theory]
    [InlineData("DcrImmutableId", "dcr-XYZ")]
    [InlineData("DcrImmutableId", "0123456789abcdef0123456789abcdef")]
    [InlineData("StreamName", "Custom-Bad Name")]
    [InlineData("StreamName", "SecurePulseAudit")]
    [InlineData("TenantId", "not-a-guid")]
    [InlineData("ClientId", "")]
    [InlineData("CertificateThumbprint", "abc")]
    public void BadValues_AreNamed(string setting, string value)
    {
        var o = Valid();
        typeof(SentinelOptions).GetProperty(setting)!.SetValue(o, value);

        Assert.Contains(o.Problems(), p => p.Contains($"AuditExport:Sentinel:{setting}"));
    }

    [Fact]
    public void ManagedIdentity_NeedsNoTenantOrCertificate_ButNotBoth()
    {
        var mi = Valid();
        mi.UseManagedIdentity = true;
        mi.CertificateThumbprint = null;
        mi.TenantId = null;
        mi.ClientId = null;
        Assert.Empty(mi.Problems());

        mi.CertificateThumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
        Assert.Contains(mi.Problems(), p => p.Contains("not both"));
    }

    [Fact]
    public void TooShortALag_IsRefused()
    {
        var o = Valid();
        o.ExportLag = TimeSpan.FromSeconds(5);

        Assert.Contains(o.Problems(), p => p.Contains("ExportLag"));
    }
}

internal static class SentinelOptionsExtensions
{
    public static SentinelOptions WithEndpoint(this SentinelOptions o, string endpoint)
    {
        o.Endpoint = endpoint;
        return o;
    }
}

public class SentinelAuditSinkTests
{
    private static AuditEvent Event(string summary = "Signed in", IReadOnlyDictionary<string, string>? details = null) => new()
    {
        Id = Guid.NewGuid(), OccurredAt = new DateTimeOffset(2026, 10, 15, 6, 0, 0, TimeSpan.Zero), RecordedAt = new DateTimeOffset(2026, 10, 15, 6, 0, 1, TimeSpan.Zero),
        Action = AuditActions.SignIn, Outcome = AuditOutcome.Denied, ActorName = "Aisha Rahman <aisha@clinic.example>", ActorUserId = Guid.NewGuid(),
        TenantId = Guid.NewGuid(), TargetType = "PortalUser", TargetId = "42", Summary = summary, IpAddress = "203.0.113.7",
        Details = details ?? new Dictionary<string, string> { ["role"] = "Owner" }
    };

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public ConcurrentQueue<(HttpRequestMessage Request, byte[] Body)> Requests { get; } = new();

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : this((r, _) => Task.FromResult(respond(r))) { }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Enqueue((request, await request.Content!.ReadAsByteArrayAsync(ct)));
            return await respond(request, ct);
        }
    }

    private sealed class FakeTokens : ISentinelTokenProvider
    {
        public Task<string> GetTokenAsync(CancellationToken ct) => Task.FromResult("monitor-token");
    }

    private static SentinelAuditSink Sink(StubHandler handler, Action<SentinelOptions>? configure = null)
    {
        var o = SentinelOptionsTests.Valid();
        configure?.Invoke(o);
        return new SentinelAuditSink(new HttpClient(handler), o, new FakeTokens(), NullLogger<SentinelAuditSink>.Instance);
    }

    private static HttpResponseMessage Status(HttpStatusCode status, string? body = null, int? retryAfter = null)
    {
        var r = new HttpResponseMessage(status);
        if (body is not null) r.Content = new StringContent(body, Encoding.UTF8, "application/json");
        if (retryAfter is { } s) r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(s));
        return r;
    }

    private static JsonElement Unzip(byte[] body)
    {
        using var gzip = new GZipStream(new MemoryStream(body), CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        return JsonDocument.Parse(reader.ReadToEnd()).RootElement.Clone();
    }

    [Fact]
    public async Task PostsGzipJsonWithTheTokenToTheDcrStream()
    {
        var handler = new StubHandler(_ => Status(HttpStatusCode.NoContent));
        var e = Event();

        await Sink(handler).SendAsync(SentinelAuditSink.Take([e]).Records, CancellationToken.None);

        var (request, body) = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(SentinelOptionsTests.Valid().IngestionUri(), request.RequestUri);
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal("monitor-token", request.Headers.Authorization.Parameter);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal(["gzip"], request.Content.Headers.ContentEncoding);

        var row = Assert.Single(Unzip(body).EnumerateArray().ToList());
        Assert.Equal(e.Id, row.GetProperty("EventId").GetGuid());
        Assert.Equal(e.OccurredAt, row.GetProperty("TimeGenerated").GetDateTimeOffset());
        Assert.Equal(e.RecordedAt, row.GetProperty("RecordedAt").GetDateTimeOffset());
        Assert.Equal("auth.sign-in", row.GetProperty("Action").GetString());
        Assert.Equal("Sign-in", row.GetProperty("ActionLabel").GetString());
        Assert.Equal("auth", row.GetProperty("Category").GetString());
        Assert.Equal("Denied", row.GetProperty("Outcome").GetString());
        Assert.Equal("Aisha Rahman <aisha@clinic.example>", row.GetProperty("ActorName").GetString());
        Assert.Equal(e.TenantId, row.GetProperty("SecurePulseTenantId").GetGuid());
        Assert.Equal("Owner", row.GetProperty("Details").GetProperty("role").GetString());
        Assert.Equal("203.0.113.7", row.GetProperty("IpAddress").GetString());
        Assert.Equal("SecurePulse", row.GetProperty("Source").GetString());
        Assert.False(row.TryGetProperty("TenantId", out _)); // reserved in Log Analytics
    }

    [Fact]
    public void TakeStaysUnderTheSizeLimit()
    {
        var events = Enumerable.Range(0, 50).Select(i => Event(new string('x', 900))).ToList();

        var (records, count) = SentinelAuditSink.Take(events, maxBytes: 10_000);

        Assert.InRange(count, 2, 49);
        Assert.Equal(count, records.Count);
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(records).Length <= 10_000);
        Assert.Equal(events.Take(count).Select(e => e.Id), records.Select(r => r.EventId));
    }

    [Fact]
    public void AnEventTooLargeOnItsOwn_GoesWithoutItsDetails()
    {
        var huge = Event(details: Enumerable.Range(0, 100).ToDictionary(i => $"k{i}", _ => new string('y', 2000)));

        var small = Event();
        var (records, count) = SentinelAuditSink.Take([huge, small], maxBytes: 20_000);

        Assert.Equal(2, count); // the stripped event no longer crowds out the next one
        Assert.Equal(huge.Id, records[0].EventId);
        Assert.Equal(["truncated"], records[0].Details.Keys);
        Assert.Equal(small.Details, records[1].Details);
    }

    [Fact]
    public async Task ThrottlingIsRetriedAfterRetryAfter()
    {
        var calls = 0;
        var handler = new StubHandler(_ => Interlocked.Increment(ref calls) == 1 ? Status(HttpStatusCode.TooManyRequests, retryAfter: 0) : Status(HttpStatusCode.NoContent));

        await Sink(handler).SendAsync(SentinelAuditSink.Take([Event()]).Records, CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "Monitoring Metrics Publisher")]
    [InlineData(HttpStatusCode.NotFound, "DcrImmutableId and StreamName")]
    [InlineData(HttpStatusCode.BadRequest, "stream doesn't match")]
    public async Task RejectionsExplainWhatToFix(HttpStatusCode status, string hint)
    {
        var handler = new StubHandler(_ => Status(status, """{"error":{"code":"OperationFailed","message":"The authentication token provided does not have access"}}"""));

        var ex = await Assert.ThrowsAsync<AuditExportException>(() => Sink(handler).SendAsync(SentinelAuditSink.Take([Event()]).Records, CancellationToken.None));

        Assert.Contains($"Sentinel returned {(int)status}", ex.Message);
        Assert.Contains("OperationFailed: The authentication token provided does not have access", ex.Message);
        Assert.Contains(hint, ex.Message);
        Assert.Single(handler.Requests); // not retried
    }

    [Fact]
    public async Task PersistentUnavailability_GivesUpAfterTheRetries()
    {
        var handler = new StubHandler(_ => Status(HttpStatusCode.ServiceUnavailable, retryAfter: 0));

        var ex = await Assert.ThrowsAsync<AuditExportException>(() =>
            Sink(handler, o => o.MaxRetries = 2).SendAsync(SentinelAuditSink.Take([Event()]).Records, CancellationToken.None));

        Assert.Contains("503", ex.Message);
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public async Task ASlowEndpoint_TimesOut()
    {
        var handler = new StubHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return Status(HttpStatusCode.NoContent);
        });

        var ex = await Assert.ThrowsAsync<AuditExportException>(() =>
            Sink(handler, o => o.Timeout = TimeSpan.FromMilliseconds(100)).SendAsync(SentinelAuditSink.Take([Event()]).Records, CancellationToken.None));

        Assert.Contains("didn't answer", ex.Message);
    }

    [Fact]
    public void TokenErrorsKeepTheInnerDetail_OnOneLine()
    {
        var ex = new Azure.Identity.AuthenticationFailedException("ClientCertificateCredential authentication failed: ",
            new InvalidOperationException("AADSTS700016: Application with identifier '1111' was not found\r\nin the directory 'Contoso'.\nTrace ID: abc"));

        Assert.Equal("ClientCertificateCredential authentication failed: AADSTS700016: Application with identifier '1111' was not found in the directory 'Contoso'. Trace ID: abc",
            AzureSentinelTokenProvider.Describe(ex));
    }

    [Fact]
    public async Task NothingToSend_MakesNoCall()
    {
        var handler = new StubHandler(_ => Status(HttpStatusCode.NoContent));

        await Sink(handler).SendAsync([], CancellationToken.None);

        Assert.Empty(handler.Requests);
    }
}

public class AuditExportServiceTests
{
    private sealed class FakeLease(List<AuditEvent> events, FakeStore store) : IAuditExportLease
    {
        public IReadOnlyList<AuditEvent> Events => events;

        public Task CommitAsync(int count, CancellationToken ct = default)
        {
            store.Commits.Add(count);
            store.Position += count;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeStore(List<AuditEvent> events) : IAuditExportStore
    {
        public int Position;
        public bool Busy;
        public List<int> Commits { get; } = [];
        public List<string> Failures { get; } = [];
        public List<TimeSpan> Lags { get; } = [];

        public Task<IAuditExportLease?> TryLeaseAsync(string destination, TimeSpan lag, int maxEvents, CancellationToken ct = default)
        {
            Assert.Equal(AuditExportDestinations.Sentinel, destination);
            Lags.Add(lag);
            return Task.FromResult<IAuditExportLease?>(Busy ? null : new FakeLease(events.Skip(Position).Take(maxEvents).ToList(), this));
        }

        public Task RecordFailureAsync(string destination, string error, CancellationToken ct = default)
        {
            Failures.Add(error);
            return Task.CompletedTask;
        }

        public Task<AuditExportStatus?> GetStatusAsync(string destination, CancellationToken ct = default) => Task.FromResult<AuditExportStatus?>(null);
    }

    private sealed class FakeSink : ISentinelAuditSink
    {
        public List<List<Guid>> Calls { get; } = [];
        public Func<int, Exception?> FailOn = _ => null;

        public Task SendAsync(IReadOnlyList<SentinelAuditRecord> records, CancellationToken ct)
        {
            Calls.Add(records.Select(r => r.EventId).ToList());
            return FailOn(Calls.Count) is { } ex ? Task.FromException(ex) : Task.CompletedTask;
        }
    }

    private static List<AuditEvent> Events(int n, int summaryLength = 10) => Enumerable.Range(0, n).Select(i => new AuditEvent
    {
        Id = Guid.NewGuid(), OccurredAt = DateTimeOffset.UtcNow, Action = AuditActions.SignIn, Outcome = AuditOutcome.Success,
        ActorName = "Test", Summary = new string('s', summaryLength)
    }).ToList();

    private static (AuditExportService Service, FakeStore Store, FakeSink Sink) Create(List<AuditEvent> events, int maxPerCall = 500)
    {
        var store = new FakeStore(events);
        var sink = new FakeSink();
        var options = SentinelOptionsTests.Valid();
        options.MaxEventsPerCall = maxPerCall;
        return (new AuditExportService(store, sink, options, NullLogger<AuditExportService>.Instance), store, sink);
    }

    [Fact]
    public async Task SendsEverythingInOrder_CommittingAfterEachAcceptedCall()
    {
        var events = Events(12);
        var (service, store, sink) = Create(events, maxPerCall: 5);

        var result = await service.RunOnceAsync();

        Assert.Equal(12, result.Sent);
        Assert.Equal(events.Select(e => e.Id), sink.Calls.SelectMany(c => c));
        Assert.Equal([5, 5, 2], store.Commits);
        Assert.All(store.Lags, l => Assert.Equal(TimeSpan.FromMinutes(2), l));
    }

    [Fact]
    public async Task AFailedCall_LeavesTheCheckpoint_AndRecordsTheError()
    {
        var events = Events(12);
        var (service, store, sink) = Create(events, maxPerCall: 5);
        sink.FailOn = call => call == 2 ? new AuditExportException("Sentinel returned 403 Forbidden.") : null;

        var result = await service.RunOnceAsync();

        Assert.Equal(5, result.Sent);
        Assert.Equal([5], store.Commits); // the second batch wasn't committed
        Assert.Equal(["Sentinel returned 403 Forbidden."], store.Failures);
        Assert.Equal("Sentinel returned 403 Forbidden.", result.Error);

        // The next run resends the failed batch, then the rest: nothing is skipped.
        sink.FailOn = _ => null;
        await service.RunOnceAsync();
        Assert.Equal(events.Skip(5).Select(e => e.Id), sink.Calls.Skip(2).SelectMany(c => c));
        Assert.Equal([5, 5, 2], store.Commits);
    }

    [Fact]
    public async Task OnlyWhatFitsInOneCall_IsCommitted()
    {
        // ~1,000 events of ~1.5 KB don't fit in one 1 MB call.
        var events = Events(1000, summaryLength: 1400);
        var (service, store, sink) = Create(events, maxPerCall: 1000);

        await service.RunOnceAsync();

        Assert.True(sink.Calls[0].Count < 1000);
        Assert.Equal(sink.Calls.Select(c => c.Count), store.Commits);
        Assert.Equal(1000, store.Commits.Sum());
    }

    [Fact]
    public async Task NothingNew_RecordsTheAttemptOnly()
    {
        var (service, store, sink) = Create([]);

        var result = await service.RunOnceAsync();

        Assert.Equal(0, result.Sent);
        Assert.Empty(sink.Calls);
        Assert.Equal([0], store.Commits);
    }

    [Fact]
    public async Task AnotherWorkerExporting_IsLeftAlone()
    {
        var (service, store, sink) = Create(Events(3));
        store.Busy = true;

        var result = await service.RunOnceAsync();

        Assert.True(result.Busy);
        Assert.Empty(sink.Calls);
    }
}

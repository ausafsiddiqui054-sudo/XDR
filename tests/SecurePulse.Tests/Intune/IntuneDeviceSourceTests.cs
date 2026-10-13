using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Tests.Intune;

public class IntuneDeviceSourceTests
{
    private const string Graph = "https://graph.test";
    private const string DevicesUrl = Graph + "/v1.0/deviceManagement/managedDevices";

    private static Tenant OnboardedTenant(TenantConsentState consent = TenantConsentState.ReadOnlyGranted, string? credential = "0123456789ABCDEF0123456789ABCDEF01234567") => new()
    {
        Id = Guid.NewGuid(),
        EntraTenantId = Guid.NewGuid(),
        DisplayName = "Contoso Clinic",
        PrimaryDomain = "contoso.example",
        ConsentState = consent,
        CredentialReference = credential
    };

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new();

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : this((r, _) => Task.FromResult(respond(r))) { }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Enqueue(request);
            return respond(request, ct);
        }
    }

    private sealed class FakeTokens(Exception? fail = null) : IGraphTokenProvider
    {
        public int Calls;

        public Task<string> GetTokenAsync(Tenant tenant, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            return fail is null ? Task.FromResult("test-token") : Task.FromException<string>(fail);
        }
    }

    private static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Status(HttpStatusCode status, int? retryAfterSeconds = null)
    {
        var r = new HttpResponseMessage(status);
        if (retryAfterSeconds is { } s) r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(s));
        return r;
    }

    private static object Device(string id, string compliance = "compliant") => new
    {
        id, deviceName = $"PC-{id}", operatingSystem = "Windows", complianceState = compliance, managedDeviceOwnerType = "company", isEncrypted = true
    };

    private static object Page(object[] value, string? nextLink = null) =>
        nextLink is null ? new { value } : new Dictionary<string, object> { ["value"] = value, ["@odata.nextLink"] = nextLink };

    private static (IntuneDeviceSource Source, StubHandler Handler, FakeTokens Tokens) Create(
        StubHandler handler, IntuneOptions? options = null, FakeTokens? tokens = null)
    {
        options ??= new IntuneOptions { GraphBaseUrl = Graph };
        tokens ??= new FakeTokens();
        var source = new IntuneDeviceSource(new HttpClient(handler), tokens, options, NullLogger<IntuneDeviceSource>.Instance);
        return (source, handler, tokens);
    }

    [Fact]
    public async Task ReadsDevicesWithBearerTokenAndSettingsForNoncompliantOnly()
    {
        var (source, handler, _) = Create(new StubHandler(r => r.RequestUri!.AbsolutePath switch
        {
            "/v1.0/deviceManagement/managedDevices" => Json(Page([Device("a"), Device("b", "noncompliant")])),
            "/v1.0/deviceManagement/managedDevices/b/deviceCompliancePolicyStates" => Json(Page([
                new { displayName = "Windows baseline", state = "nonCompliant", settingStates = new[] { new { settingName = "BitLocker", state = "nonCompliant" } } }
            ])),
            _ => Status(HttpStatusCode.NotFound)
        }));
        var tenant = OnboardedTenant();

        var result = await source.GetDevicesAsync(tenant);

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("Intune", result.Source);
        Assert.Equal(tenant.Id, result.TenantId);
        Assert.Equal(["a", "b"], result.Devices.Select(d => d.Id));
        Assert.All(result.Devices, d => Assert.Equal(tenant.Id, d.TenantId));
        Assert.Empty(result.Devices.Single(d => d.Id == "a").ComplianceSettings);
        Assert.Equal([new DeviceComplianceSetting("Windows baseline", "BitLocker", false, "Not compliant.")],
            result.Devices.Single(d => d.Id == "b").ComplianceSettings);

        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, r =>
        {
            Assert.Equal("Bearer", r.Headers.Authorization?.Scheme);
            Assert.Equal("test-token", r.Headers.Authorization?.Parameter);
        });
        var list = handler.Requests.First();
        Assert.StartsWith(DevicesUrl + "?$select=", Uri.UnescapeDataString(list.RequestUri!.ToString()));
        Assert.Contains("complianceState", list.RequestUri!.Query);
    }

    [Fact]
    public async Task FollowsNextLinkAcrossPages()
    {
        var (source, handler, _) = Create(new StubHandler(r =>
            r.RequestUri!.Query.Contains("skiptoken")
                ? Json(Page([Device("c")]))
                : Json(Page([Device("a"), Device("b")], $"{DevicesUrl}?$skiptoken=abc"))));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(["a", "b", "c"], result.Devices.Select(d => d.Id));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("https://attacker.test/v1.0/deviceManagement/managedDevices?$skiptoken=abc")]
    [InlineData("http://graph.test/v1.0/deviceManagement/managedDevices?$skiptoken=abc")]
    [InlineData("https://graph.test:8443/v1.0/deviceManagement/managedDevices?$skiptoken=abc")]
    [InlineData("/v1.0/deviceManagement/managedDevices?$skiptoken=abc")]
    public async Task RefusesToSendTheTokenToAnotherHost(string nextLink)
    {
        var (source, handler, _) = Create(new StubHandler(_ => Json(Page([Device("a")], nextLink))));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.False(result.Succeeded);
        Assert.Contains("unexpected host", result.Error);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task RetriesThrottledRequests()
    {
        var calls = 0;
        var (source, handler, _) = Create(new StubHandler(_ =>
            Interlocked.Increment(ref calls) == 1 ? Status(HttpStatusCode.TooManyRequests, retryAfterSeconds: 0) : Json(Page([Device("a")]))));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task GivesUpAfterMaxRetries()
    {
        var (source, handler, _) = Create(new StubHandler(_ => Status(HttpStatusCode.ServiceUnavailable, retryAfterSeconds: 0)),
            new IntuneOptions { GraphBaseUrl = Graph, MaxRetries = 2 });

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.False(result.Succeeded);
        Assert.Contains("503", result.Error);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Empty(result.Devices);
    }

    [Fact]
    public async Task Forbidden_ReportsGraphErrorAndPermissionHint()
    {
        var (source, _, _) = Create(new StubHandler(_ =>
            Json(new { error = new { code = "Forbidden", message = "Application is not authorized to perform this operation." } }, HttpStatusCode.Forbidden)));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.False(result.Succeeded);
        Assert.Contains("403", result.Error);
        Assert.Contains("Application is not authorized", result.Error);
        Assert.Contains("DeviceManagementManagedDevices.Read.All", result.Error);
    }

    [Fact]
    public async Task ComplianceSettingFailures_DoNotFailTheSync()
    {
        var (source, _, _) = Create(new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("deviceCompliancePolicyStates")
            ? Status(HttpStatusCode.InternalServerError)
            : Json(Page([Device("a", "noncompliant")]))));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.True(result.Succeeded, result.Error);
        var device = Assert.Single(result.Devices);
        Assert.Equal(DeviceComplianceState.Noncompliant, device.ComplianceState);
        Assert.Empty(device.ComplianceSettings);
    }

    [Fact]
    public async Task ComplianceSettingsCanBeTurnedOff()
    {
        var (source, handler, _) = Create(new StubHandler(_ => Json(Page([Device("a", "noncompliant")]))),
            new IntuneOptions { GraphBaseUrl = Graph, FetchComplianceSettings = false });

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.True(result.Succeeded, result.Error);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task DeviceIdsAreEscapedInSettingsUrl()
    {
        var (source, handler, _) = Create(new StubHandler(r => r.RequestUri!.AbsolutePath.EndsWith("deviceCompliancePolicyStates")
            ? Json(Page([]))
            : Json(Page([Device("a/../b", "noncompliant")]))));

        await source.GetDevicesAsync(OnboardedTenant());

        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsoluteUri == $"{DevicesUrl}/a%2F..%2Fb/deviceCompliancePolicyStates");
    }

    [Fact]
    public async Task DuplicateAndIdlessDevicesAreDropped()
    {
        var (source, _, _) = Create(new StubHandler(_ => Json(Page([Device("a"), Device("a"), new { deviceName = "no id" }]))));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.Equal(["a"], result.Devices.Select(d => d.Id));
    }

    [Theory]
    [InlineData(TenantConsentState.Pending, "0123456789ABCDEF0123456789ABCDEF01234567")]
    [InlineData(TenantConsentState.Revoked, "0123456789ABCDEF0123456789ABCDEF01234567")]
    [InlineData(TenantConsentState.ReadOnlyGranted, null)]
    [InlineData(TenantConsentState.ReadOnlyGranted, "not-a-thumbprint")]
    [InlineData(TenantConsentState.ReadOnlyGranted, "0123456789ABCDEF0123456789ABCDEF0123456Z")]
    public async Task UnreadyTenants_FailWithoutCallingGraph(TenantConsentState consent, string? credential)
    {
        var (source, handler, tokens) = Create(new StubHandler(_ => Json(Page([Device("a")]))));

        var result = await source.GetDevicesAsync(OnboardedTenant(consent, credential));

        Assert.False(result.Succeeded);
        Assert.Empty(handler.Requests);
        Assert.Equal(0, tokens.Calls);
    }

    [Fact]
    public async Task TokenFailure_IsReportedAsFailedSync()
    {
        var (source, handler, _) = Create(new StubHandler(_ => Json(Page([Device("a")]))),
            tokens: new FakeTokens(new GraphAuthException("Could not get a Graph token: AADSTS700027")));

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.False(result.Succeeded);
        Assert.Contains("AADSTS700027", result.Error);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task SlowGraph_TimesOut()
    {
        var (source, _, _) = Create(new StubHandler(async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return Status(HttpStatusCode.OK);
            }),
            new IntuneOptions { GraphBaseUrl = Graph, Timeout = TimeSpan.FromMilliseconds(100) });

        var result = await source.GetDevicesAsync(OnboardedTenant());

        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Error);
    }

    [Fact]
    public async Task CallerCancellation_Propagates()
    {
        var (source, _, _) = Create(new StubHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return Status(HttpStatusCode.OK);
        }));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.GetDevicesAsync(OnboardedTenant(), cts.Token));
    }
}

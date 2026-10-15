using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Services;
using SecurePulse.Worker;

namespace SecurePulse.Tests.DeviceActions;

/// <summary>The Worker side: re-checks, fail-closed audit, one send per approval, expiry.</summary>
public class DeviceActionServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 14, 9, 0, 0, TimeSpan.Zero);

    private sealed class Tokens(Func<Guid, string> issue) : IRemediationTokenProvider
    {
        public int Calls;

        public Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(issue(entraTenantId));
        }
    }

    private sealed class Sender(Func<DeviceActionSendResult>? result = null) : IDeviceActionSender
    {
        public List<(Guid Tenant, string Device, DeviceAction Action)> Sent { get; } = [];
        public Func<Task>? BeforeSend { get; set; }

        public async Task<DeviceActionSendResult> SendAsync(Guid entraTenantId, string deviceId, DeviceAction action, string accessToken,
            CancellationToken cancellationToken = default)
        {
            if (BeforeSend is not null) await BeforeSend();
            Sent.Add((entraTenantId, deviceId, action));
            return result?.Invoke() ?? DeviceActionSendResult.Ok;
        }
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(T0);
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public Tokens Tokens { get; init; } = new(tid => Jwt.With(tid, RemediationPermissions.PrivilegedOperations));
        public Sender Sender { get; init; } = new();
        public DeviceActionOptions Options { get; } = new();

        public Harness() => Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);

        public IDeviceActionRepository Actions => Store;

        public DeviceActionService Service => new(Store, Store, Tokens, Sender, Audit, Microsoft.Extensions.Options.Options.Create(Options), Time,
            NullLogger<DeviceActionService>.Instance);

        public async Task<Tenant> TenantAsync() => (await Store.GetAllAsync()).Single(t => t.CanRemediate);

        /// <summary>Puts a row straight into the queue, as the portal would after its checks (or as a tampered row would look).</summary>
        public async Task<DeviceActionRequest> ApprovedAsync(DeviceAction action = DeviceAction.Sync, PortalRole approverRole = PortalRole.Owner,
            bool selfApproved = false, string? deviceId = null)
        {
            var tenant = await TenantAsync();
            var device = (await ((IDeviceRepository)Store).GetForTenantAsync(tenant.Id))[0];
            var requester = Guid.NewGuid();
            var (a, _) = await Actions.AddAsync(new DeviceActionRequest
            {
                Id = Guid.NewGuid(), TenantId = tenant.Id, DeviceId = deviceId ?? device.Id, DeviceName = device.DeviceName, Action = action,
                Reason = "test", Status = DeviceActionStatus.PendingApproval, RequestedAt = Time.Now, RequestedByUserId = requester,
                RequestedByName = "Req", ExpiresAt = Time.Now.AddHours(24)
            });
            return (await Actions.DecideAsync(a.Id, true, selfApproved ? requester : Guid.NewGuid(), "Approver", approverRole, null, Time.Now))!;
        }

        public async Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) =>
            (await Store.QueryAsync(new AuditQuery { Limit = 1000 })).Where(e => e.Action == action).ToList();
    }

    [Fact]
    public async Task SendsAnApprovedActionOnceAfterWritingTheAuditEntry()
    {
        var h = new Harness();
        var a = await h.ApprovedAsync();
        var tenant = await h.TenantAsync();
        h.Sender.BeforeSend = async () => Assert.Single(await h.EventsAsync(AuditActions.DeviceActionSending)); // audit first

        Assert.Equal(1, await h.Service.RunOnceAsync());
        Assert.Equal(0, await h.Service.RunOnceAsync()); // never sent twice

        Assert.Equal([(tenant.EntraTenantId, a.DeviceId, DeviceAction.Sync)], h.Sender.Sent);
        var done = (await h.Actions.GetAsync(a.Id))!;
        Assert.Equal(DeviceActionStatus.Sent, done.Status);
        Assert.Equal(T0, done.SentAt);
        var result = Assert.Single(await h.EventsAsync(AuditActions.DeviceActionResult));
        Assert.Equal(AuditOutcome.Success, result.Outcome);
        Assert.Equal("SecurePulse Worker", result.ActorName);
        Assert.Equal("Approver", result.Details["approvedBy"]);
    }

    [Fact]
    public async Task NothingIsSentWhenTheAuditEntryCantBeWritten()
    {
        var h = new Harness();
        var a = await h.ApprovedAsync();
        h.Audit.Fail = true;

        await h.Service.RunOnceAsync();

        Assert.Empty(h.Sender.Sent);
        var failed = (await h.Actions.GetAsync(a.Id))!;
        Assert.Equal(DeviceActionStatus.Failed, failed.Status);
        Assert.Contains("audit log", failed.Error);
    }

    [Theory]
    [InlineData("self-approved", "own request")]
    [InlineData("wipe approved by an MSP admin", "Owner")]
    [InlineData("approved by a client viewer", "Owners and MSP admins")]
    [InlineData("device id that isn't a GUID", "device ID")]
    public async Task ApprovalsThatBreakThePolicyAreNotSent(string scenario, string expected)
    {
        // Rows like these can't come from the portal; they model a tampered or buggy queue.
        var h = new Harness();
        var a = scenario switch
        {
            "self-approved" => await h.ApprovedAsync(selfApproved: true),
            "wipe approved by an MSP admin" => await h.ApprovedAsync(DeviceAction.Wipe, PortalRole.MspAdmin),
            "approved by a client viewer" => await h.ApprovedAsync(approverRole: PortalRole.ClientViewer),
            _ => await h.ApprovedAsync(deviceId: "../../users")
        };

        await h.Service.RunOnceAsync();

        Assert.Empty(h.Sender.Sent);
        Assert.Equal(0, h.Tokens.Calls);
        var failed = (await h.Actions.GetAsync(a.Id))!;
        Assert.Equal(DeviceActionStatus.Failed, failed.Status);
        Assert.StartsWith("Not sent:", failed.Error);
        Assert.Contains(expected, failed.Error);
        Assert.Empty(await h.EventsAsync(AuditActions.DeviceActionSending));
    }

    [Fact]
    public async Task RemediationTurnedOffAfterApprovalStopsTheSend()
    {
        var h = new Harness();
        var a = await h.ApprovedAsync();
        await ((IOnboardingRepository)h.Store).DisableRemediationAsync(a.TenantId);

        await h.Service.RunOnceAsync();

        Assert.Empty(h.Sender.Sent);
        Assert.Contains("turned off", (await h.Actions.GetAsync(a.Id))!.Error);
    }

    public static TheoryData<string, Func<Guid, string>, string> BadTokens => new()
    {
        { "extra permission", tid => Jwt.With(tid, RemediationPermissions.PrivilegedOperations, "Directory.ReadWrite.All"), "Directory.ReadWrite.All" },
        { "consent withdrawn", tid => Jwt.With(tid), "hasn't granted" },
        { "other tenant", _ => Jwt.With(Guid.NewGuid(), RemediationPermissions.PrivilegedOperations), "issued for tenant" },
        { "not a token", _ => "garbage", "couldn't read" },
        { "no token", _ => throw new GraphAuthException("Certificate not found"), "Certificate not found" }
    };

    [Theory]
    [MemberData(nameof(BadTokens))]
    public async Task TheRemediationTokenIsCheckedBeforeEverySend(string _, Func<Guid, string> issue, string expected)
    {
        var h = new Harness { Tokens = new Tokens(issue) };
        var a = await h.ApprovedAsync();

        await h.Service.RunOnceAsync();

        Assert.Empty(h.Sender.Sent);
        Assert.Contains(expected, (await h.Actions.GetAsync(a.Id))!.Error);
    }

    [Fact]
    public async Task AFailedSendIsRecordedAndNeverRetried()
    {
        var h = new Harness { Sender = new Sender(() => new DeviceActionSendResult(false, "Intune returned 500.")) };
        var a = await h.ApprovedAsync(DeviceAction.Restart);

        await h.Service.RunOnceAsync();
        await h.Service.RunOnceAsync();

        Assert.Single(h.Sender.Sent);
        var failed = (await h.Actions.GetAsync(a.Id))!;
        Assert.Equal((DeviceActionStatus.Failed, "Intune returned 500."), (failed.Status, failed.Error));
        Assert.Equal(AuditOutcome.Failure, Assert.Single(await h.EventsAsync(AuditActions.DeviceActionResult)).Outcome);
    }

    [Fact]
    public async Task StaleRequestsExpireAndStuckSendsFailAsUnknown()
    {
        var h = new Harness();
        var tenant = await h.TenantAsync();
        var devices = await ((IDeviceRepository)h.Store).GetForTenantAsync(tenant.Id);
        async Task<DeviceActionRequest> Add(int device) => (await h.Actions.AddAsync(new DeviceActionRequest
        {
            Id = Guid.NewGuid(), TenantId = tenant.Id, DeviceId = devices[device].Id, DeviceName = devices[device].DeviceName, Action = DeviceAction.Sync,
            Reason = "r", Status = DeviceActionStatus.PendingApproval, RequestedAt = h.Time.Now, RequestedByUserId = Guid.NewGuid(),
            RequestedByName = "Req", ExpiresAt = h.Time.Now + DeviceActionPolicy.ApprovalWindow
        })).Request;

        var unapproved = await Add(0);
        var approvedLate = await Add(1);
        await h.Actions.DecideAsync(approvedLate.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, h.Time.Now);
        var stuck = await Add(2);
        await h.Actions.DecideAsync(stuck.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, h.Time.Now.AddMinutes(-1));
        await h.Actions.ClaimNextApprovedAsync(h.Time.Now); // the oldest approval (stuck) is claimed, as a crashed Worker would leave it
        Assert.Equal(DeviceActionStatus.Sending, (await h.Actions.GetAsync(stuck.Id))!.Status);

        h.Time.Advance(DeviceActionPolicy.ApprovalWindow + TimeSpan.FromMinutes(1));
        await h.Service.RunOnceAsync();

        Assert.Empty(h.Sender.Sent);
        Assert.Equal(DeviceActionStatus.Expired, (await h.Actions.GetAsync(unapproved.Id))!.Status);
        Assert.Equal(DeviceActionStatus.Expired, (await h.Actions.GetAsync(approvedLate.Id))!.Status);
        var unknown = (await h.Actions.GetAsync(stuck.Id))!;
        Assert.Equal(DeviceActionStatus.Failed, unknown.Status);
        Assert.Contains("may have reached Intune", unknown.Error);
        Assert.Equal(2, (await h.EventsAsync(AuditActions.DeviceActionExpired)).Count);
    }
}

/// <summary>The Graph calls themselves, against a stub handler.</summary>
public class IntuneDeviceActionSenderTests
{
    private sealed class Stub(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Url, string? Auth, string? Body)> Calls { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls.Add((request.Method, request.RequestUri!.ToString(), request.Headers.Authorization?.ToString(),
                request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken)));
            return await respond(request, cancellationToken);
        }
    }

    private static readonly string DeviceId = Guid.NewGuid().ToString();

    private static (IntuneDeviceActionSender Sender, Stub Stub) Create(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond, TimeSpan? timeout = null) =>
        Create((r, _) => respond(r), timeout);

    private static (IntuneDeviceActionSender Sender, Stub Stub) Create(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond, TimeSpan? timeout = null)
    {
        var stub = new Stub(respond);
        return (new IntuneDeviceActionSender(new HttpClient(stub), new IntuneOptions { GraphBaseUrl = "https://graph.example/" },
            new RemediationOptions { SendTimeout = timeout ?? TimeSpan.FromSeconds(30) }), stub);
    }

    [Theory]
    [InlineData(DeviceAction.Sync, "syncDevice", null)]
    [InlineData(DeviceAction.Restart, "rebootNow", null)]
    [InlineData(DeviceAction.Retire, "retire", null)]
    [InlineData(DeviceAction.Wipe, "wipe", """{"keepEnrollmentData":false,"keepUserData":false}""")]
    [InlineData(DeviceAction.DefenderQuickScan, "windowsDefenderScan", """{"quickScan":true}""")]
    [InlineData(DeviceAction.DefenderUpdateSignatures, "windowsDefenderUpdateSignatures", null)]
    public async Task PostsTheRightGraphAction(DeviceAction action, string path, string? body)
    {
        var (sender, stub) = Create(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent)));

        var result = await sender.SendAsync(Guid.NewGuid(), DeviceId, action, "tok");

        Assert.True(result.Succeeded);
        var call = Assert.Single(stub.Calls);
        Assert.Equal(HttpMethod.Post, call.Method);
        Assert.Equal($"https://graph.example/v1.0/deviceManagement/managedDevices/{DeviceId}/{path}", call.Url);
        Assert.Equal("Bearer tok", call.Auth);
        Assert.Equal(body, call.Body);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, "doesn't know this device")]
    [InlineData(HttpStatusCode.Forbidden, "refused the action (403)")]
    [InlineData(HttpStatusCode.TooManyRequests, "throttling")]
    [InlineData(HttpStatusCode.InternalServerError, "Intune returned 500")]
    public async Task ErrorsBecomeReadableFailures(HttpStatusCode status, string expected)
    {
        var (sender, stub) = Create(_ => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("{\"error\":{}}") }));

        var result = await sender.SendAsync(Guid.NewGuid(), DeviceId, DeviceAction.Sync, "tok");

        Assert.False(result.Succeeded);
        Assert.Contains(expected, result.Error);
        Assert.Single(stub.Calls); // no retries
    }

    [Fact]
    public async Task ATimeoutSaysTheOutcomeIsUnknown()
    {
        var (sender, _) = Create(async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); return new HttpResponseMessage(); },
            TimeSpan.FromMilliseconds(100));

        var result = await sender.SendAsync(Guid.NewGuid(), DeviceId, DeviceAction.Wipe, "tok");

        Assert.False(result.Succeeded);
        Assert.Contains("may still have reached Intune", result.Error);
    }

    [Theory]
    [InlineData("../../users/me")]
    [InlineData("abc")]
    [InlineData("")]
    public async Task DeviceIdsThatArentGuidsNeverReachAUrl(string deviceId)
    {
        var (sender, stub) = Create(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent)));

        Assert.False((await sender.SendAsync(Guid.NewGuid(), deviceId, DeviceAction.Wipe, "tok")).Succeeded);
        Assert.Empty(stub.Calls);
    }
}

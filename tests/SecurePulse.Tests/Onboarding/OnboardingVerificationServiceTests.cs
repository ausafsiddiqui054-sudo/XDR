using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;
using SecurePulse.Web.Services;
using SecurePulse.Worker;

namespace SecurePulse.Tests.Onboarding;

public class OnboardingVerificationServiceTests
{
    private const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly string[] Required = AssessmentPermissions.Required.Select(p => p.Name).ToArray();

    private sealed class Tokens(Func<Tenant, string> issue) : IGraphTokenProvider
    {
        public List<Tenant> Requests { get; } = [];

        public Task<string> GetTokenAsync(Tenant tenant, CancellationToken cancellationToken = default)
        {
            Requests.Add(tenant);
            return Task.FromResult(issue(tenant));
        }
    }

    private sealed class Source : IDeviceInventorySource
    {
        public List<Tenant> Synced { get; } = [];
        public string Name => "Intune";

        public Task<DeviceSyncResult> GetDevicesAsync(Tenant tenant, CancellationToken cancellationToken = default)
        {
            Synced.Add(tenant);
            return Task.FromResult(new DeviceSyncResult
            {
                TenantId = tenant.Id, Source = Name, StartedAt = T0, CompletedAt = T0,
                Devices = [new ManagedDevice { Id = "d1", TenantId = tenant.Id, DeviceName = "PC-1", Platform = DevicePlatform.Windows, ComplianceState = DeviceComplianceState.Compliant }]
            });
        }
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(T0);
        public Source Source { get; } = new();
        public OnboardingVerificationOptions Options { get; } = new() { CertificateThumbprint = Thumbprint };
        public required Tokens Tokens { get; init; }

        public OnboardingVerificationService Service => new(Store, Tokens,
            new DeviceSyncService(Store, Store, Source, Microsoft.Extensions.Options.Options.Create(new DeviceSyncOptions()), NullLogger<DeviceSyncService>.Instance),
            Store, Microsoft.Extensions.Options.Options.Create(Options), Time, NullLogger<OnboardingVerificationService>.Instance);

        public async Task<OnboardingRequest> ConsentedRequestAsync(Guid entraTenantId)
        {
            var request = new OnboardingRequest
            {
                Id = Guid.NewGuid(), DisplayName = "Contoso Clinic", PrimaryDomain = "contoso.com", PartnerName = "Gulf IT Services",
                Industry = "Healthcare", EntraTenantId = entraTenantId, Status = OnboardingStatus.AwaitingConsent,
                CreatedAt = T0.AddMinutes(-5), ExpiresAt = T0.AddDays(7)
            };
            IOnboardingRepository repo = Store;
            await repo.AddAsync(request, Guid.NewGuid().ToString("N"));
            Assert.True(await repo.MarkConsentReceivedAsync(request.Id, T0));
            return (await repo.GetAsync(request.Id))!;
        }

        public Task<OnboardingRequest?> ReloadAsync(OnboardingRequest r) => ((IOnboardingRepository)Store).GetAsync(r.Id);
    }

    [Fact]
    public async Task VerifiedConsent_CreatesTenantAndRunsFirstSync()
    {
        var tid = Guid.NewGuid();
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, [.. Required, "User.Read.All"])) };
        var request = await h.ConsentedRequestAsync(tid);

        Assert.True(await h.Service.VerifyAsync(request));

        var done = await h.ReloadAsync(request);
        Assert.Equal(OnboardingStatus.Completed, done!.Status);
        Assert.Equal(T0, done.CompletedAt);
        Assert.Equal(Required.Append("User.Read.All").Order(StringComparer.OrdinalIgnoreCase), done.GrantedPermissions);
        Assert.Null(done.ProtectedState);

        var tenant = await h.Store.GetAsync(done.TenantId!.Value);
        Assert.NotNull(tenant);
        Assert.Equal(tid, tenant.EntraTenantId);
        Assert.Equal("Contoso Clinic", tenant.DisplayName);
        Assert.Equal("Gulf IT Services", tenant.PartnerName);
        Assert.Equal(TenantConsentState.ReadOnlyGranted, tenant.ConsentState);
        Assert.Equal(Thumbprint, tenant.CredentialReference);

        // Token requested for the client tenant with the Worker's certificate.
        Assert.Equal(tid, h.Tokens.Requests.Single().EntraTenantId);
        Assert.Equal(Thumbprint, h.Tokens.Requests.Single().CredentialReference);

        Assert.Equal(tenant.Id, h.Source.Synced.Single().Id);
        Assert.True((await h.Store.GetSyncStatusAsync(tenant.Id))!.Succeeded);
    }

    [Fact]
    public async Task ConnectedTenantIsAuditedByTheWorker()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, Required)) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        await h.Service.VerifyAsync(request);

        var e = await Audit.AuditAssert.SingleAsync(h.Store, AuditActions.TenantConnected, AuditOutcome.Success);
        Assert.Equal("SecurePulse Worker", e.ActorName);
        Assert.Null(e.ActorUserId);
        Assert.Equal((await h.ReloadAsync(request))!.TenantId, e.TenantId);
        Assert.Equal(string.Join(", ", Required.Order(StringComparer.OrdinalIgnoreCase)), e.Details["permissions"]);
        Assert.Equal("contoso.com", e.Details["domain"]);
    }

    [Fact]
    public async Task OnlyTheFinalVerificationFailureIsAudited()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, Required[0])) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        await h.Service.VerifyAsync(request);
        await h.Service.VerifyAsync((await h.ReloadAsync(request))!);
        Assert.Empty(await Audit.AuditAssert.AllAsync(h.Store));

        h.Time.Advance(h.Options.VerificationWindow + TimeSpan.FromSeconds(1));
        await h.Service.VerifyAsync((await h.ReloadAsync(request))!);

        var e = await Audit.AuditAssert.SingleAsync(h.Store, AuditActions.VerificationFailed, AuditOutcome.Failure);
        Assert.Contains(Required[1], e.Summary);
    }

    [Fact]
    public async Task NonReadOnlyGrantIsAuditedAsDenied()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, [.. Required, "Mail.Send"])) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        await h.Service.VerifyAsync(request);

        var e = await Audit.AuditAssert.SingleAsync(h.Store, AuditActions.VerificationFailed, AuditOutcome.Denied);
        Assert.Contains("Mail.Send", e.Summary);
    }

    [Fact]
    public async Task ReConsent_UpdatesTheExistingTenantInsteadOfDuplicating()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, Required)) };
        var existing = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.Pending);
        var count = (await h.Store.GetAllAsync()).Count;
        var request = await h.ConsentedRequestAsync(existing.EntraTenantId);

        Assert.True(await h.Service.VerifyAsync(request));

        var tenants = await h.Store.GetAllAsync();
        Assert.Equal(count, tenants.Count);
        var updated = tenants.Single(t => t.Id == existing.Id);
        Assert.Equal(existing.DisplayName, updated.DisplayName);
        Assert.Equal(TenantConsentState.ReadOnlyGranted, updated.ConsentState);
        Assert.Equal(Thumbprint, updated.CredentialReference);
        Assert.Equal(existing.Id, (await h.ReloadAsync(request))!.TenantId);
    }

    [Fact]
    public async Task WritePermissions_FailImmediately()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, [.. Required, "DeviceManagementManagedDevices.PrivilegedOperations.All", "User.ReadWrite.All"])) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));

        var failed = await h.ReloadAsync(request);
        Assert.Equal(OnboardingStatus.Failed, failed!.Status);
        Assert.Contains("DeviceManagementManagedDevices.PrivilegedOperations.All, User.ReadWrite.All", failed.LastError);
        Assert.Null(failed.TenantId);
        Assert.Empty(h.Source.Synced);
    }

    [Fact]
    public async Task TokenForAnotherTenant_Fails()
    {
        var h = new Harness { Tokens = new Tokens(_ => Jwt.With(Guid.NewGuid(), Required)) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));

        Assert.Equal(OnboardingStatus.Failed, (await h.ReloadAsync(request))!.Status);
    }

    [Fact]
    public async Task MalformedToken_Fails()
    {
        var h = new Harness { Tokens = new Tokens(_ => "garbage") };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));

        Assert.Equal(OnboardingStatus.Failed, (await h.ReloadAsync(request))!.Status);
    }

    [Fact]
    public async Task MissingPermissions_RetryUntilTheWindowCloses()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, Required[0])) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));
        var first = await h.ReloadAsync(request);
        Assert.Equal(OnboardingStatus.Verifying, first!.Status);
        Assert.Equal(1, first.VerificationAttempts);
        Assert.Contains(Required[1], first.LastError);

        h.Time.Advance(h.Options.VerificationWindow + TimeSpan.FromSeconds(1));
        Assert.False(await h.Service.VerifyAsync(first));
        Assert.Equal(OnboardingStatus.Failed, (await h.ReloadAsync(request))!.Status);
    }

    [Fact]
    public async Task TokenNotYetAvailable_RetriesThenSucceeds()
    {
        var attempts = 0;
        var h = new Harness
        {
            Tokens = new Tokens(t => ++attempts == 1
                ? throw new GraphAuthException("Could not get a Graph token: AADSTS700016: Application not found in the directory")
                : Jwt.With(t.EntraTenantId, Required))
        };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));
        var waiting = await h.ReloadAsync(request);
        Assert.Equal(OnboardingStatus.Verifying, waiting!.Status);
        Assert.Contains("AADSTS700016", waiting.LastError);

        h.Time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, await h.Service.VerifyPendingAsync());
        Assert.Equal(OnboardingStatus.Completed, (await h.ReloadAsync(request))!.Status);
    }

    [Fact]
    public async Task MissingCertificateConfig_IsReportedWithoutCallingEntra()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, Required)) };
        h.Options.CertificateThumbprint = "";
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));

        var stored = await h.ReloadAsync(request);
        Assert.Equal(OnboardingStatus.Verifying, stored!.Status);
        Assert.Contains("CertificateThumbprint", stored.LastError);
        Assert.Empty(h.Tokens.Requests);
    }

    [Fact]
    public async Task ActionPermissionsWithoutWriteInTheName_AlsoFail()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, [.. Required, "Mail.Send"])) };
        var request = await h.ConsentedRequestAsync(Guid.NewGuid());

        Assert.False(await h.Service.VerifyAsync(request));

        Assert.Contains("Mail.Send", (await h.ReloadAsync(request))!.LastError);
    }

    [Theory]
    [InlineData("DeviceManagementManagedDevices.Read.All", true)]
    [InlineData("Directory.Read.All", true)]
    [InlineData("User.ReadBasic.All", true)]
    [InlineData("Policy.Read.ConditionalAccess", true)]
    [InlineData("RoleManagement.Read.Directory", true)]
    [InlineData("User.ReadWrite.All", false)]
    [InlineData("DeviceManagementManagedDevices.PrivilegedOperations.All", false)]
    [InlineData("Mail.Send", false)]
    [InlineData("Sites.FullControl.All", false)]
    [InlineData("Application.ReadWrite.OwnedBy", false)]
    [InlineData("Files.Read.All.Write", false)]
    [InlineData("", false)]
    public void IsReadOnly(string permission, bool expected) =>
        Assert.Equal(expected, AssessmentPermissions.IsReadOnly(permission));
}

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;
using SecurePulse.Web.Services.Onboarding;

namespace SecurePulse.Tests.Onboarding;

public class OnboardingServiceTests
{
    private const string AppClientId = "11111111-2222-3333-4444-555555555555";
    private const string Portal = "https://portal.securepulse.test/";
    private static readonly Guid ClientTenant = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    internal sealed class Resolver(Func<string, Guid?> resolve) : IEntraTenantResolver
    {
        public List<string> Calls { get; } = [];

        public Task<Guid?> ResolveAsync(string domain, CancellationToken ct = default)
        {
            Calls.Add(domain);
            return Task.FromResult(resolve(domain));
        }
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
        public Resolver Resolver { get; init; } = new(_ => ClientTenant);
        public OnboardingOptions Options { get; } = new() { AppClientId = AppClientId };
        public IDataProtectionProvider Protection { get; init; } = new EphemeralDataProtectionProvider();
        public FixedUser User { get; } = FixedUser.MspAdmin();

        public OnboardingService Service => new(Store, Store, Store, Store, Resolver, Protection, Options, Time, User,
            new AuditTrail(Store, User, Time, NullLogger<AuditTrail>.Instance), NullLogger<OnboardingService>.Instance);
        public IOnboardingRepository Requests => Store;
    }

    private static ConnectTenantForm Form(string domain = "contoso.com") => new()
    {
        DisplayName = "Contoso Clinic", PrimaryDomain = domain, PartnerName = "Gulf IT Services", Industry = "Healthcare"
    };

    private static async Task<(OnboardingRequest Request, string State)> StartAsync(Harness h)
    {
        var result = await h.Service.StartAsync(Form());
        Assert.Null(result.Error);
        var url = h.Service.GetConsentUrl(result.Request!, Portal)!;
        var state = QueryHelpers.ParseQuery(new Uri(url).Query)["state"].ToString();
        return (result.Request!, state);
    }

    // --- Starting a connection -----------------------------------------------------------

    [Fact]
    public async Task Start_CreatesRequestAndAdminConsentLink()
    {
        var h = new Harness();

        var (request, state) = await StartAsync(h);

        Assert.Equal(OnboardingStatus.AwaitingConsent, request.Status);
        Assert.Equal(ClientTenant, request.EntraTenantId);
        Assert.Equal("Adam Admin <adam@msp.example>", request.StartedBy);
        Assert.Equal("contoso.com", request.PrimaryDomain);
        Assert.Equal(h.Time.Now.AddDays(7), request.ExpiresAt);

        var url = new Uri(h.Service.GetConsentUrl(request, Portal)!);
        var query = QueryHelpers.ParseQuery(url.Query);
        Assert.Equal("login.microsoftonline.com", url.Host);
        Assert.Equal($"/{ClientTenant}/v2.0/adminconsent", url.AbsolutePath);
        Assert.Equal(AppClientId, query["client_id"]);
        Assert.Equal("https://graph.microsoft.com/.default", query["scope"]);
        Assert.Equal(Portal + "onboarding/consent-callback", query["redirect_uri"]);
        Assert.True(state.Length >= 40, "state should carry at least 256 bits");

        // Only a hash of the state is used for lookup; the raw value is not stored readable.
        Assert.Equal(request.Id, (await h.Requests.FindByStateHashAsync(OnboardingService.HashState(state)))?.Id);
        Assert.Null(await h.Requests.FindByStateHashAsync(state));
        Assert.DoesNotContain(state, request.ProtectedState);
    }

    [Fact]
    public async Task Start_EachLinkHasItsOwnState()
    {
        var h = new Harness();
        var (first, s1) = await StartAsync(h);
        await h.Service.CancelAsync(first.Id);

        var (_, s2) = await StartAsync(h);

        Assert.NotEqual(s1, s2);
    }

    [Fact]
    public async Task Start_ConfiguredRedirectUriWins()
    {
        var h = new Harness();
        h.Options.RedirectUri = "https://consent.example.com/cb";
        var (request, _) = await StartAsync(h);

        var query = QueryHelpers.ParseQuery(new Uri(h.Service.GetConsentUrl(request, Portal)!).Query);

        Assert.Equal("https://consent.example.com/cb", query["redirect_uri"]);
    }

    [Theory]
    [InlineData("  Contoso.COM. ", "contoso.com")]
    [InlineData("contoso.onmicrosoft.com", "contoso.onmicrosoft.com")]
    [InlineData("sub-domain.contoso.co.uk", "sub-domain.contoso.co.uk")]
    public void NormalizeDomain_Accepts(string input, string expected) =>
        Assert.Equal(expected, OnboardingService.NormalizeDomain(input));

    [Theory]
    [InlineData("")]
    [InlineData("contoso")]
    [InlineData("https://contoso.com")]
    [InlineData("contoso.com/path")]
    [InlineData("admin@contoso.com")]
    [InlineData("-contoso.com")]
    [InlineData("contoso-.com")]
    [InlineData("contoso..com")]
    [InlineData("contoso.com?x=1")]
    [InlineData("../contoso.com")]
    [InlineData("contoso.123")]
    public async Task Start_RejectsInvalidDomainsWithoutCallingEntra(string domain)
    {
        var h = new Harness();

        var result = await h.Service.StartAsync(Form(domain));

        Assert.Null(result.Request);
        Assert.Contains("domain", result.Error);
        Assert.Empty(h.Resolver.Calls);
    }

    [Fact]
    public async Task Start_UnknownDomain()
    {
        var h = new Harness { Resolver = new Resolver(_ => null) };

        var result = await h.Service.StartAsync(Form("not-a-tenant.example"));

        Assert.Null(result.Request);
        Assert.Contains("isn't a Microsoft 365", result.Error);
    }

    [Fact]
    public async Task Start_EntraUnreachable()
    {
        var h = new Harness { Resolver = new Resolver(_ => throw new HttpRequestException("dns")) };

        var result = await h.Service.StartAsync(Form());

        Assert.Null(result.Request);
        Assert.Contains("Couldn't reach Microsoft Entra", result.Error);
    }

    [Fact]
    public async Task Start_RequiresAppClientId()
    {
        var h = new Harness();
        h.Options.AppClientId = "";

        var result = await h.Service.StartAsync(Form());

        Assert.False(h.Service.IsConfigured);
        Assert.Contains("AppClientId", result.Error);
        Assert.Empty(h.Resolver.Calls);
    }

    [Fact]
    public async Task Start_AllowsReconsentForAConnectedTenant()
    {
        // E.g. after the app gained permissions: the admin approves again and the tenant is updated.
        var store = new SampleDataStore();
        var connected = (await store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);
        var h = new HarnessWith(store, new Resolver(_ => connected.EntraTenantId));

        var result = await h.Service.StartAsync(Form());

        Assert.Null(result.Error);
        Assert.Equal(connected.Id, (await h.Service.GetConnectedTenantAsync(result.Request!))?.Id);
    }

    [Fact]
    public async Task Start_AllowsReconnectingAPendingTenant()
    {
        var store = new SampleDataStore();
        var pending = (await store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.Pending);
        var h = new HarnessWith(store, new Resolver(_ => pending.EntraTenantId));

        var result = await h.Service.StartAsync(Form());

        Assert.NotNull(result.Request);
    }

    [Fact]
    public async Task Start_ReturnsTheInProgressRequestForTheSameTenant()
    {
        var h = new Harness();
        var (first, _) = await StartAsync(h);

        var again = await h.Service.StartAsync(Form());

        Assert.True(again.Reused);
        Assert.Equal(first.Id, again.Request!.Id);
    }

    [Fact]
    public async Task Start_ExpiredRequestIsNotReused()
    {
        var h = new Harness();
        var (first, _) = await StartAsync(h);
        h.Time.Advance(TimeSpan.FromDays(8));

        var again = await h.Service.StartAsync(Form());

        Assert.False(again.Reused);
        Assert.NotEqual(first.Id, again.Request!.Id);
    }

    [Fact]
    public async Task ClientViewersCannotOnboard()
    {
        var h = new Harness();
        var (request, _) = await StartAsync(h);
        h.User.User = FixedUser.Viewer(Guid.NewGuid()).User;

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Service.StartAsync(Form("other.example")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Service.GetAsync(request.Id));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Service.CancelAsync(request.Id));
        Assert.Empty(await h.Service.GetOpenAsync());
        Assert.DoesNotContain("other.example", h.Resolver.Calls);
    }

    [Fact]
    public async Task ConsentCallbackNeedsNoSignedInUser()
    {
        var h = new Harness();
        var (_, state) = await StartAsync(h);
        h.User.User = UserContext.Anonymous;

        Assert.Equal(ConsentCallbackOutcome.Received, await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null));
    }

    // --- Consent callback ----------------------------------------------------------------

    [Fact]
    public async Task Callback_RecordsConsentAndMovesToVerifying()
    {
        var h = new Harness();
        var (request, state) = await StartAsync(h);

        var outcome = await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null);

        Assert.Equal(ConsentCallbackOutcome.Received, outcome);
        var stored = await h.Requests.GetAsync(request.Id);
        Assert.Equal(OnboardingStatus.Verifying, stored!.Status);
        Assert.Equal(h.Time.Now, stored.ConsentReceivedAt);
        Assert.Null(h.Service.GetConsentUrl(stored, Portal));
    }

    [Fact]
    public async Task Callback_LinkWorksOnlyOnce()
    {
        var h = new Harness();
        var (_, state) = await StartAsync(h);
        await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null);

        var replay = await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null);

        Assert.Equal(ConsentCallbackOutcome.ExpiredOrUsed, replay);
    }

    [Fact]
    public async Task Callback_ExpiredLinkIsRejected()
    {
        var h = new Harness();
        var (request, state) = await StartAsync(h);
        h.Time.Advance(TimeSpan.FromDays(7));

        var outcome = await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null);

        Assert.Equal(ConsentCallbackOutcome.ExpiredOrUsed, outcome);
        Assert.Equal(OnboardingStatus.AwaitingConsent, (await h.Requests.GetAsync(request.Id))!.Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("forged-state")]
    public async Task Callback_UnknownStateIsInvalid(string? state)
    {
        var h = new Harness();
        await StartAsync(h);

        Assert.Equal(ConsentCallbackOutcome.Invalid, await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null));
    }

    [Fact]
    public async Task Callback_OverlongStateIsInvalid()
    {
        var h = new Harness();

        Assert.Equal(ConsentCallbackOutcome.Invalid,
            await h.Service.HandleCallbackAsync(new string('a', 5000), ClientTenant.ToString(), "True", null, null));
    }

    [Fact]
    public async Task Callback_ConsentFromAnotherTenantIsRejectedButLinkStaysUsable()
    {
        var h = new Harness();
        var (request, state) = await StartAsync(h);
        var other = Guid.NewGuid();

        var outcome = await h.Service.HandleCallbackAsync(state, other.ToString(), "True", null, null);

        Assert.Equal(ConsentCallbackOutcome.WrongTenant, outcome);
        var stored = await h.Requests.GetAsync(request.Id);
        Assert.Equal(OnboardingStatus.AwaitingConsent, stored!.Status);
        Assert.Contains(other.ToString(), stored.LastError);

        Assert.Equal(ConsentCallbackOutcome.Received, await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null));
    }

    [Fact]
    public async Task Callback_DeclinedConsentIsRecordedAndLinkStaysUsable()
    {
        var h = new Harness();
        var (request, state) = await StartAsync(h);

        var outcome = await h.Service.HandleCallbackAsync(state, null, null, "access_denied",
            "AADSTS65004: User declined to consent to access the app.\r\nTrace ID: 123\r\nCorrelation ID: 456");

        Assert.Equal(ConsentCallbackOutcome.Declined, outcome);
        var stored = await h.Requests.GetAsync(request.Id);
        Assert.Equal(OnboardingStatus.AwaitingConsent, stored!.Status);
        Assert.Equal("The admin didn't grant consent: AADSTS65004: User declined to consent to access the app.", stored.LastError);
        Assert.NotNull(h.Service.GetConsentUrl(stored, Portal));
    }

    [Theory]
    [InlineData("False", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]
    [InlineData(null, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]
    [InlineData("True", "not-a-guid")]
    [InlineData("True", null)]
    public async Task Callback_IncompleteResponseIsInvalid(string? adminConsent, string? tenant)
    {
        var h = new Harness();
        var (request, state) = await StartAsync(h);

        Assert.Equal(ConsentCallbackOutcome.Invalid, await h.Service.HandleCallbackAsync(state, tenant, adminConsent, null, null));
        Assert.Equal(OnboardingStatus.AwaitingConsent, (await h.Requests.GetAsync(request.Id))!.Status);
    }

    // --- Link display --------------------------------------------------------------------

    [Fact]
    public async Task ConsentUrl_UnavailableAfterCancelOrExpiry()
    {
        var h = new Harness();
        var (request, state) = await StartAsync(h);

        h.Time.Advance(TimeSpan.FromDays(7));
        Assert.Null(h.Service.GetConsentUrl((await h.Requests.GetAsync(request.Id))!, Portal));

        await h.Service.CancelAsync(request.Id);
        Assert.Equal(OnboardingStatus.Cancelled, (await h.Requests.GetAsync(request.Id))!.Status);
        Assert.Equal(ConsentCallbackOutcome.ExpiredOrUsed, await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null));
    }

    [Fact]
    public async Task ConsentUrl_NullWhenKeysChanged()
    {
        var h = new Harness();
        var (request, _) = await StartAsync(h);
        var otherKeys = new HarnessWith(h.Store, h.Resolver) { Protection = new EphemeralDataProtectionProvider() };

        Assert.Null(otherKeys.Service.GetConsentUrl(request, Portal));
    }

    private sealed class HarnessWith(SampleDataStore store, IEntraTenantResolver resolver)
    {
        public IDataProtectionProvider Protection { get; init; } = new EphemeralDataProtectionProvider();

        public OnboardingService Service
        {
            get
            {
                var time = new FakeTime(DateTimeOffset.UtcNow);
                var owner = FixedUser.Owner();
                return new(store, store, store, store, resolver, Protection, new OnboardingOptions { AppClientId = AppClientId }, time, owner,
                    new AuditTrail(store, owner, time, NullLogger<AuditTrail>.Instance), NullLogger<OnboardingService>.Instance);
            }
        }
    }

    // --- Wazuh agent group ---------------------------------------------------------------------

    [Fact]
    public async Task OnlyOwnersSetTheWazuhGroup_AndEachChangeIsAudited()
    {
        var h = new Harness();
        var tenants = await h.Store.GetAllAsync();
        var (a, b) = (tenants[0], tenants[1]);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Service.SetWazuhAgentGroupAsync(a.Id, "clinic-a"));

        h.User.User = FixedUser.Owner().User;
        Assert.Equal((true, $"{a.DisplayName} now reads Wazuh agents in 'clinic-a'."), await h.Service.SetWazuhAgentGroupAsync(a.Id, " clinic-a "));
        Assert.Equal("clinic-a", (await h.Store.GetAsync(a.Id))!.WazuhAgentGroup);

        var (ok, message) = await h.Service.SetWazuhAgentGroupAsync(b.Id, "clinic-a");
        Assert.False(ok);
        Assert.Contains("already belongs to another tenant", message);

        Assert.False((await h.Service.SetWazuhAgentGroupAsync(b.Id, "default")).Ok);
        Assert.False((await h.Service.SetWazuhAgentGroupAsync(b.Id, "bad group")).Ok);
        Assert.Null((await h.Store.GetAsync(b.Id))!.WazuhAgentGroup);

        Assert.True((await h.Service.SetWazuhAgentGroupAsync(a.Id, "clinic-a-v2")).Ok);
        Assert.True((await h.Service.SetWazuhAgentGroupAsync(a.Id, "")).Ok);
        Assert.Null((await h.Store.GetAsync(a.Id))!.WazuhAgentGroup);

        var events = await ((IAuditLog)h.Store).QueryAsync(new AuditQuery { Action = AuditActions.WazuhGroupChanged });
        Assert.Equal(3, events.Count);
        Assert.All(events, e => Assert.Equal("Olivia Owner <olivia@msp.example>", e.ActorName));
        Assert.Contains(events, e => e.Details["group"] == "clinic-a" && e.Details["previousGroup"] == "" && e.TenantId == a.Id);
        Assert.Contains(events, e => e.Details["group"] == "clinic-a-v2" && e.Details["previousGroup"] == "clinic-a");
        Assert.Contains(events, e => e.Details["group"] == "" && e.Details["previousGroup"] == "clinic-a-v2" && e.Summary.StartsWith("Stopped reading"));
    }

    [Fact]
    public async Task SettingTheSameWazuhGroupAgain_IsNotAChange()
    {
        var h = new Harness();
        h.User.User = FixedUser.Owner().User;
        var tenant = (await h.Store.GetAllAsync())[0];
        await h.Service.SetWazuhAgentGroupAsync(tenant.Id, "clinic-a");

        Assert.Equal((true, "No change."), await h.Service.SetWazuhAgentGroupAsync(tenant.Id, "clinic-a"));
        Assert.Single(await ((IAuditLog)h.Store).QueryAsync(new AuditQuery { Action = AuditActions.WazuhGroupChanged }));
    }

    // --- GoPhish ---------------------------------------------------------------------------------

    [Fact]
    public async Task OnlyOwnersTurnGoPhishOnOrOff_AndEachChangeIsAudited()
    {
        var h = new Harness();
        var tenant = (await h.Store.GetAllAsync())[0];
        var secret = GoPhishSecrets.ApiKeySecretName(tenant.Id);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Service.SetGoPhishEnabledAsync(tenant.Id, true));
        Assert.False((await h.Store.GetAsync(tenant.Id))!.GoPhishEnabled);

        h.User.User = FixedUser.Owner().User;
        var (ok, message) = await h.Service.SetGoPhishEnabledAsync(tenant.Id, true);
        Assert.True(ok);
        Assert.Contains($"Key Vault as '{secret}'", message);
        Assert.True((await h.Store.GetAsync(tenant.Id))!.GoPhishEnabled);

        Assert.Equal((true, "No change."), await h.Service.SetGoPhishEnabledAsync(tenant.Id, true));
        Assert.True((await h.Service.SetGoPhishEnabledAsync(tenant.Id, false)).Ok);
        Assert.False((await h.Store.GetAsync(tenant.Id))!.GoPhishEnabled);
        Assert.Equal((false, "Tenant not found."), await h.Service.SetGoPhishEnabledAsync(Guid.NewGuid(), true));

        var events = await ((IAuditLog)h.Store).QueryAsync(new AuditQuery { Action = AuditActions.GoPhishChanged });
        Assert.Equal(2, events.Count);
        Assert.All(events, e =>
        {
            Assert.Equal("Olivia Owner <olivia@msp.example>", e.ActorName);
            Assert.Equal(tenant.Id, e.TenantId);
            Assert.Equal(secret, e.Details["secretName"]);
        });
        Assert.Contains(events, e => e.Details["enabled"] == "true" && e.Summary.StartsWith("Turned on"));
        Assert.Contains(events, e => e.Details["enabled"] == "false" && e.Summary.StartsWith("Turned off"));
        Assert.Equal("Onboarding", AuditActions.Categories[AuditActions.CategoryOf(AuditActions.GoPhishChanged)]);
        Assert.NotEqual(AuditActions.GoPhishChanged, AuditActions.Label(AuditActions.GoPhishChanged));
    }
}

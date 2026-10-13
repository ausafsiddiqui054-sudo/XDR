using System.Net;
using System.Text;
using SecurePulse.Intune;
using SecurePulse.Web.Services.Onboarding;

namespace SecurePulse.Tests.Onboarding;

public class EntraTenantResolverTests
{
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> Urls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Urls.Add(request.RequestUri!);
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Discovery(string issuer) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($$"""{"issuer":"{{issuer}}","token_endpoint":"x"}""", Encoding.UTF8, "application/json")
    };

    private static (EntraTenantResolver Resolver, Handler Handler) Create(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new Handler(respond);
        return (new EntraTenantResolver(new HttpClient(handler), new OnboardingOptions()), handler);
    }

    [Fact]
    public async Task ReadsTenantIdFromIssuer()
    {
        var tid = Guid.NewGuid();
        var (resolver, handler) = Create(_ => Discovery($"https://login.microsoftonline.com/{tid}/v2.0"));

        Assert.Equal(tid, await resolver.ResolveAsync("contoso.com"));
        Assert.Equal("https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration", handler.Urls.Single().ToString());
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task UnknownDomainIsNull(HttpStatusCode status)
    {
        var (resolver, _) = Create(_ => new HttpResponseMessage(status));

        Assert.Null(await resolver.ResolveAsync("nope.example"));
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com/common/v2.0")]
    [InlineData("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0")]
    [InlineData("not a url")]
    public async Task UnexpectedIssuerIsNull(string issuer)
    {
        var (resolver, _) = Create(_ => Discovery(issuer));

        Assert.Null(await resolver.ResolveAsync("contoso.com"));
    }

    [Fact]
    public async Task ServerErrorThrows()
    {
        var (resolver, _) = Create(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        await Assert.ThrowsAsync<HttpRequestException>(() => resolver.ResolveAsync("contoso.com"));
    }
}

public class AccessTokenClaimsTests
{
    [Fact]
    public void ReadsTenantAndRoles()
    {
        var tid = Guid.NewGuid();

        var claims = AccessTokenClaims.Parse(Jwt.With(tid, "DeviceManagementManagedDevices.Read.All", "Directory.Read.All"));

        Assert.Equal(tid, claims.TenantId);
        Assert.Equal(["DeviceManagementManagedDevices.Read.All", "Directory.Read.All"], claims.Roles);
    }

    [Fact]
    public void NoRolesClaimMeansNoPermissions()
    {
        var tid = Guid.NewGuid();

        Assert.Empty(AccessTokenClaims.Parse(Jwt.With(new Dictionary<string, object> { ["tid"] = tid.ToString() })).Roles);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("a.b")]
    [InlineData("a.!!!.c")]
    public void MalformedTokenThrows(string token) =>
        Assert.Throws<FormatException>(() => AccessTokenClaims.Parse(token));

    [Fact]
    public void MissingTenantThrows() =>
        Assert.Throws<FormatException>(() => AccessTokenClaims.Parse(Jwt.With(new Dictionary<string, object> { ["roles"] = new[] { "x" } })));
}

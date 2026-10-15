using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Tests.Onboarding;

internal sealed class FakeTime(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

internal static class Jwt
{
    /// <summary>An unsigned token with the given claims; enough for claim parsing.</summary>
    public static string With(Guid tenantId, params string[] roles) => With(new Dictionary<string, object> { ["tid"] = tenantId.ToString(), ["roles"] = roles });

    public static string With(Dictionary<string, object> claims) =>
        $"{Encode("""{"alg":"none","typ":"JWT"}""")}.{Encode(JsonSerializer.Serialize(claims))}.sig";

    private static string Encode(string json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json));
}

internal sealed class FixedUser(UserContext user) : IUserContextAccessor
{
    public UserContext User { get; set; } = user;
    public Task<UserContext> GetAsync() => Task.FromResult(User);

    public static FixedUser Owner() => new(new UserContext(Guid.NewGuid(), PortalRole.Owner, null, "Olivia Owner <olivia@msp.example>"));
    public static FixedUser MspAdmin() => new(new UserContext(Guid.NewGuid(), PortalRole.MspAdmin, null, "Adam Admin <adam@msp.example>"));
    public static FixedUser Viewer(Guid tenantId) => new(new UserContext(Guid.NewGuid(), PortalRole.ClientViewer, tenantId, "Vera Viewer <vera@client.example>"));
    public static FixedUser Anonymous() => new(UserContext.Anonymous);
}

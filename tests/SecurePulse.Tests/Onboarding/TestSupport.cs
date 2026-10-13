using System.Buffers.Text;
using System.Text;
using System.Text.Json;

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

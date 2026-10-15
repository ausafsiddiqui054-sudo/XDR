using System.Buffers.Text;
using System.Text.Json;

namespace SecurePulse.Intune;

/// <summary>
/// The claims SecurePulse reads from its own app-only Graph tokens: the tenant the token was
/// issued for and the application permissions (roles) granted there. The signature isn't
/// checked because the token came straight from Entra's token endpoint over TLS to us; never
/// use this for tokens received from someone else.
/// </summary>
public sealed record AccessTokenClaims(Guid TenantId, IReadOnlyList<string> Roles)
{
    public static AccessTokenClaims Parse(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) throw new FormatException("Access token is not a JWT.");

        byte[] payload;
        try
        {
            payload = Base64Url.DecodeFromChars(parts[1]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Access token payload is not valid base64url.", ex);
        }

        using var doc = JsonDocument.Parse(payload);
        var root = doc.RootElement;

        if (!root.TryGetProperty("tid", out var tid) || !Guid.TryParse(tid.GetString(), out var tenantId))
            throw new FormatException("Access token has no tenant (tid) claim.");

        var roles = root.TryGetProperty("roles", out var r) && r.ValueKind == JsonValueKind.Array
            ? r.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : [];

        return new AccessTokenClaims(tenantId, roles);
    }
}

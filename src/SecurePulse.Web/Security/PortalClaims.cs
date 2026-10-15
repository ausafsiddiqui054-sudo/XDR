using System.Security.Claims;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Security;

/// <summary>
/// Claims SecurePulse issues itself, from the portal_users table, on every request. Authorization
/// only trusts claims with <see cref="Issuer"/>: Entra tokens can carry a client tenant's own app
/// roles, and those must never grant access here.
/// </summary>
public static class PortalClaims
{
    public const string Issuer = "SecurePulse";
    public const string AuthenticationType = "SecurePulse";
    public const string Role = "securepulse:role";
    public const string UserId = "securepulse:user";
    public const string ClientTenant = "securepulse:client-tenant";

    private static readonly string[] TenantIdTypes = ["http://schemas.microsoft.com/identity/claims/tenantid", "tid"];
    private static readonly string[] ObjectIdTypes = ["http://schemas.microsoft.com/identity/claims/objectidentifier", "oid"];
    private static readonly string[] SignInNameTypes = ["preferred_username", ClaimTypes.Upn, "upn", ClaimTypes.Email, "email"];

    /// <summary>Inbound role claims stripped at sign-in (Entra app roles from the user's home tenant).</summary>
    public static bool IsInboundRoleClaim(Claim c) =>
        c.Type is "roles" or "role" or ClaimTypes.Role || c.Type.StartsWith("securepulse:", StringComparison.Ordinal);

    public static (Guid TenantId, Guid ObjectId)? EntraIdentity(this ClaimsPrincipal user)
    {
        var tid = First(user, TenantIdTypes);
        var oid = First(user, ObjectIdTypes);
        return Guid.TryParse(tid, out var t) && Guid.TryParse(oid, out var o) ? (t, o) : null;
    }

    public static string? SignInName(this ClaimsPrincipal user) => First(user, SignInNameTypes);

    public static string? DisplayName(this ClaimsPrincipal user) => user.FindFirst("name")?.Value ?? user.Identity?.Name;

    /// <summary>Role granted by SecurePulse, ignoring any role claim from elsewhere.</summary>
    public static PortalRole? PortalRole(this ClaimsPrincipal user) =>
        Enum.TryParse<PortalRole>(Own(user, Role), out var role) ? role : null;

    public static Guid? ClientTenantId(this ClaimsPrincipal user) =>
        Guid.TryParse(Own(user, ClientTenant), out var id) ? id : null;

    public static Guid? PortalUserId(this ClaimsPrincipal user) =>
        Guid.TryParse(Own(user, UserId), out var id) ? id : null;

    public static bool HasPortalRole(this ClaimsPrincipal user, params PortalRole[] roles) =>
        user.PortalRole() is { } role && roles.Contains(role);

    public static ClaimsIdentity CreateIdentity(PortalUser user)
    {
        var identity = new ClaimsIdentity(AuthenticationType);
        identity.AddClaim(new Claim(UserId, user.Id.ToString(), ClaimValueTypes.String, Issuer));
        identity.AddClaim(new Claim(Role, user.Role.ToString(), ClaimValueTypes.String, Issuer));
        if (user.Role == Core.Models.PortalRole.ClientViewer && user.ClientTenantId is { } tenantId)
            identity.AddClaim(new Claim(ClientTenant, tenantId.ToString(), ClaimValueTypes.String, Issuer));
        return identity;
    }

    private static string? Own(ClaimsPrincipal user, string type) =>
        user.Claims.FirstOrDefault(c => c.Type == type && c.Issuer == Issuer)?.Value;

    private static string? First(ClaimsPrincipal user, string[] types) =>
        types.Select(t => user.FindFirst(t)?.Value).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}

public static class Policies
{
    /// <summary>Signed in, with or without a portal role (e.g. the access-pending page).</summary>
    public const string SignedIn = "SignedIn";

    /// <summary>Any portal role. The default for every page and endpoint.</summary>
    public const string Member = "Member";

    /// <summary>Owner or MSP admin: all tenants, onboarding, user management.</summary>
    public const string Operator = "Operator";

    public const string Owner = "Owner";
}

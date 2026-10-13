using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using SecurePulse.Core.Abstractions;

namespace SecurePulse.Web.Security;

/// <summary>
/// Adds SecurePulse's own role and tenant-scope claims to every authenticated request, looked up
/// by the immutable Entra (tenant, object ID) pair. Nothing from the token decides access.
/// </summary>
public sealed class PortalClaimsTransformation(IPortalUserRepository users, IMemoryCache cache) : IClaimsTransformation
{
    /// <summary>Short, so role changes and removals reach new requests quickly.</summary>
    private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(30);

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true
            || principal.Identities.Any(i => i.AuthenticationType == PortalClaims.AuthenticationType)
            || principal.EntraIdentity() is not { } id)
        {
            return principal;
        }

        var user = await cache.GetOrCreateAsync($"portal-user:{id.TenantId}:{id.ObjectId}", entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheFor;
            return users.FindByObjectIdAsync(id.TenantId, id.ObjectId);
        });

        var result = new ClaimsPrincipal(principal.Identities.Select(StripSecurePulseClaims));
        if (user is not null) result.AddIdentity(PortalClaims.CreateIdentity(user));
        return result;
    }

    private static ClaimsIdentity StripSecurePulseClaims(ClaimsIdentity identity)
    {
        var copy = identity.Clone();
        foreach (var claim in copy.Claims.Where(PortalClaims.IsInboundRoleClaim).ToList())
            copy.RemoveClaim(claim);
        return copy;
    }
}

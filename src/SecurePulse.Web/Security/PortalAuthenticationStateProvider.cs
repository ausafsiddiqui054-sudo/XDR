using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using System.Security.Claims;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Security;

/// <summary>
/// Blazor Server keeps a user's claims for the life of their circuit. This re-checks the
/// database every minute so a removed user or changed role takes effect in open sessions too.
/// </summary>
public sealed class PortalAuthenticationStateProvider(ILoggerFactory loggerFactory, IServiceScopeFactory scopes)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(1);

    protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState state, CancellationToken ct)
    {
        var principal = state.User;
        if (principal.EntraIdentity() is not { } id) return false;

        await using var scope = scopes.CreateAsyncScope();
        var user = await scope.ServiceProvider.GetRequiredService<IPortalUserRepository>().FindByObjectIdAsync(id.TenantId, id.ObjectId, ct);
        return IsStillValid(user, principal);
    }

    /// <summary>
    /// Valid only if access is unchanged. Otherwise the circuit drops to signed-out and the next
    /// navigation goes through sign-in again, picking up fresh claims.
    /// </summary>
    internal static bool IsStillValid(PortalUser? user, ClaimsPrincipal principal) =>
        user is not null
        && user.Id == principal.PortalUserId()
        && user.Role == principal.PortalRole()
        && user.ClientTenantId == principal.ClientTenantId();
}

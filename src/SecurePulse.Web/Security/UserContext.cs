using Microsoft.AspNetCore.Components.Authorization;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Security;

/// <summary>Who is using the portal right now, and which tenants they may see.</summary>
public sealed record UserContext(Guid? UserId, PortalRole? Role, Guid? ClientTenantId, string Name)
{
    public static readonly UserContext Anonymous = new(null, null, null, "Anonymous");

    public bool IsOperator => Role is PortalRole.Owner or PortalRole.MspAdmin;
    public bool IsOwner => Role == PortalRole.Owner;

    /// <summary>Operators see every tenant; a client viewer sees only their own.</summary>
    public bool CanSee(Guid tenantId) => IsOperator || (Role == PortalRole.ClientViewer && ClientTenantId == tenantId);
}

public interface IUserContextAccessor
{
    Task<UserContext> GetAsync();
}

/// <summary>Reads the current user from Blazor's authentication state (works in circuits and prerendering).</summary>
public sealed class AuthStateUserContextAccessor(AuthenticationStateProvider auth) : IUserContextAccessor
{
    public async Task<UserContext> GetAsync()
    {
        var user = (await auth.GetAuthenticationStateAsync()).User;
        if (user.Identity?.IsAuthenticated != true) return UserContext.Anonymous;
        var name = user.DisplayName() ?? user.SignInName() ?? "Signed-in user";
        var upn = user.SignInName();
        return new UserContext(user.PortalUserId(), user.PortalRole(), user.ClientTenantId(), upn is null || upn == name ? name : $"{name} <{upn}>");
    }
}

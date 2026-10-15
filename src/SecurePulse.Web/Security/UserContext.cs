using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Security;

/// <summary>Who is using the portal right now, and which tenants they may see.</summary>
public sealed record UserContext(Guid? UserId, PortalRole? Role, Guid? ClientTenantId, string Name)
{
    public static readonly UserContext Anonymous = new(null, null, null, "Anonymous");

    /// <summary>Reads SecurePulse's own claims (see <see cref="PortalClaims"/>) from a principal.</summary>
    public static UserContext From(ClaimsPrincipal user) =>
        user.Identity?.IsAuthenticated != true
            ? Anonymous
            : new UserContext(user.PortalUserId(), user.PortalRole(), user.ClientTenantId(), NameFor(user.DisplayName(), user.SignInName()));

    /// <summary>"Name &lt;sign-in name&gt;", as shown in the audit log.</summary>
    public static string NameFor(string? displayName, string? signInName)
    {
        var name = displayName ?? signInName ?? "Signed-in user";
        return signInName is null || signInName == name ? name : $"{name} <{signInName}>";
    }

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
    public async Task<UserContext> GetAsync() => UserContext.From((await auth.GetAuthenticationStateAsync()).User);
}

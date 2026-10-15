using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

public sealed class InviteForm
{
    public string? SignInName { get; set; }
    public PortalRole Role { get; set; } = PortalRole.ClientViewer;
    public Guid? ClientTenantId { get; set; }
}

public sealed record PortalUserResult(PortalUser? User, string? Error);

/// <summary>
/// Inviting and managing portal users. Owners manage everyone; MSP admins manage client viewers.
/// A role can't move someone between organizations: Owners and MSP admins sign in from the
/// operator tenant, a client viewer from their client's tenant.
/// </summary>
public sealed class PortalUserService(
    IPortalUserRepository users,
    ITenantRepository tenants,
    AuthOptions auth,
    IUserContextAccessor current,
    TimeProvider time,
    AuditTrail audit)
{
    public Guid OperatorTenantId => auth.OperatorTenantId;

    public static bool CanManage(UserContext actor, PortalRole target) =>
        actor.IsOwner || (actor.Role == PortalRole.MspAdmin && target == PortalRole.ClientViewer);

    public async Task<IReadOnlyList<PortalUser>> GetAllAsync(CancellationToken ct = default)
    {
        var actor = await current.GetAsync();
        return actor.IsOperator ? await users.GetAllAsync(ct) : [];
    }

    public async Task<PortalUserResult> InviteAsync(InviteForm form, CancellationToken ct = default)
    {
        var actor = await current.GetAsync();
        if (!CanManage(actor, form.Role))
        {
            await audit.RecordAsync(AuditActions.Invited, AuditOutcome.Denied,
                $"{actor.Name} tried to invite {form.SignInName?.Trim()} as {AuthSetup.RoleLabel(form.Role)} without permission", actor: actor);
            return new(null, actor.IsOperator ? "Only Owners can invite Owners and MSP admins." : "You can't invite people.");
        }

        var upn = form.SignInName?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(upn) || upn.Length > 320 || upn.Any(char.IsWhiteSpace) || upn.Count(c => c == '@') != 1 || upn[0] == '@' || upn[^1] == '@')
            return new(null, "Enter the person's sign-in name, like name@contoso.com.");

        Guid entraTenantId;
        Guid? clientTenantId = null;
        var scope = "all tenants";
        if (form.Role == PortalRole.ClientViewer)
        {
            if (form.ClientTenantId is not { } id || await tenants.GetAsync(id, ct) is not { } tenant)
                return new(null, "Choose which client tenant they can see.");
            scope = tenant.DisplayName;
            if (tenant.ConsentState is not (TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted))
                return new(null, $"{tenant.DisplayName} isn't connected yet.");
            entraTenantId = tenant.EntraTenantId;
            clientTenantId = tenant.Id;
        }
        else
        {
            if (auth.OperatorTenantId == Guid.Empty)
                return new(null, "Set Auth:OperatorTenantId (your own Entra tenant ID) before inviting Owners or MSP admins.");
            entraTenantId = auth.OperatorTenantId;
        }

        var user = new PortalUser
        {
            Id = Guid.NewGuid(),
            Role = form.Role,
            EntraTenantId = entraTenantId,
            UserPrincipalName = upn,
            ClientTenantId = clientTenantId,
            CreatedAt = time.GetUtcNow(),
            CreatedBy = actor.Name
        };
        try
        {
            await users.AddAsync(user, ct);
            await audit.RecordAsync(AuditActions.Invited, AuditOutcome.Success,
                $"Invited {upn} as {AuthSetup.RoleLabel(form.Role)} ({scope})", clientTenantId, "PortalUser", user.Id.ToString(),
                new Dictionary<string, string> { ["signInName"] = upn, ["role"] = form.Role.ToString(), ["entraTenantId"] = entraTenantId.ToString() },
                actor);
            return new(user, null);
        }
        catch (DuplicatePortalUserException ex)
        {
            return new(null, ex.Message);
        }
    }

    /// <summary>Switches between Owner and MSP admin. Owners only.</summary>
    public async Task<string?> ChangeRoleAsync(Guid userId, PortalRole role, CancellationToken ct = default)
    {
        var actor = await current.GetAsync();
        if (await users.GetAsync(userId, ct) is not { } user) return "That person no longer has access.";
        var change = $"{user.UserPrincipalName} from {AuthSetup.RoleLabel(user.Role)} to {AuthSetup.RoleLabel(role)}";
        var details = new Dictionary<string, string> { ["from"] = user.Role.ToString(), ["to"] = role.ToString() };
        if (!actor.IsOwner)
        {
            await audit.RecordAsync(AuditActions.RoleChanged, AuditOutcome.Denied, $"{actor.Name} tried to change {change} without permission",
                user.ClientTenantId, "PortalUser", user.Id.ToString(), details, actor);
            return "Only Owners can change roles.";
        }
        if (user.Role == PortalRole.ClientViewer || role == PortalRole.ClientViewer)
            return "Client viewers sign in from their own organization; remove and invite them again instead.";

        var error = await GuardLastOwnerAsync(() => users.UpdateRoleAsync(userId, role, null, ct));
        await audit.RecordAsync(AuditActions.RoleChanged, error is null ? AuditOutcome.Success : AuditOutcome.Failure,
            error is null ? $"Changed {change}" : $"Refused to change {change}: {error}", user.ClientTenantId, "PortalUser", user.Id.ToString(), details, actor);
        return error;
    }

    public async Task<string?> RemoveAsync(Guid userId, CancellationToken ct = default)
    {
        var actor = await current.GetAsync();
        if (await users.GetAsync(userId, ct) is not { } user) return null;
        var who = $"{user.UserPrincipalName} ({AuthSetup.RoleLabel(user.Role)})";
        var details = new Dictionary<string, string> { ["signInName"] = user.UserPrincipalName, ["role"] = user.Role.ToString() };
        if (!CanManage(actor, user.Role))
        {
            await audit.RecordAsync(AuditActions.Removed, AuditOutcome.Denied, $"{actor.Name} tried to remove {who} without permission",
                user.ClientTenantId, "PortalUser", user.Id.ToString(), details, actor);
            return "You can't remove this person.";
        }

        var error = await GuardLastOwnerAsync(() => users.RemoveAsync(userId, ct));
        await audit.RecordAsync(AuditActions.Removed, error is null ? AuditOutcome.Success : AuditOutcome.Failure,
            error is null ? $"Removed access for {who}" : $"Refused to remove {who}: {error}", user.ClientTenantId, "PortalUser", user.Id.ToString(), details, actor);
        return error;
    }

    private static async Task<string?> GuardLastOwnerAsync(Func<Task> change)
    {
        try
        {
            await change();
            return null;
        }
        catch (LastOwnerException ex)
        {
            return ex.Message;
        }
    }
}

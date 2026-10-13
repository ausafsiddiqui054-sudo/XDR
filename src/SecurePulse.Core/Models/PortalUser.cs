namespace SecurePulse.Core.Models;

public enum PortalRole
{
    /// <summary>Everything, including managing users.</summary>
    Owner,

    /// <summary>All tenants, onboarding, and managing client viewers.</summary>
    MspAdmin,

    /// <summary>Read-only access to one client tenant.</summary>
    ClientViewer
}

/// <summary>
/// Someone allowed into the portal. Access is decided here, not by Entra app roles: the sign-in
/// app is multi-tenant, so a role claim minted in a client's tenant can't be trusted.
/// </summary>
public sealed record PortalUser
{
    public required Guid Id { get; init; }
    public required PortalRole Role { get; init; }

    /// <summary>The Entra tenant this user must sign in from.</summary>
    public required Guid EntraTenantId { get; init; }

    /// <summary>
    /// Sign-in name the invitation was issued for (lowercase). Only used to match the first
    /// sign-in from <see cref="EntraTenantId"/>; after that the object ID is authoritative.
    /// </summary>
    public required string UserPrincipalName { get; init; }

    /// <summary>Immutable Entra object ID, bound at first sign-in. Null while the invitation is pending.</summary>
    public Guid? ObjectId { get; init; }

    public string? DisplayName { get; init; }

    /// <summary>For <see cref="PortalRole.ClientViewer"/>: the SecurePulse tenant they can see.</summary>
    public Guid? ClientTenantId { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
    public string? CreatedBy { get; init; }
    public DateTimeOffset? LastSignInAt { get; init; }

    public bool IsInvitationPending => ObjectId is null;
}

/// <summary>Thrown when a change would leave the portal without an Owner who can sign in.</summary>
public sealed class LastOwnerException() : InvalidOperationException("At least one Owner who has signed in must remain.");

/// <summary>Thrown when an invitation for the same sign-in name and tenant already exists.</summary>
public sealed class DuplicatePortalUserException() : InvalidOperationException("That person already has access or an invitation.");

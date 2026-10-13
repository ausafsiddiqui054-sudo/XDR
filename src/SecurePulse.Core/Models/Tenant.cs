namespace SecurePulse.Core.Models;

/// <summary>A client Microsoft 365 / Entra tenant connected to the platform.</summary>
public sealed record Tenant
{
    public required Guid Id { get; init; }

    /// <summary>The client's Entra tenant ID (directory ID).</summary>
    public required Guid EntraTenantId { get; init; }

    public required string DisplayName { get; init; }
    public required string PrimaryDomain { get; init; }

    /// <summary>Owning MSP / partner, if the tenant is managed through one.</summary>
    public string? PartnerName { get; init; }

    public string Industry { get; init; } = "General";

    /// <summary>
    /// Reference to the credential in the secret store (e.g. a Key Vault certificate name).
    /// Never store secrets or private keys on this object.
    /// </summary>
    public string? CredentialReference { get; init; }

    public TenantConsentState ConsentState { get; init; } = TenantConsentState.Pending;

    public DateTimeOffset? LastScanAt { get; init; }
}

public enum TenantConsentState
{
    Pending,
    ReadOnlyGranted,
    RemediationGranted,
    Revoked
}

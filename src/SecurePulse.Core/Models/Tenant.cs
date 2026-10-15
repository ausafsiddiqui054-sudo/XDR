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

    /// <summary>
    /// Thumbprint of the remediation app's certificate, set when the tenant grants remediation
    /// (write) consent to that separate app. A reference only, like <see cref="CredentialReference"/>.
    /// </summary>
    public string? RemediationCredentialReference { get; init; }

    public bool CanRemediate => ConsentState == TenantConsentState.RemediationGranted && !string.IsNullOrWhiteSpace(RemediationCredentialReference);

    /// <summary>
    /// Thumbprint of the configuration app's certificate, set when the tenant consents to that separate app
    /// (report-only Conditional Access fixes). Independent of remediation access. A reference only.
    /// </summary>
    public string? ConfigurationCredentialReference { get; init; }

    public bool CanConfigure => ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted
                                && !string.IsNullOrWhiteSpace(ConfigurationCredentialReference);

    /// <summary>
    /// The Wazuh agent group holding this tenant's agents on the shared Wazuh manager. The Wazuh
    /// engine reads only agents in this group; null means the tenant isn't scanned by Wazuh.
    /// Unique across tenants, so two tenants can never read the same agents.
    /// </summary>
    public string? WazuhAgentGroup { get; init; }

    /// <summary>
    /// Whether the GoPhish engine imports this tenant's phishing simulation results. The tenant's campaigns
    /// are run by its own GoPhish user, whose API key is in Key Vault under <see cref="GoPhishSecrets.ApiKeySecretName"/>.
    /// </summary>
    public bool GoPhishEnabled { get; init; }

    public DateTimeOffset? LastScanAt { get; init; }
}

/// <summary>Rules for <see cref="Tenant.WazuhAgentGroup"/>.</summary>
public static class WazuhAgentGroups
{
    public const int MaxLength = 128;

    /// <summary>Wazuh puts every agent without a group in "default", so it never belongs to one tenant.</summary>
    public const string Default = "default";

    /// <summary>Why <paramref name="group"/> can't be a tenant's agent group, or null.</summary>
    public static string? Problem(string? group)
    {
        if (string.IsNullOrWhiteSpace(group)) return "Enter the Wazuh agent group name.";
        if (group.Length > MaxLength) return $"Wazuh group names are at most {MaxLength} characters.";
        if (group is "." or ".." || !group.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'))
            return "Wazuh group names use only letters, digits, '.', '_' and '-'.";
        if (string.Equals(group, Default, StringComparison.OrdinalIgnoreCase))
            return "The \"default\" group holds every unassigned agent, so it can't belong to one tenant. Put the tenant's agents in their own group.";
        return null;
    }
}

/// <summary>Where a tenant's GoPhish API key lives. Derived from the tenant ID, so no tenant can be pointed at another's key.</summary>
public static class GoPhishSecrets
{
    public const string Prefix = "gophish-api-key-";

    /// <summary>The Key Vault secret holding the API key of the tenant's own GoPhish user, e.g. gophish-api-key-3f2a….</summary>
    public static string ApiKeySecretName(Guid tenantId) => $"{Prefix}{tenantId:N}";
}

public enum TenantConsentState
{
    Pending,
    ReadOnlyGranted,
    RemediationGranted,
    Revoked
}

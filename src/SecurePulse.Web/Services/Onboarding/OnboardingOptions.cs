namespace SecurePulse.Web.Services.Onboarding;

public sealed class OnboardingOptions
{
    /// <summary>Client ID of SecurePulse's multi-tenant Entra app registration (not a secret).</summary>
    public string AppClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client ID of the separate remediation app, which holds only the Intune permission remote
    /// device actions need. Empty: remediation can't be turned on.
    /// </summary>
    public string RemediationAppClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client ID of the separate configuration app, which holds only the Conditional Access permissions
    /// report-only fixes need. Empty: configuration fixes can't be turned on.
    /// </summary>
    public string ConfigurationAppClientId { get; set; } = string.Empty;

    /// <summary>Entra authority. Use https://login.microsoftonline.us for US Government clouds.</summary>
    public string AuthorityHost { get; set; } = "https://login.microsoftonline.com";

    /// <summary>Graph resource the consent covers (the app's configured application permissions).</summary>
    public string GraphBaseUrl { get; set; } = "https://graph.microsoft.com";

    /// <summary>
    /// Absolute URL Entra returns to after consent. Must be registered on the app as a Web
    /// redirect URI. Empty means {portal base URL}/onboarding/consent-callback.
    /// </summary>
    public string? RedirectUri { get; set; }

    /// <summary>How long a consent link stays usable.</summary>
    public TimeSpan LinkLifetime { get; set; } = TimeSpan.FromDays(7);
}

/// <summary>Whether the portal runs on PostgreSQL (with a Worker) or in-memory sample data.</summary>
public sealed record PortalMode(bool UsesDatabase);

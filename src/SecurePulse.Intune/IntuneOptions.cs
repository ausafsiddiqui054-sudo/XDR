namespace SecurePulse.Intune;

public sealed class IntuneOptions
{
    /// <summary>Client ID of SecurePulse's multi-tenant Entra app registration.</summary>
    public string AppClientId { get; set; } = string.Empty;

    /// <summary>Graph endpoint. Use https://graph.microsoft.us for GCC High, https://dod-graph.microsoft.us for DoD.</summary>
    public string GraphBaseUrl { get; set; } = "https://graph.microsoft.com";

    /// <summary>Entra authority. Use https://login.microsoftonline.us for US Government clouds.</summary>
    public string AuthorityHost { get; set; } = "https://login.microsoftonline.com";

    /// <summary>Also read per-setting compliance results for devices that aren't compliant (one extra call per device).</summary>
    public bool FetchComplianceSettings { get; set; } = true;

    /// <summary>
    /// Also read Defender health: Defender Antivirus state per Windows device (one extra call each)
    /// and Defender for Endpoint sensor state (one advanced hunting query per tenant).
    /// </summary>
    public bool FetchDefenderHealth { get; set; } = true;

    /// <summary>Parallel Graph calls per tenant when reading compliance settings and antivirus state.</summary>
    public int MaxConcurrentRequests { get; set; } = 4;

    /// <summary>Retries for throttled (429) or unavailable (503/504) responses.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Longest wait honoured from a Retry-After header.</summary>
    public TimeSpan MaxRetryDelay { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Upper bound for one tenant's sync.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(10);
}

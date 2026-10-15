using System.Text.RegularExpressions;

namespace SecurePulse.Worker.Siem;

/// <summary>
/// The <c>AuditExport:Sentinel</c> section: where audit events go (an Azure Monitor data collection
/// rule feeding a Log Analytics workspace with Microsoft Sentinel) and how the Worker signs in.
/// </summary>
public sealed partial class SentinelOptions
{
    public bool Enabled { get; set; }

    /// <summary>The DCR's logs ingestion endpoint (or a DCE), e.g. https://dcr-x.uaenorth-1.ingest.monitor.azure.com.</summary>
    public string Endpoint { get; set; } = "";

    /// <summary>The DCR's immutable ID: dcr- followed by 32 hex characters.</summary>
    public string DcrImmutableId { get; set; } = "";

    /// <summary>The DCR input stream that takes SecurePulse's records.</summary>
    public string StreamName { get; set; } = "Custom-SecurePulseAudit";

    /// <summary>Token audience: https://monitor.azure.com (public), https://monitor.azure.us (US Gov), https://monitor.azure.cn.</summary>
    public string Audience { get; set; } = "https://monitor.azure.com";

    /// <summary>Your own Entra tenant (where the workspace is), for certificate sign-in.</summary>
    public string? TenantId { get; set; }

    /// <summary>App registration (certificate sign-in) or user-assigned managed identity client ID.</summary>
    public string? ClientId { get; set; }

    /// <summary>Certificate in CurrentUser\My or LocalMachine\My. Leave empty to use a managed identity instead.</summary>
    public string? CertificateThumbprint { get; set; }

    /// <summary>Sign in with the host's managed identity (Azure) instead of a certificate.</summary>
    public bool UseManagedIdentity { get; set; }

    /// <summary>Entra authority, for national clouds.</summary>
    public string AuthorityHost { get; set; } = "https://login.microsoftonline.com";

    public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Events stored more recently than this wait for the next run, so a slow insert can't land behind the checkpoint.</summary>
    public TimeSpan ExportLag { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Events read per API call; a call is also kept under the API's 1 MB limit.</summary>
    public int MaxEventsPerCall { get; set; } = 500;

    /// <summary>Calls per run, so a large backlog is sent in steady steps.</summary>
    public int MaxCallsPerRun { get; set; } = 50;

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(60);

    public int MaxRetries { get; set; } = 3;

    /// <summary>Only Azure Monitor ingestion hosts get the token and the audit data.</summary>
    public static readonly string[] AllowedHostSuffixes = [".ingest.monitor.azure.com", ".ingest.monitor.azure.us", ".ingest.monitor.azure.cn"];

    /// <summary>Every configuration problem, or none.</summary>
    public IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        if (!Enabled) return problems;

        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme != Uri.UriSchemeHttps
            || !AllowedHostSuffixes.Any(s => endpoint.Host.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            || endpoint.PathAndQuery != "/" || !string.IsNullOrEmpty(endpoint.UserInfo))
            problems.Add($"AuditExport:Sentinel:Endpoint must be an https Azure Monitor ingestion endpoint (a host ending in {string.Join(", ", AllowedHostSuffixes)}), with no path.");
        if (!DcrId().IsMatch(DcrImmutableId))
            problems.Add("AuditExport:Sentinel:DcrImmutableId must be the DCR's immutable ID (dcr- followed by 32 hex characters).");
        if (!Stream().IsMatch(StreamName))
            problems.Add("AuditExport:Sentinel:StreamName must be a DCR stream name such as Custom-SecurePulseAudit.");
        if (!Uri.TryCreate(Audience, UriKind.Absolute, out var audience) || audience.Scheme != Uri.UriSchemeHttps)
            problems.Add("AuditExport:Sentinel:Audience must be an https URL such as https://monitor.azure.com.");

        if (UseManagedIdentity)
        {
            if (!string.IsNullOrWhiteSpace(CertificateThumbprint))
                problems.Add("Use either a certificate or a managed identity for AuditExport:Sentinel, not both.");
            if (!string.IsNullOrWhiteSpace(ClientId) && !Guid.TryParse(ClientId, out _))
                problems.Add("AuditExport:Sentinel:ClientId must be a GUID (the user-assigned identity's client ID), or empty for the system-assigned one.");
        }
        else
        {
            if (!Guid.TryParse(TenantId, out var tenant) || tenant == Guid.Empty)
                problems.Add("AuditExport:Sentinel:TenantId must be your Entra tenant ID (a GUID).");
            if (!Guid.TryParse(ClientId, out var client) || client == Guid.Empty)
                problems.Add("AuditExport:Sentinel:ClientId must be the app registration's client ID (a GUID).");
            if (CertificateThumbprint is not { Length: 40 } t || !t.All(Uri.IsHexDigit))
                problems.Add("AuditExport:Sentinel:CertificateThumbprint must be a certificate thumbprint (40 hex characters), or set UseManagedIdentity.");
        }

        if (Interval < TimeSpan.FromSeconds(10)) problems.Add("AuditExport:Sentinel:Interval must be at least 10 seconds.");
        if (ExportLag < TimeSpan.FromSeconds(30)) problems.Add("AuditExport:Sentinel:ExportLag must be at least 30 seconds.");
        if (MaxEventsPerCall is < 1 or > 5000) problems.Add("AuditExport:Sentinel:MaxEventsPerCall must be between 1 and 5000.");
        if (MaxCallsPerRun < 1) problems.Add("AuditExport:Sentinel:MaxCallsPerRun must be at least 1.");
        if (Timeout < TimeSpan.FromSeconds(5)) problems.Add("AuditExport:Sentinel:Timeout must be at least 5 seconds.");
        return problems;
    }

    /// <summary>{endpoint}/dataCollectionRules/{dcr}/streams/{stream}?api-version=2023-01-01</summary>
    public Uri IngestionUri() =>
        new($"{Endpoint.TrimEnd('/')}/dataCollectionRules/{Uri.EscapeDataString(DcrImmutableId)}/streams/{Uri.EscapeDataString(StreamName)}?api-version=2023-01-01");

    [GeneratedRegex("^dcr-[0-9a-f]{32}$")]
    private static partial Regex DcrId();

    [GeneratedRegex("^(Custom|Microsoft)-[A-Za-z][A-Za-z0-9_]{0,99}$")]
    private static partial Regex Stream();
}

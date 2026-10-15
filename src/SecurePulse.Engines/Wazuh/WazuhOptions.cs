using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.Wazuh;

/// <summary>The <c>Wazuh</c> section: the shared Wazuh manager's server API and its read-only user.</summary>
public sealed class WazuhOptions
{
    /// <summary>The Wazuh server API, e.g. https://wazuh.msp.example:55000.</summary>
    public string Url { get; set; } = "";

    /// <summary>A Wazuh API user whose role allows only read actions (see the README). Its password comes from Key Vault.</summary>
    public string Username { get; set; } = "";

    /// <summary>
    /// SHA-256 of the API's TLS certificate (hex, colons allowed). When set, only that certificate is
    /// accepted, which is how Wazuh's default self-signed certificate is trusted. Empty: normal validation.
    /// </summary>
    public string? CertificateSha256 { get; set; }

    /// <summary>Upper bound for one tenant's scan.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(20);

    public int MaxConcurrentRequests { get; set; } = 4;
    public int MaxRetries { get; set; } = 3;
    public int PageSize { get; set; } = 500;

    /// <summary>
    /// SCA checks carry no severity, so every Wazuh finding gets this one. It sets how much the
    /// tenant's endpoint hardening weighs in its score (RiskScoreCalculator weights by severity).
    /// </summary>
    public Severity FindingSeverity { get; set; } = Severity.Low;

    public IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        if (!Uri.TryCreate(Url, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(url.UserInfo)
            || url.PathAndQuery != "/")
            problems.Add("Wazuh:Url must be the https address of the Wazuh server API (e.g. https://wazuh.example:55000), with no path.");
        if (string.IsNullOrWhiteSpace(Username) || Username.Length > 64 || Username.Any(char.IsWhiteSpace))
            problems.Add("Wazuh:Username must be the read-only Wazuh API user.");
        if (!string.IsNullOrWhiteSpace(CertificateSha256) && NormalizePin(CertificateSha256) is null)
            problems.Add("Wazuh:CertificateSha256 must be a SHA-256 fingerprint (64 hex characters, colons allowed).");
        if (Timeout < TimeSpan.FromMinutes(1)) problems.Add("Wazuh:Timeout must be at least one minute.");
        if (MaxConcurrentRequests is < 1 or > 16) problems.Add("Wazuh:MaxConcurrentRequests must be between 1 and 16.");
        if (PageSize is < 10 or > 10_000) problems.Add("Wazuh:PageSize must be between 10 and 10000.");
        if (!Enum.IsDefined(FindingSeverity)) problems.Add("Wazuh:FindingSeverity must be Info, Low, Medium, High or Critical.");
        return problems;
    }

    /// <summary>64 lowercase hex characters, or null if <paramref name="pin"/> isn't a SHA-256 fingerprint.</summary>
    public static string? NormalizePin(string? pin)
    {
        var hex = pin?.Replace(":", "").Replace(" ", "").Trim().ToLowerInvariant();
        return hex is { Length: 64 } && hex.All(Uri.IsHexDigit) ? hex : null;
    }

    /// <summary>
    /// The handler every Wazuh call goes through: no redirects (the token stays on the configured host),
    /// and the server certificate either pinned or validated normally.
    /// </summary>
    public HttpMessageHandler CreateHandler()
    {
        var pin = NormalizePin(CertificateSha256);
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) => pin is null
                    ? errors == System.Net.Security.SslPolicyErrors.None
                    : certificate is not null && MatchesPin(certificate, pin)
            }
        };
    }

    public static bool MatchesPin(X509Certificate certificate, string normalizedPin) =>
        Convert.ToHexStringLower(SHA256.HashData(certificate.GetRawCertData())) == normalizedPin;
}

/// <summary>The Wazuh API user's password, from a secret store (Azure Key Vault in the Worker). Never config.</summary>
public interface IWazuhPasswordProvider
{
    Task<string> GetPasswordAsync(CancellationToken ct);
}

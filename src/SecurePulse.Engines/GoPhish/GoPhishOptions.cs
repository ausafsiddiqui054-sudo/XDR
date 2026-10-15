using SecurePulse.Core.Models;
using SecurePulse.Engines.Http;

namespace SecurePulse.Engines.GoPhish;

/// <summary>
/// The <c>GoPhish</c> section: the MSP's GoPhish admin server. Each tenant's campaigns are run by that
/// tenant's own GoPhish user; its API key is read from Key Vault per scan (<see cref="IGoPhishApiKeyProvider"/>).
/// </summary>
public sealed class GoPhishOptions
{
    /// <summary>The GoPhish admin server, e.g. https://gophish.msp.example:3333. The API is under /api/.</summary>
    public string Url { get; set; } = "";

    /// <summary>SHA-256 of the admin server's TLS certificate (GoPhish creates a self-signed one). Empty: normal validation.</summary>
    public string? CertificateSha256 { get; set; }

    /// <summary>Upper bound for one tenant's import.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);

    public int MaxRetries { get; set; } = 3;

    /// <summary>Campaigns launched longer ago than this are left out, so old results stop counting.</summary>
    public TimeSpan Lookback { get; set; } = TimeSpan.FromDays(365);

    /// <summary>
    /// Severity of a campaign finding. A campaign fails when anyone entered data on its landing page, so this
    /// sets how much that weighs in the tenant's score (RiskScoreCalculator weights by severity).
    /// </summary>
    public Severity FindingSeverity { get; set; } = Severity.Medium;

    public IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        if (!Uri.TryCreate(Url, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(url.UserInfo)
            || url.PathAndQuery != "/")
            problems.Add("GoPhish:Url must be the https address of the GoPhish admin server (e.g. https://gophish.example:3333), with no path.");
        if (!string.IsNullOrWhiteSpace(CertificateSha256) && PinnedHttp.NormalizePin(CertificateSha256) is null)
            problems.Add("GoPhish:CertificateSha256 must be a SHA-256 fingerprint (64 hex characters, colons allowed).");
        if (Timeout < TimeSpan.FromMinutes(1)) problems.Add("GoPhish:Timeout must be at least one minute.");
        if (MaxRetries is < 0 or > 10) problems.Add("GoPhish:MaxRetries must be between 0 and 10.");
        if (Lookback < TimeSpan.FromDays(7) || Lookback > TimeSpan.FromDays(3 * 366))
            problems.Add("GoPhish:Lookback must be between 7 days and 3 years.");
        if (!Enum.IsDefined(FindingSeverity)) problems.Add("GoPhish:FindingSeverity must be Info, Low, Medium, High or Critical.");
        return problems;
    }

    /// <summary>Every GoPhish call goes through this: GET and HEAD only, no redirects, certificate pinned or validated.</summary>
    public HttpMessageHandler CreateHandler() => new ReadOnlyHttpHandler(PinnedHttp.CreateHandler(CertificateSha256));
}

/// <summary>The API key of a tenant's GoPhish user, from a secret store (Azure Key Vault in the Worker). Never config.</summary>
public interface IGoPhishApiKeyProvider
{
    /// <summary>The key in the secret named <see cref="GoPhishSecrets.ApiKeySecretName"/> for <paramref name="tenantId"/>.</summary>
    Task<string> GetApiKeyAsync(Guid tenantId, CancellationToken ct);
}

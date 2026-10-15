using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecurePulse.Engines.Http;

/// <summary>
/// HTTP plumbing shared by the API engines (Wazuh, GoPhish): self-hosted servers often use a self-signed
/// certificate, which is trusted by pinning its SHA-256 fingerprint instead of turning validation off.
/// </summary>
public static class PinnedHttp
{
    /// <summary>64 lowercase hex characters, or null if <paramref name="pin"/> isn't a SHA-256 fingerprint.</summary>
    public static string? NormalizePin(string? pin)
    {
        var hex = pin?.Replace(":", "").Replace(" ", "").Trim().ToLowerInvariant();
        return hex is { Length: 64 } && hex.All(Uri.IsHexDigit) ? hex : null;
    }

    public static bool MatchesPin(X509Certificate certificate, string normalizedPin) =>
        Convert.ToHexStringLower(SHA256.HashData(certificate.GetRawCertData())) == normalizedPin;

    /// <summary>
    /// No redirects (credentials stay on the configured host), and the server certificate either pinned
    /// (<paramref name="pin"/> set) or validated normally.
    /// </summary>
    public static SocketsHttpHandler CreateHandler(string? pin)
    {
        var normalized = NormalizePin(pin);
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) => normalized is null
                    ? errors == SslPolicyErrors.None
                    : certificate is not null && MatchesPin(certificate, normalized)
            }
        };
    }
}

/// <summary>
/// Refuses every request that isn't a GET or HEAD before it leaves the process. For servers whose API
/// keys can also write (GoPhish has no read-only keys), this is what keeps SecurePulse's use read-only.
/// </summary>
public sealed class ReadOnlyHttpHandler : DelegatingHandler
{
    public ReadOnlyHttpHandler() { }

    public ReadOnlyHttpHandler(HttpMessageHandler inner) : base(inner) { }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        request.Method == HttpMethod.Get || request.Method == HttpMethod.Head
            ? base.SendAsync(request, cancellationToken)
            : throw new InvalidOperationException($"SecurePulse only reads from this API; refused a {request.Method} request.");
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using SecurePulse.Core.Models;

namespace SecurePulse.Intune;

/// <summary>Gets an app-only Graph access token for a client tenant.</summary>
public interface IGraphTokenProvider
{
    Task<string> GetTokenAsync(Tenant tenant, CancellationToken cancellationToken = default);
}

/// <summary>Finds a certificate with a private key by thumbprint.</summary>
public interface ICertificateLoader
{
    X509Certificate2? Find(string thumbprint);
}

/// <summary>Looks in CurrentUser\My, then LocalMachine\My. Certificates live in the store, never in config.</summary>
public sealed class StoreCertificateLoader : ICertificateLoader
{
    public X509Certificate2? Find(string thumbprint)
    {
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                var match = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                    .FirstOrDefault(c => c.HasPrivateKey);
                if (match is not null) return match;
            }
            catch (CryptographicException)
            {
                // Store missing or unsupported here (e.g. LocalMachine\My on Linux). Try the next one.
            }
        }
        return null;
    }
}

/// <summary>
/// App-only auth with SecurePulse's multi-tenant app and a certificate (no client secrets).
/// The tenant's <see cref="Tenant.CredentialReference"/> holds the certificate thumbprint.
/// </summary>
public sealed class CertificateGraphTokenProvider(IntuneOptions options, ICertificateLoader certificates) : IGraphTokenProvider
{
    public async Task<string> GetTokenAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(options.AppClientId, out var clientId) || clientId == Guid.Empty)
            throw new GraphAuthException("Intune:AppClientId is not configured as a valid GUID.");
        if (!Thumbprints.IsValid(tenant.CredentialReference))
            throw new GraphAuthException("Tenant credential reference is not a valid certificate thumbprint.");

        return await AppOnlyToken.AcquireAsync(tenant.EntraTenantId, clientId, tenant.CredentialReference!, certificates, options, cancellationToken);
    }
}

/// <summary>Client-credential token acquisition with a certificate from the store, shared by both apps.</summary>
internal static class AppOnlyToken
{
    public static async Task<string> AcquireAsync(Guid entraTenantId, Guid clientId, string thumbprint, ICertificateLoader certificates,
        IntuneOptions options, CancellationToken cancellationToken)
    {
        // A new credential per call means no token cache, so each token reflects the
        // permissions granted right now (verification and the checks before writes depend on that).
        using var certificate = certificates.Find(thumbprint)
            ?? throw new GraphAuthException($"Certificate {thumbprint} with a private key was not found in the certificate store.");

        var credential = new ClientCertificateCredential(
            entraTenantId.ToString(), clientId.ToString(), certificate,
            new ClientCertificateCredentialOptions { AuthorityHost = new Uri(options.AuthorityHost) });

        try
        {
            var token = await credential.GetTokenAsync(
                new TokenRequestContext([$"{options.GraphBaseUrl.TrimEnd('/')}/.default"]), cancellationToken);
            return token.Token;
        }
        catch (AuthenticationFailedException ex)
        {
            // Azure.Identity messages include a long troubleshooting footer; keep the first line.
            throw new GraphAuthException($"Could not get a Graph token: {ex.Message.Split('\n')[0].Trim()}", ex);
        }
    }
}

public sealed class GraphAuthException(string message, Exception? inner = null) : Exception(message, inner);

public static class Thumbprints
{
    /// <summary>A SHA-1 certificate thumbprint: 40 hex characters.</summary>
    public static bool IsValid(string? value) =>
        value is { Length: 40 } && value.All(Uri.IsHexDigit);
}

using Azure.Core;
using Azure.Identity;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>
/// How the Worker signs in to Azure services in your own tenant (Sentinel, Key Vault): a certificate
/// on an app registration, or the host's managed identity. Never a client secret.
/// </summary>
public static class AzureCredentials
{
    /// <summary>Problems with the identity settings under <paramref name="section"/>.</summary>
    public static IEnumerable<string> Problems(string section, string? tenantId, string? clientId, string? certificateThumbprint, bool useManagedIdentity)
    {
        if (useManagedIdentity)
        {
            if (!string.IsNullOrWhiteSpace(certificateThumbprint))
                yield return $"Use either a certificate or a managed identity for {section}, not both.";
            if (!string.IsNullOrWhiteSpace(clientId) && !Guid.TryParse(clientId, out _))
                yield return $"{section}:ClientId must be a GUID (the user-assigned identity's client ID), or empty for the system-assigned one.";
            yield break;
        }
        if (!Guid.TryParse(tenantId, out var tenant) || tenant == Guid.Empty)
            yield return $"{section}:TenantId must be your Entra tenant ID (a GUID).";
        if (!Guid.TryParse(clientId, out var client) || client == Guid.Empty)
            yield return $"{section}:ClientId must be the app registration's client ID (a GUID).";
        if (certificateThumbprint is not { Length: 40 } t || !t.All(Uri.IsHexDigit))
            yield return $"{section}:CertificateThumbprint must be a certificate thumbprint (40 hex characters), or set UseManagedIdentity.";
    }

    /// <summary>The credential; throws if the certificate isn't installed with its private key.</summary>
    public static TokenCredential Create(string section, string? tenantId, string? clientId, string? certificateThumbprint, bool useManagedIdentity,
        string authorityHost, ICertificateLoader certificates)
    {
        if (useManagedIdentity)
            return string.IsNullOrWhiteSpace(clientId)
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(clientId));

        var certificate = certificates.Find(certificateThumbprint!)
            ?? throw new InvalidOperationException(
                $"{section} certificate {certificateThumbprint} wasn't found with its private key in CurrentUser\\My or LocalMachine\\My.");
        return new ClientCertificateCredential(tenantId, clientId, certificate,
            new ClientCertificateCredentialOptions { AuthorityHost = new Uri(authorityHost) });
    }

    /// <summary>Azure.Identity puts the useful part (e.g. an AADSTS code) in inner exceptions; keep it on one line.</summary>
    public static string Describe(Exception ex)
    {
        var parts = new List<string>();
        for (var e = ex; e is not null; e = e.InnerException)
        {
            var line = string.Join(' ', e.Message.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).Trim().TrimEnd(':');
            if (line.Length > 0 && !parts.Any(p => p.Contains(line, StringComparison.Ordinal))) parts.Add(line);
        }
        var text = string.Join(": ", parts);
        return text.Length > 1000 ? text[..1000] + "…" : text;
    }
}

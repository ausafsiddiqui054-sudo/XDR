using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>A Key Vault the Worker reads engine secrets from, and how it signs in (certificate or managed identity).</summary>
public class KeyVaultOptions
{
    /// <summary>e.g. https://msp-securepulse.vault.azure.net/</summary>
    public string VaultUri { get; set; } = "";

    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public string? CertificateThumbprint { get; set; }
    public bool UseManagedIdentity { get; set; }
    public string AuthorityHost { get; set; } = "https://login.microsoftonline.com";

    /// <summary>Key Vault hosts in the public, US Government and China clouds.</summary>
    public static readonly string[] AllowedHostSuffixes = [".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn"];

    public IEnumerable<string> Problems(string section)
    {
        if (!Uri.TryCreate(VaultUri, UriKind.Absolute, out var vault) || vault.Scheme != Uri.UriSchemeHttps
            || !AllowedHostSuffixes.Any(s => vault.Host.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            || vault.PathAndQuery != "/" || !string.IsNullOrEmpty(vault.UserInfo))
            yield return $"{section}:VaultUri must be an https Azure Key Vault address (a host ending in {string.Join(", ", AllowedHostSuffixes)}).";
        foreach (var p in AzureCredentials.Problems(section, TenantId, ClientId, CertificateThumbprint, UseManagedIdentity))
            yield return p;
    }
}

/// <summary>
/// Reads secrets for each use; they're never written to config, disk or the database. Every failure comes
/// back as one readable line through <paramref name="error"/>, so a scan fails with a message, not a stack trace.
/// </summary>
public sealed class KeyVaultSecretReader(KeyVaultOptions options, string section, ICertificateLoader certificates, Func<string, Exception, Exception> error)
{
    private readonly Lazy<SecretClient> _client = new(() => new SecretClient(new Uri(options.VaultUri),
        AzureCredentials.Create(section, options.TenantId, options.ClientId, options.CertificateThumbprint, options.UseManagedIdentity,
            options.AuthorityHost, certificates)));

    /// <param name="what">What the secret is, for messages ("the Wazuh password").</param>
    /// <param name="notFoundHint">Added when the secret doesn't exist.</param>
    public async Task<string> GetAsync(string name, string what, string notFoundHint, CancellationToken ct)
    {
        try
        {
            var secret = await _client.Value.GetSecretAsync(name, cancellationToken: ct);
            return secret.Value.Value is { Length: > 0 } value
                ? value
                : throw error($"Key Vault secret '{name}' ({what}) is empty.", new InvalidOperationException("empty secret"));
        }
        catch (RequestFailedException ex)
        {
            var hint = ex.Status is 401 or 403
                ? " Give the Worker's identity the Key Vault Secrets User role (or a get-secret access policy) on the vault."
                : ex.Status == 404 ? $" {notFoundHint}" : "";
            throw error($"Couldn't read {what} from Key Vault secret '{name}' ({ex.Status}): {AzureCredentials.Describe(ex)}.{hint}", ex);
        }
        catch (AuthenticationFailedException ex)
        {
            throw error($"Couldn't sign in to Key Vault: {AzureCredentials.Describe(ex)}", ex);
        }
        catch (AggregateException ex)
        {
            // The Azure SDK's retries gave up on the network (DNS, proxy, firewall): name the vault, keep one line.
            var cause = ex.InnerExceptions.LastOrDefault() is { } last ? AzureCredentials.Describe(last) : ex.Message;
            throw error($"Couldn't reach Key Vault {new Uri(options.VaultUri).Host}: {cause}", ex);
        }
    }
}

using System.Text.RegularExpressions;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using SecurePulse.Engines.Wazuh;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>The <c>Wazuh:KeyVault</c> section: where the Wazuh API user's password is kept, and how the Worker signs in to read it.</summary>
public sealed partial class WazuhKeyVaultOptions
{
    /// <summary>e.g. https://msp-securepulse.vault.azure.net/</summary>
    public string VaultUri { get; set; } = "";

    public string PasswordSecretName { get; set; } = "wazuh-api-password";

    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public string? CertificateThumbprint { get; set; }
    public bool UseManagedIdentity { get; set; }
    public string AuthorityHost { get; set; } = "https://login.microsoftonline.com";

    /// <summary>Key Vault hosts in the public, US Government and China clouds.</summary>
    public static readonly string[] AllowedHostSuffixes = [".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn"];

    public IEnumerable<string> Problems()
    {
        if (!Uri.TryCreate(VaultUri, UriKind.Absolute, out var vault) || vault.Scheme != Uri.UriSchemeHttps
            || !AllowedHostSuffixes.Any(s => vault.Host.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            || vault.PathAndQuery != "/" || !string.IsNullOrEmpty(vault.UserInfo))
            yield return $"Wazuh:KeyVault:VaultUri must be an https Azure Key Vault address (a host ending in {string.Join(", ", AllowedHostSuffixes)}).";
        if (!SecretName().IsMatch(PasswordSecretName))
            yield return "Wazuh:KeyVault:PasswordSecretName must be a Key Vault secret name (letters, digits and '-').";
        foreach (var p in AzureCredentials.Problems("Wazuh:KeyVault", TenantId, ClientId, CertificateThumbprint, UseManagedIdentity))
            yield return p;
    }

    [GeneratedRegex("^[0-9A-Za-z-]{1,127}$")]
    private static partial Regex SecretName();
}

/// <summary>Reads the Wazuh API password from Key Vault for each scan; it's never written to config, disk or the database.</summary>
public sealed class KeyVaultWazuhPasswordProvider(WazuhKeyVaultOptions options, ICertificateLoader certificates) : IWazuhPasswordProvider
{
    private readonly Lazy<SecretClient> _client = new(() => new SecretClient(new Uri(options.VaultUri),
        AzureCredentials.Create("Wazuh:KeyVault", options.TenantId, options.ClientId, options.CertificateThumbprint, options.UseManagedIdentity,
            options.AuthorityHost, certificates)));

    public async Task<string> GetPasswordAsync(CancellationToken ct)
    {
        try
        {
            var secret = await _client.Value.GetSecretAsync(options.PasswordSecretName, cancellationToken: ct);
            return secret.Value.Value is { Length: > 0 } password
                ? password
                : throw new WazuhException($"Key Vault secret '{options.PasswordSecretName}' is empty.");
        }
        catch (RequestFailedException ex)
        {
            var hint = ex.Status is 401 or 403
                ? " Give the Worker's identity the Key Vault Secrets User role (or a get-secret access policy) on the vault."
                : ex.Status == 404 ? " Check Wazuh:KeyVault:PasswordSecretName." : "";
            throw new WazuhException($"Couldn't read the Wazuh password from Key Vault ({ex.Status}): {AzureCredentials.Describe(ex)}.{hint}", ex);
        }
        catch (AuthenticationFailedException ex)
        {
            throw new WazuhException($"Couldn't sign in to Key Vault: {AzureCredentials.Describe(ex)}", ex);
        }
        catch (AggregateException ex)
        {
            // The Azure SDK's retries gave up on the network (DNS, proxy, firewall): name the vault, keep one line.
            var cause = ex.InnerExceptions.LastOrDefault() is { } last ? AzureCredentials.Describe(last) : ex.Message;
            throw new WazuhException($"Couldn't reach Key Vault {new Uri(options.VaultUri).Host}: {cause}", ex);
        }
    }
}

public static class WazuhSetup
{
    /// <summary>Registers the Wazuh engine; throws when its settings would let it scan unsafely.</summary>
    public static WazuhOptions AddWazuhEngine(this IServiceCollection services, IConfiguration configuration)
    {
        var wazuh = configuration.GetSection("Wazuh").Get<WazuhOptions>() ?? new WazuhOptions();
        var keyVault = configuration.GetSection("Wazuh:KeyVault").Get<WazuhKeyVaultOptions>() ?? new WazuhKeyVaultOptions();
        var problems = wazuh.Problems().Concat(keyVault.Problems()).ToList();
        if (problems.Count > 0) throw new InvalidOperationException(string.Join(" ", problems));

        services.AddSingleton(wazuh);
        services.AddSingleton(keyVault);
        services.AddSingleton<IWazuhPasswordProvider, KeyVaultWazuhPasswordProvider>();
        // WazuhOptions.Timeout bounds the whole scan; the handler pins the API's certificate and refuses redirects.
        services.AddHttpClient<WazuhEngine>(c => c.Timeout = Timeout.InfiniteTimeSpan)
            .ConfigurePrimaryHttpMessageHandler(wazuh.CreateHandler);
        services.AddSingleton<SecurePulse.Core.Abstractions.IScanEngine>(sp => sp.GetRequiredService<WazuhEngine>());
        return wazuh;
    }
}

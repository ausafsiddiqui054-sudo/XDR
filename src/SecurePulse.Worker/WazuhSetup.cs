using System.Text.RegularExpressions;
using SecurePulse.Engines.Wazuh;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>The <c>Wazuh:KeyVault</c> section: where the Wazuh API user's password is kept, and how the Worker signs in to read it.</summary>
public sealed partial class WazuhKeyVaultOptions : KeyVaultOptions
{
    public const string Section = "Wazuh:KeyVault";

    public string PasswordSecretName { get; set; } = "wazuh-api-password";

    public IEnumerable<string> Problems()
    {
        foreach (var p in Problems(Section)) yield return p;
        if (!SecretName().IsMatch(PasswordSecretName))
            yield return "Wazuh:KeyVault:PasswordSecretName must be a Key Vault secret name (letters, digits and '-').";
    }

    [GeneratedRegex("^[0-9A-Za-z-]{1,127}$")]
    private static partial Regex SecretName();
}

/// <summary>Reads the Wazuh API password from Key Vault for each scan.</summary>
public sealed class KeyVaultWazuhPasswordProvider(WazuhKeyVaultOptions options, ICertificateLoader certificates) : IWazuhPasswordProvider
{
    private readonly KeyVaultSecretReader _reader = new(options, WazuhKeyVaultOptions.Section, certificates, (m, e) => new WazuhException(m, e));

    public Task<string> GetPasswordAsync(CancellationToken ct) =>
        _reader.GetAsync(options.PasswordSecretName, "the Wazuh password", "Check Wazuh:KeyVault:PasswordSecretName.", ct);
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

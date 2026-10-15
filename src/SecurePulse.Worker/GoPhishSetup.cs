using SecurePulse.Core.Models;
using SecurePulse.Engines.GoPhish;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>Reads a tenant's GoPhish API key from Key Vault (secret gophish-api-key-{tenant ID}) for each import.</summary>
public sealed class KeyVaultGoPhishApiKeyProvider(GoPhishKeyVaultOptions options, ICertificateLoader certificates) : IGoPhishApiKeyProvider
{
    private readonly KeyVaultSecretReader _reader = new(options, GoPhishKeyVaultOptions.Section, certificates, (m, e) => new GoPhishException(m, e));

    public Task<string> GetApiKeyAsync(Guid tenantId, CancellationToken ct) =>
        _reader.GetAsync(GoPhishSecrets.ApiKeySecretName(tenantId), "the tenant's GoPhish API key",
            "Store the API key of the tenant's GoPhish user under that name (the Tenants page shows it).", ct);
}

/// <summary>The <c>GoPhish:KeyVault</c> section. Secret names come from the tenant ID, so they aren't configured.</summary>
public sealed class GoPhishKeyVaultOptions : KeyVaultOptions
{
    public const string Section = "GoPhish:KeyVault";
}

public static class GoPhishSetup
{
    /// <summary>Registers the GoPhish engine; throws when its settings would let it import unsafely.</summary>
    public static GoPhishOptions AddGoPhishEngine(this IServiceCollection services, IConfiguration configuration)
    {
        var goPhish = configuration.GetSection("GoPhish").Get<GoPhishOptions>() ?? new GoPhishOptions();
        var keyVault = configuration.GetSection(GoPhishKeyVaultOptions.Section).Get<GoPhishKeyVaultOptions>() ?? new GoPhishKeyVaultOptions();
        var problems = goPhish.Problems().Concat(keyVault.Problems(GoPhishKeyVaultOptions.Section)).ToList();
        if (problems.Count > 0) throw new InvalidOperationException(string.Join(" ", problems));

        services.AddSingleton(goPhish);
        services.AddSingleton(keyVault);
        services.AddSingleton<IGoPhishApiKeyProvider, KeyVaultGoPhishApiKeyProvider>();
        // GoPhishOptions.Timeout bounds the import; the handler allows only GET/HEAD, pins the certificate and refuses redirects.
        services.AddHttpClient<GoPhishEngine>(c => c.Timeout = Timeout.InfiniteTimeSpan)
            .ConfigurePrimaryHttpMessageHandler(goPhish.CreateHandler);
        services.AddSingleton<SecurePulse.Core.Abstractions.IScanEngine>(sp => sp.GetRequiredService<GoPhishEngine>());
        return goPhish;
    }
}

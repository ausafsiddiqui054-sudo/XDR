using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Engines.GoPhish;
using SecurePulse.Worker;

namespace SecurePulse.Tests.Scans;

public class EngineSetupTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    private static readonly (string, string)[] GoodGoPhish =
    [
        ("GoPhish:Url", "https://gophish.msp.example:3333"),
        ("GoPhish:KeyVault:VaultUri", "https://msp-securepulse.vault.azure.net/"),
        ("GoPhish:KeyVault:UseManagedIdentity", "true")
    ];

    [Fact]
    public void GoPhish_RegistersWithGoodSettings()
    {
        var services = new ServiceCollection();
        var options = services.AddGoPhishEngine(Config(GoodGoPhish));

        Assert.Equal(TimeSpan.FromMinutes(5), options.Timeout);
        Assert.Contains(services, d => d.ServiceType == typeof(IGoPhishApiKeyProvider) && d.ImplementationType == typeof(KeyVaultGoPhishApiKeyProvider));
    }

    [Theory]
    [InlineData("GoPhish:Url", "http://gophish.msp.example:3333", "GoPhish:Url")]
    [InlineData("GoPhish:KeyVault:VaultUri", "https://secrets.attacker.example/", "GoPhish:KeyVault:VaultUri")]
    [InlineData("GoPhish:KeyVault:UseManagedIdentity", "false", "GoPhish:KeyVault:TenantId")]
    public void GoPhish_RefusesToStartWithUnsafeSettings(string key, string value, string expected)
    {
        var settings = GoodGoPhish.Where(s => s.Item1 != key).Append((key, value)).ToArray();

        var ex = Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddGoPhishEngine(Config(settings)));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Wazuh_KeyVaultSettingsStillChecked()
    {
        var o = new WazuhKeyVaultOptions { VaultUri = "https://vault.example.com/", PasswordSecretName = "bad name!", UseManagedIdentity = true };

        var problems = o.Problems().ToList();
        Assert.Contains(problems, p => p.StartsWith("Wazuh:KeyVault:VaultUri"));
        Assert.Contains(problems, p => p.StartsWith("Wazuh:KeyVault:PasswordSecretName"));
        Assert.Empty(new WazuhKeyVaultOptions { VaultUri = "https://msp.vault.usgovcloudapi.net/", UseManagedIdentity = true }.Problems());
    }
}

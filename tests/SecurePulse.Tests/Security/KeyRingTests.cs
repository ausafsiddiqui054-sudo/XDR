using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Data;
using SecurePulse.Data.Entities;
using SecurePulse.Tests.Data;
using SecurePulse.Web.Security;

namespace SecurePulse.Tests.Security;

public class KeyRingTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static X509Certificate2 NewCertificate(DateTimeOffset? notAfter = null)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=SecurePulse key encryption (test)", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-60), notAfter ?? DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
    }

    private static readonly X509Certificate2 Cert = NewCertificate();

    private static Func<string, X509Certificate2?> Finder(params X509Certificate2[] certs) =>
        t => certs.FirstOrDefault(c => string.Equals(c.Thumbprint, t, StringComparison.OrdinalIgnoreCase));

    private static KeyRingStatus Configure(KeyRingOptions options, bool database, bool development, Func<string, X509Certificate2?>? find = null) =>
        new ServiceCollection().AddSecurePulseDataProtection(options, database, development, find ?? Finder(Cert));

    // --- Which store, and when the portal refuses to start -------------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WithoutADatabase_KeysAreLocal(bool development)
    {
        var status = Configure(new KeyRingOptions(), database: false, development);

        Assert.Equal(KeyRingStore.Local, status.Store);
        Assert.Empty(status.Warnings);
    }

    [Fact]
    public void DevelopmentWithoutACertificate_StaysLocal()
    {
        var status = Configure(new KeyRingOptions(), database: true, development: true);

        Assert.Equal(KeyRingStore.Local, status.Store);
    }

    [Fact]
    public void ProductionDatabaseWithoutACertificate_RefusesToStart()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Configure(new KeyRingOptions(), database: true, development: false));

        Assert.Contains("DataProtection:CertificateThumbprint isn't set", ex.Message);
    }

    [Fact]
    public void WithACertificate_KeysGoToTheDatabaseEvenInDevelopment()
    {
        var status = Configure(new KeyRingOptions { CertificateThumbprint = Cert.Thumbprint }, database: true, development: true);

        Assert.Equal(KeyRingStore.Database, status.Store);
        Assert.Contains(Cert.Thumbprint, status.Description);
        Assert.Empty(status.Warnings);
    }

    [Theory]
    [InlineData("not-a-thumbprint", "isn't a certificate thumbprint")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456Z", "isn't a certificate thumbprint")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF01234567", "wasn't found with its private key")]
    public void BadOrMissingCertificate_RefusesToStart(string thumbprint, string message)
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Configure(new KeyRingOptions { Store = KeyRingStore.Database, CertificateThumbprint = thumbprint }, database: true, development: true));

        Assert.Contains(message, ex.Message);
    }

    [Fact]
    public void CertificateWithoutItsPrivateKey_RefusesToStart()
    {
        var publicOnly = X509CertificateLoader.LoadCertificate(Cert.RawData);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            Configure(new KeyRingOptions { CertificateThumbprint = Cert.Thumbprint }, database: true, development: false, _ => publicOnly));

        Assert.Contains("wasn't found with its private key", ex.Message);
    }

    [Fact]
    public void MissingPreviousCertificate_RefusesToStart()
    {
        // Otherwise keys it encrypted would silently become unreadable and everyone signed out.
        var ex = Assert.Throws<InvalidOperationException>(() => Configure(new KeyRingOptions
        {
            CertificateThumbprint = Cert.Thumbprint,
            PreviousCertificateThumbprints = ["0123456789ABCDEF0123456789ABCDEF01234567"]
        }, database: true, development: false));

        Assert.Contains("DataProtection:PreviousCertificateThumbprints:0", ex.Message);
    }

    [Fact]
    public void DatabaseStoreWithoutADatabase_RefusesToStart()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Configure(new KeyRingOptions { Store = KeyRingStore.Database, CertificateThumbprint = Cert.Thumbprint }, database: false, development: false));

        Assert.Contains("ConnectionStrings:SecurePulse isn't set", ex.Message);
    }

    [Fact]
    public void ExplicitLocalInProduction_IsAllowedWithAWarning()
    {
        var status = Configure(new KeyRingOptions { Store = KeyRingStore.Local }, database: true, development: false);

        Assert.Equal(KeyRingStore.Local, status.Store);
        Assert.Contains(status.Warnings, w => w.Contains("Don't run more than one portal instance"));
    }

    [Fact]
    public void ExpiringAndExpiredCertificates_AreWarnedAbout()
    {
        var soon = NewCertificate(DateTimeOffset.UtcNow.AddDays(10));
        var expired = NewCertificate(DateTimeOffset.UtcNow.AddDays(-1));

        var status = Configure(new KeyRingOptions { CertificateThumbprint = soon.Thumbprint, PreviousCertificateThumbprints = [expired.Thumbprint] },
            database: true, development: false, Finder(soon, expired));

        Assert.Contains(status.Warnings, w => w.Contains(soon.Thumbprint) && w.Contains("Rotate it soon"));
        Assert.Contains(status.Warnings, w => w.Contains(expired.Thumbprint) && w.Contains("expired"));
    }

    [Fact]
    public void DatabaseStore_UsesTheSharedApplicationNameAndTheDatabaseRepository()
    {
        var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddSecurePulseData("Host=unused;Database=unused");
        services.AddSecurePulseDataProtection(new KeyRingOptions { CertificateThumbprint = Cert.Thumbprint }, true, false, Finder(Cert));
        using var sp = services.BuildServiceProvider();

        Assert.IsType<DatabaseXmlRepository>(sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value.XmlRepository);
        Assert.NotNull(sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value.XmlEncryptor);
        Assert.Equal(KeyRing.ApplicationName, sp.GetRequiredService<IOptions<DataProtectionOptions>>().Value.ApplicationDiscriminator);
    }

    [Fact]
    public void LocalStore_StillUsesTheSharedApplicationName()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddSecurePulseDataProtection(new KeyRingOptions(), false, true, Finder());
        using var sp = services.BuildServiceProvider();

        Assert.Null(sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value.XmlRepository);
        Assert.Equal(KeyRing.ApplicationName, sp.GetRequiredService<IOptions<DataProtectionOptions>>().Value.ApplicationDiscriminator);
    }

    // --- Shared keys in PostgreSQL ---------------------------------------------------------------

    private IDbContextFactory<SecurePulseDbContext> Factory => db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();

    /// <summary>One portal instance: its own service provider and key ring cache, the shared database.</summary>
    private ServiceProvider Instance(X509Certificate2 current, params X509Certificate2[] previous)
    {
        var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddSingleton(Factory);
        services.AddSecurePulseDataProtection(
            new KeyRingOptions { CertificateThumbprint = current.Thumbprint, PreviousCertificateThumbprints = [.. previous.Select(c => c.Thumbprint)] },
            databaseConfigured: true, isDevelopment: false, Finder([current, .. previous]));
        return services.BuildServiceProvider();
    }

    private static IDataProtector Protector(IServiceProvider sp) =>
        sp.GetRequiredService<IDataProtectionProvider>().CreateProtector("SecurePulse.Tests.KeyRing");

    [PostgresFact]
    public void AnotherInstance_ReadsWhatOneInstanceProtected()
    {
        using var a = Instance(Cert);
        var payload = Protector(a).Protect("consent-state-123");

        using var b = Instance(Cert);

        Assert.Equal("consent-state-123", Protector(b).Unprotect(payload));
    }

    [PostgresFact]
    public void KeysAreStoredEncrypted()
    {
        using var a = Instance(Cert);
        Protector(a).Protect("anything");

        using var context = Factory.CreateDbContext();
        var rows = context.DataProtectionKeys.AsNoTracking().ToList();
        Assert.NotEmpty(rows);
        Assert.All(rows, r =>
        {
            var xml = XElement.Parse(r.Xml);
            if (xml.Name.LocalName != "key") return; // revocations carry no secret
            Assert.DoesNotContain(xml.Descendants(), e => e.Name.LocalName == "masterKey");
            Assert.Contains(xml.Descendants(), e => e.Name.LocalName == "encryptedSecret");
            Assert.Contains(xml.Descendants(), e => e.Name.LocalName == "X509Certificate" && e.Value == Convert.ToBase64String(Cert.RawData));
            Assert.StartsWith("key-", r.FriendlyName);
        });
    }

    [PostgresFact]
    public void AnInstanceWithAnotherCertificate_CantReadTheKeys()
    {
        using var a = Instance(Cert);
        var payload = Protector(a).Protect("cookie");

        using var stranger = Instance(NewCertificate());

        Assert.ThrowsAny<CryptographicException>(() => Protector(stranger).Unprotect(payload));
    }

    [PostgresFact]
    public void AfterRotation_KeysFromThePreviousCertificateStillWork()
    {
        var old = NewCertificate();
        using var before = Instance(old);
        var payload = Protector(before).Protect("signed-in");

        var replacement = NewCertificate();
        using var after = Instance(replacement, old);

        Assert.Equal("signed-in", Protector(after).Unprotect(payload));
        using var withoutOld = Instance(replacement);
        Assert.ThrowsAny<CryptographicException>(() => Protector(withoutOld).Unprotect(payload));
    }

    [PostgresFact]
    public void UnencryptedKeysAreNeverStored()
    {
        var repository = new DatabaseXmlRepository(Factory, TimeProvider.System, NullLogger<DatabaseXmlRepository>.Instance);
        XNamespace dp = "http://schemas.asp.net/2015/03/dataProtection";
        var plain = new XElement("securepulse-test", new XElement("descriptor", new XElement("masterKey", new XAttribute(dp + "requiresEncryption", "true"),
            new XElement("value", "c2VjcmV0"))));

        Assert.Throws<InvalidOperationException>(() => repository.StoreElement(plain, "key-plain"));

        using var context = Factory.CreateDbContext();
        Assert.DoesNotContain(context.DataProtectionKeys.AsNoTracking(), r => r.FriendlyName == "key-plain");
    }

    [PostgresFact]
    public void ADamagedRowIsSkipped_NotFatal()
    {
        var repository = new DatabaseXmlRepository(Factory, TimeProvider.System, NullLogger<DatabaseXmlRepository>.Instance);
        // An element data protection ignores, so other tests' key rings aren't affected.
        repository.StoreElement(new XElement("securepulse-test"), "test-good");
        using (var context = Factory.CreateDbContext())
        {
            context.DataProtectionKeys.Add(new DataProtectionKeyEntity { FriendlyName = "key-damaged", Xml = "<key", CreatedAt = DateTimeOffset.UtcNow });
            context.SaveChanges();
        }

        var elements = repository.GetAllElements();

        using var read = Factory.CreateDbContext();
        Assert.Equal(read.DataProtectionKeys.Count() - 1, elements.Count); // every row but the damaged one
        Assert.Contains(elements, e => e.Name.LocalName == "securepulse-test");
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecurePulse.Data;
using SecurePulse.Data.Entities;

namespace SecurePulse.Web.Security;

public enum KeyRingStore
{
    /// <summary>Database when the portal uses PostgreSQL (Local in Development without a certificate); otherwise Local.</summary>
    Auto,

    /// <summary>Shared by every portal instance: PostgreSQL, encrypted with the key-encryption certificate.</summary>
    Database,

    /// <summary>ASP.NET Core's default per-machine folder. Only for one instance.</summary>
    Local
}

/// <summary>The <c>DataProtection</c> configuration section.</summary>
public sealed class KeyRingOptions
{
    public KeyRingStore Store { get; set; } = KeyRingStore.Auto;

    /// <summary>
    /// Certificate (with private key, in CurrentUser\My or LocalMachine\My) that encrypts the keys
    /// before they are stored. A reference only: the certificate itself never goes in config.
    /// </summary>
    public string? CertificateThumbprint { get; set; }

    /// <summary>Earlier certificates, kept so keys they encrypted stay readable after a rotation.</summary>
    public string[] PreviousCertificateThumbprints { get; set; } = [];
}

/// <summary>How the key ring was set up, for the startup log.</summary>
public sealed record KeyRingStatus(KeyRingStore Store, string Description, IReadOnlyList<string> Warnings);

/// <summary>
/// Data protection protects the sign-in cookie, antiforgery tokens and consent-link state. With
/// more than one portal instance every instance needs the same keys, so they live in PostgreSQL,
/// encrypted with a certificate: the database never holds key material in the clear (rule 3).
/// </summary>
public static class KeyRing
{
    /// <summary>Shared by every instance; ASP.NET Core otherwise isolates apps by content root path.</summary>
    public const string ApplicationName = "SecurePulse";

    /// <summary>Warn this long before the key-encryption certificate expires.</summary>
    public static readonly TimeSpan ExpiryWarning = TimeSpan.FromDays(30);

    /// <param name="findCertificate">Looks a thumbprint up in the certificate stores (with private key); null if absent.</param>
    /// <exception cref="InvalidOperationException">The configuration can't give every instance the same, encrypted keys.</exception>
    public static KeyRingStatus AddSecurePulseDataProtection(this IServiceCollection services, KeyRingOptions options, bool databaseConfigured,
        bool isDevelopment, Func<string, X509Certificate2?> findCertificate, TimeProvider? time = null)
    {
        var builder = services.AddDataProtection().SetApplicationName(ApplicationName);
        var hasThumbprint = !string.IsNullOrWhiteSpace(options.CertificateThumbprint);
        var warnings = new List<string>();

        var store = options.Store switch
        {
            KeyRingStore.Auto when !databaseConfigured => KeyRingStore.Local,
            KeyRingStore.Auto when isDevelopment && !hasThumbprint => KeyRingStore.Local,
            KeyRingStore.Auto => KeyRingStore.Database,
            KeyRingStore.Database or KeyRingStore.Local => options.Store,
            _ => throw new InvalidOperationException($"DataProtection:Store '{options.Store}' isn't one of Auto, Database or Local.")
        };

        if (store == KeyRingStore.Local)
        {
            if (databaseConfigured && !isDevelopment)
                warnings.Add("Data-protection keys are local to this instance (DataProtection:Store = Local). Don't run more than one portal instance.");
            return new KeyRingStatus(KeyRingStore.Local, "Local key folder (this instance only)", warnings);
        }

        if (!databaseConfigured)
            throw new InvalidOperationException("DataProtection:Store is Database, but ConnectionStrings:SecurePulse isn't set.");

        var current = Load(options.CertificateThumbprint, "DataProtection:CertificateThumbprint", findCertificate);
        var previous = options.PreviousCertificateThumbprints
            .Select((t, i) => Load(t, $"DataProtection:PreviousCertificateThumbprints:{i}", findCertificate))
            .ToList();

        var now = (time ?? TimeProvider.System).GetUtcNow();
        foreach (var cert in previous.Prepend(current))
        {
            if (cert.NotAfter.ToUniversalTime() <= now.UtcDateTime)
                warnings.Add($"Key-encryption certificate {cert.Thumbprint} expired on {cert.NotAfter:yyyy-MM-dd}. It still decrypts, but rotate it.");
            else if (cert.NotAfter.ToUniversalTime() - now.UtcDateTime < ExpiryWarning)
                warnings.Add($"Key-encryption certificate {cert.Thumbprint} expires on {cert.NotAfter:yyyy-MM-dd}. Rotate it soon.");
        }

        services.AddSingleton<DatabaseXmlRepository>();
        services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp =>
            new ConfigureOptions<KeyManagementOptions>(o => o.XmlRepository = sp.GetRequiredService<DatabaseXmlRepository>()));
        builder.ProtectKeysWithCertificate(current)
            .UnprotectKeysWithAnyCertificate([current, .. previous]);

        return new KeyRingStatus(KeyRingStore.Database, $"PostgreSQL, encrypted with certificate {current.Thumbprint}", warnings);
    }

    private static X509Certificate2 Load(string? thumbprint, string setting, Func<string, X509Certificate2?> findCertificate)
    {
        var value = thumbprint?.Trim();
        if (string.IsNullOrEmpty(value))
            throw new InvalidOperationException(
                $"{setting} isn't set. Shared data-protection keys are stored in PostgreSQL and must be encrypted with a certificate. " +
                "Set DataProtection:Store to Local only for a single portal instance.");
        if (value.Length != 40 || !value.All(Uri.IsHexDigit))
            throw new InvalidOperationException($"{setting} isn't a certificate thumbprint (40 hex characters).");
        return findCertificate(value) is { HasPrivateKey: true } cert
            ? cert
            : throw new InvalidOperationException($"Certificate {value} ({setting}) wasn't found with its private key in CurrentUser\\My or LocalMachine\\My.");
    }

    /// <summary>CurrentUser\My, then LocalMachine\My; only certificates with a private key.</summary>
    public static X509Certificate2? FindInStores(string thumbprint)
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
/// The key ring in PostgreSQL (<c>data_protection_keys</c>). Insert-only: data protection never
/// deletes keys, it revokes them by storing a revocation element. It refuses to store any element
/// still marked as needing encryption, so a missing key-encryption step fails instead of leaking keys.
/// </summary>
public sealed class DatabaseXmlRepository(IDbContextFactory<SecurePulseDbContext> factory, TimeProvider time, ILogger<DatabaseXmlRepository> logger)
    : IXmlRepository
{
    private static readonly XName RequiresEncryption = XName.Get("requiresEncryption", "http://schemas.asp.net/2015/03/dataProtection");

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var db = factory.CreateDbContext();
        var rows = db.DataProtectionKeys.AsNoTracking().OrderBy(k => k.Id).Select(k => new { k.FriendlyName, k.Xml }).ToList();
        var elements = new List<XElement>(rows.Count);
        foreach (var row in rows)
        {
            try
            {
                elements.Add(XElement.Parse(row.Xml));
            }
            catch (System.Xml.XmlException ex)
            {
                // One damaged row mustn't take every instance down; the rest of the ring still works.
                logger.LogCritical(ex, "Data-protection key {FriendlyName} in the database isn't valid XML; ignoring it", row.FriendlyName);
            }
        }
        return elements;
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        if (element.DescendantsAndSelf().Any(e => (bool?)e.Attribute(RequiresEncryption) == true))
            throw new InvalidOperationException("Refusing to store a data-protection key that isn't encrypted.");

        using var db = factory.CreateDbContext();
        db.DataProtectionKeys.Add(new DataProtectionKeyEntity
        {
            FriendlyName = friendlyName,
            Xml = element.ToString(SaveOptions.DisableFormatting),
            CreatedAt = time.GetUtcNow()
        });
        db.SaveChanges();
        logger.LogInformation("Stored data-protection element {FriendlyName} in the database", friendlyName);
    }
}

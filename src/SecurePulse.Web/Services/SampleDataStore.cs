using System.Collections.Concurrent;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Services;

/// <summary>
/// In-memory store seeded with fictional tenants and realistic M365 findings so the
/// portal can be designed and demoed before real scans exist. Replace with EF Core
/// repositories once the Worker starts writing real scan results.
/// </summary>
public sealed class SampleDataStore : ITenantRepository, IFindingRepository, IDeviceRepository
{
    private readonly List<Tenant> _tenants;
    private readonly ConcurrentDictionary<Guid, IReadOnlyList<Finding>> _findings = new();
    private readonly ConcurrentDictionary<Guid, IReadOnlyList<ManagedDevice>> _devices = new();

    private sealed record Check(
        string Id, string Title, string Category, Severity Severity,
        string Remediation, string Evidence, string[] Frameworks);

    private static readonly Check[] Catalog =
    [
        new("SP-ID-001", "Privileged roles require phishing-resistant MFA", "Identity", Severity.Critical,
            "Create a Conditional Access policy targeting directory roles that requires the 'Phishing-resistant MFA' authentication strength.",
            "3 of 5 Global Administrators can sign in with SMS or voice MFA.", ["UAE IA", "CIS M365"]),
        new("SP-ID-002", "Legacy authentication is blocked", "Identity", Severity.High,
            "Block 'Exchange ActiveSync clients' and 'Other clients' with a tenant-wide Conditional Access policy.",
            "No Conditional Access policy blocks legacy authentication protocols.", ["UAE IA", "CIS M365"]),
        new("SP-ID-003", "All users are registered for MFA", "Identity", Severity.High,
            "Enable the MFA registration campaign and require registration within 14 days.",
            "27 enabled users have no MFA method registered.", ["UAE IA", "DoH ADHICS"]),
        new("SP-ID-004", "Break-glass accounts are excluded from Conditional Access", "Identity", Severity.High,
            "Exclude two cloud-only emergency access accounts from all CA policies and alert on their sign-ins.",
            "No emergency access accounts detected.", ["CIS M365"]),
        new("SP-ID-005", "Standing Global Admin assignments are minimised", "Identity", Severity.Medium,
            "Move permanent Global Admin assignments to PIM-eligible with approval and time limits.",
            "4 permanent Global Administrator assignments found.", ["UAE IA"]),
        new("SP-DV-001", "Devices must be compliant to access corporate data", "Devices", Severity.High,
            "Require 'device marked as compliant' in Conditional Access for Office 365 apps.",
            "No compliance-based Conditional Access policy found.", ["DoH ADHICS", "CIS M365"]),
        new("SP-DV-002", "Disk encryption required on Windows devices", "Devices", Severity.High,
            "Deploy an Intune BitLocker policy and add encryption to the Windows compliance policy.",
            "14 of 62 Windows devices are not encrypted.", ["DoH ADHICS"]),
        new("SP-DV-003", "OS updates enforced via update rings", "Devices", Severity.Medium,
            "Assign Windows Update rings with a 7-day quality-update deadline.",
            "No update ring assigned to 'All devices'.", ["UAE IA"]),
        new("SP-EM-001", "External mail auto-forwarding is disabled", "Email", Severity.High,
            "Set the outbound spam policy auto-forwarding mode to 'Off'.",
            "Automatic forwarding is set to 'On' in the default outbound policy.", ["UAE IA", "CIS M365"]),
        new("SP-EM-002", "DMARC is published with an enforcing policy", "Email", Severity.Medium,
            "Publish DMARC with p=quarantine, then move to p=reject after monitoring.",
            "DMARC record is p=none.", ["CIS M365"]),
        new("SP-EM-003", "Safe Links is enabled for email and Office apps", "Email", Severity.Medium,
            "Enable the Standard preset security policy for all recipients.",
            "Safe Links policy not assigned.", ["CIS M365"]),
        new("SP-CO-001", "SharePoint external sharing is restricted", "Collaboration", Severity.Medium,
            "Limit external sharing to 'New and existing guests' and set link expiry.",
            "Sharing allows 'Anyone' links with no expiry.", ["DoH ADHICS"]),
        new("SP-CO-002", "Guest access is reviewed quarterly", "Collaboration", Severity.Low,
            "Create an access review for all guest users every 90 days.",
            "No access reviews configured.", ["UAE IA"]),
        new("SP-AU-001", "Unified audit logging is enabled", "Monitoring", Severity.Critical,
            "Enable unified audit log ingestion in Microsoft Purview.",
            "Audit log search is disabled.", ["UAE IA", "DoH ADHICS", "CIS M365"]),
        new("SP-AU-002", "Sign-in risk alerts are routed to IT", "Monitoring", Severity.Low,
            "Configure Identity Protection risk notifications to the security mailbox.",
            "No recipients configured for risky sign-in alerts.", ["UAE IA"])
    ];

    public SampleDataStore()
    {
        _tenants =
        [
            MakeTenant("Al Noor Family Clinic", "alnoorclinic.example", "Healthcare", null, TenantConsentState.ReadOnlyGranted, 2, passRate: 0.45),
            MakeTenant("Palm Dental Studio", "palmdental.example", "Healthcare", "Gulf IT Services", TenantConsentState.ReadOnlyGranted, 5, passRate: 0.7),
            MakeTenant("Creek Physio Center", "creekphysio.example", "Healthcare", "Gulf IT Services", TenantConsentState.RemediationGranted, 1, passRate: 0.88),
            MakeTenant("Marina Legal Partners", "marinalegal.example", "Professional services", "Gulf IT Services", TenantConsentState.ReadOnlyGranted, 9, passRate: 0.6),
            MakeTenant("Desert Rose Pharmacy", "desertrose.example", "Healthcare", null, TenantConsentState.Pending, null, passRate: 0)
        ];
    }

    private Tenant MakeTenant(string name, string domain, string industry, string? partner,
        TenantConsentState consent, int? daysSinceScan, double passRate)
    {
        var tenant = new Tenant
        {
            Id = Guid.NewGuid(),
            EntraTenantId = Guid.NewGuid(),
            DisplayName = name,
            PrimaryDomain = domain,
            Industry = industry,
            PartnerName = partner,
            ConsentState = consent,
            LastScanAt = daysSinceScan is null ? null : DateTimeOffset.UtcNow.AddDays(-daysSinceScan.Value).AddHours(-3)
        };

        _findings[tenant.Id] = tenant.LastScanAt is null ? [] : Generate(tenant, passRate);
        _devices[tenant.Id] = tenant.LastScanAt is null ? [] : GenerateDevices(tenant, passRate);
        return tenant;
    }

    private static Random StableRandom(string seed, int salt = 0) =>
        new(seed.Aggregate(17 + salt, (h, c) => unchecked(h * 31 + c)) & 0x7fffffff);

    private static IReadOnlyList<Finding> Generate(Tenant tenant, double passRate)
    {
        // Deterministic per tenant name so the demo looks the same on every run.
        // (string.GetHashCode is randomized per process, so hash the characters ourselves.)
        var stable = StableRandom(tenant.DisplayName);

        return Catalog.Select(check =>
        {
            var roll = stable.NextDouble();
            var status = roll < passRate ? FindingStatus.Passed
                : roll < passRate + 0.08 ? FindingStatus.Investigate
                : FindingStatus.Failed;

            return new Finding
            {
                Id = $"sample:{tenant.Id:N}:{check.Id}",
                TenantId = tenant.Id,
                Source = check.Category is "Email" or "Collaboration" ? "ScubaGear" : "Maester",
                SourceCheckId = check.Id,
                Title = check.Title,
                Category = check.Category,
                Severity = check.Severity,
                Status = status,
                Evidence = status == FindingStatus.Passed ? "Check passed." : check.Evidence,
                Remediation = check.Remediation,
                Frameworks = check.Frameworks,
                DetectedAt = tenant.LastScanAt ?? DateTimeOffset.UtcNow
            };
        }).ToList();
    }

    private sealed record SettingDef(string Setting, string FailDetail, bool IsEncryption = false, bool IsDefender = false);

    private sealed record PlatformDef(
        DevicePlatform Platform, double Share, string NamePart, string Policy,
        (string Manufacturer, string Model)[] Models, string[] OsVersions, SettingDef[] Settings);

    private static readonly PlatformDef[] Platforms =
    [
        new(DevicePlatform.Windows, 0.55, "LT", "Windows 11 baseline",
            [("Dell", "Latitude 5440"), ("HP", "EliteBook 840 G10"), ("Lenovo", "ThinkPad T14 Gen 4"), ("Microsoft", "Surface Laptop 5")],
            ["Windows 11 23H2 (22631.4317)", "Windows 11 24H2 (26100.2033)", "Windows 10 22H2 (19045.5011)"],
            [
                new("BitLocker drive encryption", "OS drive is not encrypted.", IsEncryption: true),
                new("Microsoft Defender Antivirus", "Real-time protection is turned off.", IsDefender: true),
                new("Firewall enabled", "Windows Firewall is off for the domain profile."),
                new("Minimum OS version 10.0.22631", "Running a build below the minimum supported version."),
                new("Secure Boot enabled", "Secure Boot is disabled in firmware."),
                new("Password required", "No sign-in password or Windows Hello PIN is set.")
            ]),
        new(DevicePlatform.MacOS, 0.10, "MB", "macOS baseline",
            [("Apple", "MacBook Air (M2, 2022)"), ("Apple", "MacBook Pro 14 (M3, 2023)")],
            ["macOS 14.6.1", "macOS 15.0.1"],
            [
                new("FileVault enabled", "FileVault is off.", IsEncryption: true),
                new("Firewall enabled", "Application firewall is off."),
                new("Gatekeeper enabled", "Apps from unidentified developers are allowed."),
                new("Minimum OS version 14.0", "Running a macOS version below the minimum.")
            ]),
        new(DevicePlatform.iOS, 0.20, "IP", "iOS baseline",
            [("Apple", "iPhone 14"), ("Apple", "iPhone 15 Pro"), ("Apple", "iPad (10th gen)")],
            ["iOS 17.6.1", "iOS 18.0.1"],
            [
                new("Jailbroken devices blocked", "Device reports as jailbroken."),
                new("Passcode required", "No passcode is set."),
                new("Minimum OS version 17.0", "Running an iOS version below the minimum.")
            ]),
        new(DevicePlatform.Android, 0.12, "AN", "Android Enterprise baseline",
            [("Samsung", "Galaxy S23"), ("Samsung", "Galaxy A54"), ("Google", "Pixel 8")],
            ["Android 14", "Android 13"],
            [
                new("Rooted devices blocked", "Device reports as rooted."),
                new("Storage encryption", "Storage is not encrypted.", IsEncryption: true),
                new("Google Play Protect", "Play Protect is turned off."),
                new("Minimum OS version 13", "Running an Android version below the minimum.")
            ]),
        new(DevicePlatform.Linux, 0.03, "WS", "Linux baseline",
            [("Dell", "OptiPlex 7010")],
            ["Ubuntu 22.04.5 LTS", "Ubuntu 24.04.1 LTS"],
            [
                new("Disk encryption (dm-crypt)", "Root partition is not encrypted.", IsEncryption: true),
                new("Password policy", "Password complexity requirements are not met.")
            ])
    ];

    private static readonly string[] People =
    [
        "Aisha Rahman", "Omar Haddad", "Fatima Al Mansoori", "Rahul Menon", "Sara Khoury", "Daniel Brooks",
        "Noura Saeed", "Yousef Karim", "Priya Nair", "Hassan Ali", "Maria Santos", "Khalid Nasser",
        "Layla Farouk", "James Whitfield", "Mariam Obaid", "Arjun Pillai", "Reem Al Hashimi", "Tariq Aziz"
    ];

    private static IReadOnlyList<ManagedDevice> GenerateDevices(Tenant tenant, double passRate)
    {
        var stable = StableRandom(tenant.DisplayName, salt: 101);
        var prefix = string.Concat(tenant.DisplayName.Split(' ').Select(w => char.ToUpperInvariant(w[0])));
        var mailDomain = tenant.PrimaryDomain;
        var failChance = (1 - passRate) * 0.12;
        var now = DateTimeOffset.UtcNow;
        var count = 10 + stable.Next(14);
        var devices = new List<ManagedDevice>(count);

        for (var i = 1; i <= count; i++)
        {
            var roll = stable.NextDouble();
            var platform = Platforms[^1];
            foreach (var p in Platforms)
            {
                if (roll < p.Share) { platform = p; break; }
                roll -= p.Share;
            }

            var (manufacturer, model) = platform.Models[stable.Next(platform.Models.Length)];
            var os = platform.OsVersions[stable.Next(platform.OsVersions.Length)];
            var person = People[stable.Next(People.Length)];
            var upn = $"{person.Split(' ')[0].ToLowerInvariant()}.{person.Split(' ')[^1].ToLowerInvariant()}@{mailDomain}";

            var settings = platform.Settings.Select(s =>
            {
                // Windows 10 always misses the Windows 11 minimum build.
                var ok = s.Setting.StartsWith("Minimum OS", StringComparison.Ordinal) && os.StartsWith("Windows 10", StringComparison.Ordinal)
                    ? false
                    : stable.NextDouble() >= failChance;
                return new DeviceComplianceSetting(platform.Policy, s.Setting, ok, ok ? null : s.FailDetail);
            }).ToList();

            var failing = settings.Count(s => !s.Compliant);
            var encryption = platform.Settings.Select((s, idx) => (s, idx)).FirstOrDefault(x => x.s.IsEncryption);
            var defender = platform.Settings.Select((s, idx) => (s, idx)).FirstOrDefault(x => x.s.IsDefender);

            var stale = stable.NextDouble() < 0.12;
            var mobile = platform.Platform is DevicePlatform.iOS or DevicePlatform.Android;
            var idBytes = new byte[16];
            stable.NextBytes(idBytes);

            devices.Add(new ManagedDevice
            {
                Id = new Guid(idBytes).ToString(),
                TenantId = tenant.Id,
                DeviceName = $"{prefix}-{platform.NamePart}-{i:D3}",
                UserDisplayName = person,
                UserPrincipalName = upn,
                Platform = platform.Platform,
                OsVersion = os,
                Manufacturer = manufacturer,
                Model = model,
                SerialNumber = string.Concat(Enumerable.Range(0, 10).Select(_ => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[stable.Next(32)])),
                Ownership = mobile && stable.NextDouble() < 0.5 ? DeviceOwnership.Personal : DeviceOwnership.Corporate,
                ComplianceState = failing == 0 ? DeviceComplianceState.Compliant
                    : stable.NextDouble() < 0.3 ? DeviceComplianceState.InGracePeriod
                    : DeviceComplianceState.Noncompliant,
                // iOS hardware encryption is always on and isn't reported as a setting.
                IsEncrypted = platform.Platform == DevicePlatform.iOS ? true
                    : encryption.s is null ? null
                    : settings[encryption.idx].Compliant,
                Defender = defender.s is not null
                    ? settings[defender.idx].Compliant ? DefenderState.Protected : DefenderState.Unhealthy
                    : stable.NextDouble() < 0.7 ? DefenderState.Protected : DefenderState.NotOnboarded,
                EnrolledAt = now.AddDays(-30 - stable.Next(670)),
                LastSyncAt = stale ? now.AddDays(-31 - stable.Next(40)) : now.AddMinutes(-stable.Next(60 * 48)),
                ComplianceSettings = settings
            });
        }

        return devices;
    }

    public Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<Tenant>>(_tenants);

    public Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default) =>
        Task.FromResult(_tenants.FirstOrDefault(t => t.Id == id));

    public Task<IReadOnlyList<Finding>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default) =>
        Task.FromResult(_findings.TryGetValue(tenantId, out var f) ? f : (IReadOnlyList<Finding>)[]);

    Task<IReadOnlyList<Finding>> IFindingRepository.GetAllAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<Finding>>(_findings.Values.SelectMany(f => f).ToList());

    Task<IReadOnlyList<ManagedDevice>> IDeviceRepository.GetForTenantAsync(Guid tenantId, CancellationToken ct) =>
        Task.FromResult(_devices.TryGetValue(tenantId, out var d) ? d : (IReadOnlyList<ManagedDevice>)[]);

    public Task<ManagedDevice?> GetAsync(Guid tenantId, string deviceId, CancellationToken ct = default) =>
        Task.FromResult(_devices.TryGetValue(tenantId, out var d) ? d.FirstOrDefault(x => x.Id == deviceId) : null);

    public Task SaveScanAsync(ScanResult result, CancellationToken ct = default)
    {
        if (result.Succeeded)
            _findings[result.TenantId] = result.Findings;
        return Task.CompletedTask;
    }
}

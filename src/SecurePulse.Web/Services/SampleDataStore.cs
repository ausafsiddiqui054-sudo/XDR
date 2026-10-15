using System.Collections.Concurrent;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Services;

/// <summary>
/// In-memory store seeded with fictional tenants and realistic M365 findings so the
/// portal can be designed and demoed before real scans exist. Replace with EF Core
/// repositories once the Worker starts writing real scan results.
/// </summary>
public sealed class SampleDataStore : ITenantRepository, IFindingRepository, IDeviceRepository, IOnboardingRepository, IPortalUserRepository, IAuditLog,
    IScanRunRepository, IDeviceActionRepository, IAuditExportStore, IPlaybookRepository
{
    private readonly List<DeviceActionRequest> _actions = [];
    private readonly List<RemediationPlaybook> _playbooks = [];
    private readonly List<ScanRun> _scanRuns = [];
    private readonly List<AuditEvent> _audit = [];
    private readonly List<PortalUser> _users = [];
    private readonly Lock _gate = new();
    private readonly Dictionary<Guid, (OnboardingRequest Request, string StateHash)> _onboarding = [];
    private readonly List<Tenant> _tenants;
    private readonly ConcurrentDictionary<Guid, IReadOnlyList<Finding>> _findings = new();
    private readonly ConcurrentDictionary<Guid, IReadOnlyList<ManagedDevice>> _devices = new();
    private readonly ConcurrentDictionary<Guid, DeviceSyncStatus> _syncStatus = new();

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
            // A sample thumbprint so the remediation tenant can take device action requests in demos.
            RemediationCredentialReference = consent == TenantConsentState.RemediationGranted ? "FEDCBA9876543210FEDCBA9876543210FEDCBA98" : null,
            LastScanAt = daysSinceScan is null ? null : DateTimeOffset.UtcNow.AddDays(-daysSinceScan.Value).AddHours(-3)
        };

        _findings[tenant.Id] = tenant.LastScanAt is null ? [] : Generate(tenant, passRate);
        if (tenant.LastScanAt is not null)
        {
            _devices[tenant.Id] = GenerateDevices(tenant, passRate);
            var syncedAt = DateTimeOffset.UtcNow.AddMinutes(-20);
            _syncStatus[tenant.Id] = new DeviceSyncStatus
            {
                TenantId = tenant.Id, LastAttemptAt = syncedAt, LastSuccessAt = syncedAt,
                Succeeded = true, DeviceCount = _devices[tenant.Id].Count
            };
        }
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
        var defenderRandom = StableRandom(tenant.DisplayName, salt: 202);
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

            // Platforms without a Defender compliance setting draw one value here (kept so the rest of the sample stays the same).
            var sensorRoll = defender.s is null ? stable.NextDouble() : defenderRandom.NextDouble();
            var (defenderState, defenderHealth) = SampleDefender(platform.Platform,
                defender.s is null ? null : settings[defender.idx].Compliant, sensorRoll, stale, now, defenderRandom);

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
                Defender = defenderState,
                DefenderDetails = defenderHealth,
                EnrolledAt = now.AddDays(-30 - stable.Next(670)),
                LastSyncAt = stale ? now.AddDays(-31 - stable.Next(40)) : now.AddMinutes(-stable.Next(60 * 48)),
                ComplianceSettings = settings
            });
        }

        return devices;
    }

    private static readonly string[] ExposureLevels = ["Low", "Low", "Medium", "Medium", "High"];

    private static string MachineId(Random random)
    {
        var bytes = new byte[20];
        random.NextBytes(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Defender data shaped like the Worker's (antivirus from Intune on Windows, sensor from advanced
    /// hunting), with its state worked out by the same <see cref="DefenderHealthEvaluator"/>.
    /// </summary>
    private static (DefenderState, DefenderHealth) SampleDefender(DevicePlatform platform, bool? realTimeOn, double sensorRoll, bool stale,
        DateTimeOffset now, Random random)
    {
        DefenderAntivirusStatus? antivirus = platform == DevicePlatform.Windows
            ? new DefenderAntivirusStatus
            {
                MalwareProtectionEnabled = true,
                RealTimeProtectionEnabled = realTimeOn ?? true,
                TamperProtectionEnabled = random.NextDouble() >= 0.06,
                SignaturesOutOfDate = stale || random.NextDouble() < 0.05,
                QuickScanOverdue = stale || random.NextDouble() < 0.1,
                RebootRequired = random.NextDouble() < 0.08,
                ThreatState = random.NextDouble() < 0.03 ? DefenderThreatState.RebootPending : DefenderThreatState.Clean,
                SignatureVersion = $"1.419.{150 + random.Next(80)}.0",
                EngineVersion = "1.1.24090.11",
                LastQuickScanAt = now.AddHours(-2 - random.Next(70)),
                LastReportedAt = now.AddHours(-random.Next(30))
            }
            : null;

        // Most Windows PCs are onboarded; Macs, Linux and phones less often.
        var onboardedShare = platform == DevicePlatform.Windows ? 0.9 : 0.7;
        DefenderSensorStatus? sensor = sensorRoll < onboardedShare
            ? new DefenderSensorStatus
            {
                MachineId = MachineId(random),
                Onboarding = DefenderOnboarding.Onboarded,
                Health = stale ? DefenderSensorHealth.Inactive
                    : random.NextDouble() < 0.04 ? DefenderSensorHealth.ImpairedCommunication
                    : DefenderSensorHealth.Active,
                ExposureLevel = ExposureLevels[random.Next(ExposureLevels.Length)],
                LastSeenAt = stale ? now.AddDays(-20 - random.Next(9)) : now.AddHours(-random.Next(24))
            }
            : platform == DevicePlatform.Windows && sensorRoll < 0.95
                ? new DefenderSensorStatus { Onboarding = DefenderOnboarding.CanBeOnboarded, LastSeenAt = now.AddDays(-random.Next(5)) }
                : null;

        return DefenderHealthEvaluator.Evaluate(platform, antivirus, sensor, sensorDataAvailable: true);
    }

    public Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default)
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<Tenant>>(_tenants.ToList());
    }

    public Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default)
    {
        lock (_gate) return Task.FromResult(_tenants.FirstOrDefault(t => t.Id == id));
    }

    public Task<IReadOnlyList<Finding>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default) =>
        Task.FromResult(_findings.TryGetValue(tenantId, out var f) ? f : (IReadOnlyList<Finding>)[]);

    Task<IReadOnlyList<Finding>> IFindingRepository.GetAllAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<Finding>>(_findings.Values.SelectMany(f => f).ToList());

    Task<IReadOnlyList<ManagedDevice>> IDeviceRepository.GetForTenantAsync(Guid tenantId, CancellationToken ct) =>
        Task.FromResult(_devices.TryGetValue(tenantId, out var d) ? d : (IReadOnlyList<ManagedDevice>)[]);

    public Task<ManagedDevice?> GetAsync(Guid tenantId, string deviceId, CancellationToken ct = default) =>
        Task.FromResult(_devices.TryGetValue(tenantId, out var d) ? d.FirstOrDefault(x => x.Id == deviceId) : null);

    public Task SaveSyncAsync(DeviceSyncResult result, CancellationToken ct = default)
    {
        if (result.Succeeded)
            _devices[result.TenantId] = result.Devices;
        _syncStatus.TryGetValue(result.TenantId, out var previous);
        _syncStatus[result.TenantId] = new DeviceSyncStatus
        {
            TenantId = result.TenantId,
            LastAttemptAt = result.CompletedAt,
            LastSuccessAt = result.Succeeded ? result.CompletedAt : previous?.LastSuccessAt,
            Succeeded = result.Succeeded,
            Error = result.Error,
            Warning = result.Succeeded ? result.Warning : previous?.Warning,
            DeviceCount = _devices.TryGetValue(result.TenantId, out var d) ? d.Count : 0
        };
        return Task.CompletedTask;
    }

    public Task<DeviceSyncStatus?> GetSyncStatusAsync(Guid tenantId, CancellationToken ct = default) =>
        Task.FromResult(_syncStatus.TryGetValue(tenantId, out var s) ? s : null);

    // --- Onboarding (in memory; mirrors EfOnboardingRepository) ------------------------------

    public Task AddAsync(OnboardingRequest request, string stateHash, CancellationToken ct = default)
    {
        lock (_gate) _onboarding.Add(request.Id, (request, stateHash));
        return Task.CompletedTask;
    }

    Task<OnboardingRequest?> IOnboardingRepository.GetAsync(Guid id, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_onboarding.TryGetValue(id, out var e) ? e.Request : null);
    }

    public Task<OnboardingRequest?> FindByStateHashAsync(string stateHash, CancellationToken ct = default)
    {
        lock (_gate) return Task.FromResult<OnboardingRequest?>(_onboarding.Values.FirstOrDefault(e => e.StateHash == stateHash).Request);
    }

    public Task<IReadOnlyList<OnboardingRequest>> GetOpenAsync(CancellationToken ct = default)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<OnboardingRequest>>(_onboarding.Values.Select(e => e.Request)
                .Where(r => r.Status is OnboardingStatus.AwaitingConsent or OnboardingStatus.Verifying or OnboardingStatus.Failed)
                .OrderByDescending(r => r.CreatedAt).ToList());
    }

    public Task<IReadOnlyList<OnboardingRequest>> GetVerifyingAsync(CancellationToken ct = default)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<OnboardingRequest>>(_onboarding.Values.Select(e => e.Request)
                .Where(r => r.Status == OnboardingStatus.Verifying).ToList());
    }

    public Task<bool> MarkConsentReceivedAsync(Guid id, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (!_onboarding.TryGetValue(id, out var e) || e.Request.Status != OnboardingStatus.AwaitingConsent || e.Request.ExpiresAt <= at)
                return Task.FromResult(false);
            _onboarding[id] = (e.Request with { Status = OnboardingStatus.Verifying, ConsentReceivedAt = at, LastError = null }, e.StateHash);
            return Task.FromResult(true);
        }
    }

    public Task SetErrorAsync(Guid id, string error, CancellationToken ct = default)
    {
        Update(id, r => r with { LastError = error });
        return Task.CompletedTask;
    }

    public Task RecordVerificationFailureAsync(Guid id, string error, bool final, CancellationToken ct = default)
    {
        Update(id, r => r.Status != OnboardingStatus.Verifying ? r : r with
        {
            LastError = error,
            Status = final ? OnboardingStatus.Failed : OnboardingStatus.Verifying,
            VerificationAttempts = r.VerificationAttempts + 1
        });
        return Task.CompletedTask;
    }

    public Task<Tenant> CompleteAsync(Guid id, Tenant tenant, IReadOnlyList<string> grantedPermissions, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (!_onboarding.TryGetValue(id, out var e) || e.Request.Status != OnboardingStatus.Verifying)
                throw new InvalidOperationException($"Onboarding request {id} is not verifying.");
            if (e.Request.Kind != OnboardingKind.Assessment)
                throw new InvalidOperationException($"Onboarding request {id} is a {e.Request.Kind} request; use CompleteRemediationAsync.");

            var index = _tenants.FindIndex(t => t.EntraTenantId == tenant.EntraTenantId);
            Tenant stored;
            if (index < 0)
            {
                stored = tenant;
                _tenants.Add(stored);
            }
            else
            {
                var existing = _tenants[index];
                stored = existing with
                {
                    CredentialReference = tenant.CredentialReference,
                    ConsentState = existing.ConsentState == TenantConsentState.RemediationGranted ? existing.ConsentState : tenant.ConsentState
                };
                _tenants[index] = stored;
            }

            _onboarding[id] = (e.Request with
            {
                Status = OnboardingStatus.Completed, CompletedAt = at, TenantId = stored.Id, LastError = null,
                GrantedPermissions = grantedPermissions, ProtectedState = null
            }, e.StateHash);
            return Task.FromResult(stored);
        }
    }

    public Task<Tenant?> CompleteRemediationAsync(Guid id, string remediationCredentialReference, IReadOnlyList<string> grantedPermissions,
        DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (!_onboarding.TryGetValue(id, out var e) || e.Request.Status != OnboardingStatus.Verifying || e.Request.Kind != OnboardingKind.Remediation)
                throw new InvalidOperationException($"Onboarding request {id} isn't a remediation request being verified.");

            var index = _tenants.FindIndex(t => t.EntraTenantId == e.Request.EntraTenantId
                && t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted);
            if (index < 0)
            {
                _onboarding[id] = (e.Request with
                {
                    Status = OnboardingStatus.Failed, ProtectedState = null,
                    LastError = "The tenant isn't connected for assessment any more, so remediation access can't be added."
                }, e.StateHash);
                return Task.FromResult<Tenant?>(null);
            }

            var stored = _tenants[index] with { ConsentState = TenantConsentState.RemediationGranted, RemediationCredentialReference = remediationCredentialReference };
            _tenants[index] = stored;
            _onboarding[id] = (e.Request with
            {
                Status = OnboardingStatus.Completed, CompletedAt = at, TenantId = stored.Id, LastError = null,
                GrantedPermissions = grantedPermissions, ProtectedState = null
            }, e.StateHash);
            return Task.FromResult<Tenant?>(stored);
        }
    }

    public Task<bool> SetWazuhAgentGroupAsync(Guid tenantId, string? group, CancellationToken ct = default)
    {
        if (group is not null && WazuhAgentGroups.Problem(group) is { } problem) throw new ArgumentException(problem, nameof(group));
        lock (_gate)
        {
            var index = _tenants.FindIndex(t => t.Id == tenantId);
            if (index < 0) throw new KeyNotFoundException($"Tenant {tenantId} not found.");
            if (group is not null && _tenants.Any(t => t.Id != tenantId && t.WazuhAgentGroup == group)) return Task.FromResult(false);
            _tenants[index] = _tenants[index] with { WazuhAgentGroup = group };
            return Task.FromResult(true);
        }
    }

    public Task SetGoPhishEnabledAsync(Guid tenantId, bool enabled, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var index = _tenants.FindIndex(t => t.Id == tenantId);
            if (index < 0) throw new KeyNotFoundException($"Tenant {tenantId} not found.");
            _tenants[index] = _tenants[index] with { GoPhishEnabled = enabled };
            return Task.CompletedTask;
        }
    }

    public Task<bool> DisableRemediationAsync(Guid tenantId, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var index = _tenants.FindIndex(t => t.Id == tenantId && t.ConsentState == TenantConsentState.RemediationGranted);
            if (index < 0) return Task.FromResult(false);
            _tenants[index] = _tenants[index] with { ConsentState = TenantConsentState.ReadOnlyGranted, RemediationCredentialReference = null };
            return Task.FromResult(true);
        }
    }

    public Task CancelAsync(Guid id, CancellationToken ct = default)
    {
        Update(id, r => r.Status is OnboardingStatus.AwaitingConsent or OnboardingStatus.Failed
            ? r with { Status = OnboardingStatus.Cancelled, ProtectedState = null }
            : r);
        return Task.CompletedTask;
    }

    private void Update(Guid id, Func<OnboardingRequest, OnboardingRequest> change)
    {
        lock (_gate)
        {
            if (_onboarding.TryGetValue(id, out var e))
                _onboarding[id] = (change(e.Request), e.StateHash);
        }
    }

    // --- Portal users (in memory; mirrors EfPortalUserRepository) -----------------------------

    Task<IReadOnlyList<PortalUser>> IPortalUserRepository.GetAllAsync(CancellationToken ct)
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<PortalUser>>(_users.OrderBy(u => u.Role).ThenBy(u => u.UserPrincipalName).ToList());
    }

    Task<PortalUser?> IPortalUserRepository.GetAsync(Guid id, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_users.FirstOrDefault(u => u.Id == id));
    }

    public Task<PortalUser?> FindByObjectIdAsync(Guid entraTenantId, Guid objectId, CancellationToken ct = default)
    {
        lock (_gate) return Task.FromResult(_users.FirstOrDefault(u => u.EntraTenantId == entraTenantId && u.ObjectId == objectId));
    }

    public Task<PortalUser?> SignInAsync(Guid entraTenantId, Guid objectId, string? userPrincipalName, string? displayName,
        DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var upn = userPrincipalName?.Trim().ToLowerInvariant();
            var index = _users.FindIndex(u => u.EntraTenantId == entraTenantId && u.ObjectId == objectId);
            if (index < 0 && !string.IsNullOrEmpty(upn))
                index = _users.FindIndex(u => u.EntraTenantId == entraTenantId && u.UserPrincipalName == upn && u.ObjectId is null);
            if (index < 0) return Task.FromResult<PortalUser?>(null);

            var user = _users[index] with
            {
                ObjectId = objectId,
                LastSignInAt = at,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? _users[index].DisplayName : displayName.Trim()
            };
            _users[index] = user;
            return Task.FromResult<PortalUser?>(user);
        }
    }

    Task IPortalUserRepository.AddAsync(PortalUser user, CancellationToken ct)
    {
        lock (_gate)
        {
            var upn = user.UserPrincipalName.Trim().ToLowerInvariant();
            if (_users.Any(u => u.EntraTenantId == user.EntraTenantId && u.UserPrincipalName == upn))
                throw new DuplicatePortalUserException();
            _users.Add(user with { UserPrincipalName = upn });
        }
        return Task.CompletedTask;
    }

    public Task UpdateRoleAsync(Guid id, PortalRole role, Guid? clientTenantId, CancellationToken ct = default)
    {
        ChangeUsers(id, (list, i) => list[i] = list[i] with { Role = role, ClientTenantId = role == PortalRole.ClientViewer ? clientTenantId : null });
        return Task.CompletedTask;
    }

    public Task RemoveAsync(Guid id, CancellationToken ct = default)
    {
        ChangeUsers(id, (list, i) => list.RemoveAt(i));
        return Task.CompletedTask;
    }

    private void ChangeUsers(Guid id, Action<List<PortalUser>, int> change)
    {
        lock (_gate)
        {
            var index = _users.FindIndex(u => u.Id == id);
            if (index < 0) return;
            var copy = _users.ToList();
            change(copy, index);
            if (!copy.Any(u => u.Role == PortalRole.Owner && u.ObjectId is not null)) throw new LastOwnerException();
            _users.Clear();
            _users.AddRange(copy);
        }
    }

    // --- Audit log (in memory, append-only; mirrors EfAuditLog) -------------------------------

    public Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default)
    {
        lock (_gate) _audit.Add(auditEvent);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery q, CancellationToken ct = default)
    {
        lock (_gate)
        {
            IEnumerable<AuditEvent> rows = _audit;
            if (q.From is { } from) rows = rows.Where(e => e.OccurredAt >= from);
            if (q.To is { } to) rows = rows.Where(e => e.OccurredAt < to);
            if (!string.IsNullOrEmpty(q.Category)) rows = rows.Where(e => e.Category == q.Category);
            if (!string.IsNullOrEmpty(q.Action)) rows = rows.Where(e => e.Action == q.Action);
            if (q.Outcome is { } outcome) rows = rows.Where(e => e.Outcome == outcome);
            if (q.TenantId is { } tenantId) rows = rows.Where(e => e.TenantId == tenantId);
            if (!string.IsNullOrWhiteSpace(q.Search))
            {
                var term = q.Search.Trim();
                rows = rows.Where(e => e.ActorName.Contains(term, StringComparison.OrdinalIgnoreCase)
                                       || e.Summary.Contains(term, StringComparison.OrdinalIgnoreCase));
            }
            if (q.Before is { } before)
                rows = rows.Where(e => e.OccurredAt < before.OccurredAt || (e.OccurredAt == before.OccurredAt && e.Id.CompareTo(before.Id) < 0));

            return Task.FromResult<IReadOnlyList<AuditEvent>>(rows.OrderByDescending(e => e.OccurredAt).ThenByDescending(e => e.Id)
                .Take(Math.Clamp(q.Limit, 1, 1000)).ToList());
        }
    }

    // --- Audit export (the sample portal never exports; the status can be set for demos and tests) ---

    public AuditExportStatus? ExportStatus { get; set; }

    public Task<IAuditExportLease?> TryLeaseAsync(string destination, TimeSpan lag, int maxEvents, CancellationToken ct = default) =>
        Task.FromResult<IAuditExportLease?>(null);

    public Task RecordFailureAsync(string destination, string error, CancellationToken ct = default) => Task.CompletedTask;

    public Task<AuditExportStatus?> GetStatusAsync(string destination, CancellationToken ct = default) =>
        Task.FromResult(ExportStatus?.Destination == destination ? ExportStatus : null);

    // --- Scan queue (in memory; mirrors EfScanRunRepository) ---------------------------------

    public Task<(ScanRun Run, bool Created)> EnqueueAsync(Guid tenantId, string engine, ScanTrigger trigger, string? requestedBy,
        DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_scanRuns.FirstOrDefault(r => r.TenantId == tenantId && r.Engine == engine && r.IsActive) is { } active)
                return Task.FromResult((active, false));
            var run = new ScanRun
            {
                Id = Guid.NewGuid(), TenantId = tenantId, Engine = engine, Trigger = trigger, Status = ScanRunStatus.Queued,
                QueuedAt = at, RequestedBy = requestedBy
            };
            _scanRuns.Add(run);
            return Task.FromResult((run, true));
        }
    }

    public Task<ScanRun?> ClaimNextAsync(IReadOnlyCollection<string> engines, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var next = _scanRuns.Where(r => r.Status == ScanRunStatus.Queued && engines.Contains(r.Engine))
                .OrderBy(r => r.Trigger == ScanTrigger.Manual ? 0 : 1).ThenBy(r => r.QueuedAt).FirstOrDefault();
            if (next is null) return Task.FromResult<ScanRun?>(null);
            var claimed = next with { Status = ScanRunStatus.Running, StartedAt = at };
            _scanRuns[_scanRuns.IndexOf(next)] = claimed;
            return Task.FromResult<ScanRun?>(claimed);
        }
    }

    public Task CompleteAsync(Guid runId, bool succeeded, int? findingCount, string? error, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var index = _scanRuns.FindIndex(r => r.Id == runId && r.Status == ScanRunStatus.Running);
            if (index >= 0)
                _scanRuns[index] = _scanRuns[index] with
                {
                    Status = succeeded ? ScanRunStatus.Succeeded : ScanRunStatus.Failed, CompletedAt = at, FindingCount = findingCount, Error = error
                };
        }
        return Task.CompletedTask;
    }

    public Task<int> FailStaleAsync(DateTimeOffset startedBefore, string error, DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var stale = _scanRuns.Where(r => r.Status == ScanRunStatus.Running && r.StartedAt < startedBefore).ToList();
            foreach (var r in stale)
                _scanRuns[_scanRuns.IndexOf(r)] = r with { Status = ScanRunStatus.Failed, CompletedAt = at, Error = error };
            return Task.FromResult(stale.Count);
        }
    }

    public Task<IReadOnlyList<ScanRun>> GetLatestAsync(CancellationToken ct = default)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<ScanRun>>(_scanRuns.GroupBy(r => (r.TenantId, r.Engine))
                .Select(g => g.OrderByDescending(r => r.QueuedAt).First()).ToList());
    }

    /// <summary>Everything the store holds, for seeding a real database in development.</summary>
    public (IReadOnlyList<Tenant> Tenants, IReadOnlyList<Finding> Findings, IReadOnlyList<ManagedDevice> Devices) Snapshot() =>
        (_tenants, _findings.Values.SelectMany(f => f).ToList(), _devices.Values.SelectMany(d => d).ToList());

    public Task SaveScanAsync(ScanResult result, CancellationToken ct = default)
    {
        // Like the database: a scan replaces only its own engine's findings.
        if (result.Succeeded)
            _findings[result.TenantId] = _findings.GetValueOrDefault(result.TenantId, [])
                .Where(f => f.Source != result.Source).Concat(result.Findings).ToList();
        return Task.CompletedTask;
    }

    // --- Device actions (same rules as the database: conditional transitions, one open action per device) ---

    public Task<(DeviceActionRequest Request, bool Created)> AddAsync(DeviceActionRequest request, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_actions.FirstOrDefault(a => a.TenantId == request.TenantId && a.DeviceId == request.DeviceId && a.IsOpen) is { } open)
                return Task.FromResult((open, false));
            _actions.Add(request);
            return Task.FromResult((request, true));
        }
    }

    Task<DeviceActionRequest?> IDeviceActionRepository.GetAsync(Guid id, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_actions.FirstOrDefault(a => a.Id == id));
    }

    public Task<IReadOnlySet<string>> GetPlaybookDevicesSinceAsync(Guid playbookId, Guid tenantId, DateTimeOffset since, CancellationToken ct = default)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlySet<string>>(_actions
                .Where(a => a.PlaybookId == playbookId && a.TenantId == tenantId && a.RequestedAt >= since)
                .Select(a => a.DeviceId).ToHashSet(StringComparer.Ordinal));
    }

    // --- Remediation playbooks ---------------------------------------------------------------------

    Task<IReadOnlyList<RemediationPlaybook>> IPlaybookRepository.GetAllAsync(CancellationToken ct)
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<RemediationPlaybook>>(_playbooks.OrderBy(p => p.Name, StringComparer.Ordinal).ToList());
    }

    Task<RemediationPlaybook?> IPlaybookRepository.GetAsync(Guid id, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_playbooks.FirstOrDefault(p => p.Id == id));
    }

    Task IPlaybookRepository.AddAsync(RemediationPlaybook playbook, CancellationToken ct)
    {
        lock (_gate) _playbooks.Add(playbook);
        return Task.CompletedTask;
    }

    Task<bool> IPlaybookRepository.UpdateAsync(RemediationPlaybook playbook, DateTimeOffset expectedUpdatedAt, CancellationToken ct)
    {
        lock (_gate)
        {
            var index = _playbooks.FindIndex(p => p.Id == playbook.Id && p.UpdatedAt == expectedUpdatedAt);
            if (index < 0) return Task.FromResult(false);
            _playbooks[index] = playbook with { CreatedAt = _playbooks[index].CreatedAt, LastRunAt = _playbooks[index].LastRunAt };
            return Task.FromResult(true);
        }
    }

    Task<bool> IPlaybookRepository.GrantPreApprovalAsync(Guid id, DateTimeOffset expectedUpdatedAt, Guid byUserId, string byName, DateTimeOffset at,
        DateTimeOffset expiresAt, CancellationToken ct)
    {
        lock (_gate)
        {
            var index = _playbooks.FindIndex(p => p.Id == id && p.UpdatedAt == expectedUpdatedAt && p.UpdatedByUserId != byUserId);
            if (index < 0) return Task.FromResult(false);
            _playbooks[index] = _playbooks[index] with
            {
                PreApprovedByUserId = byUserId, PreApprovedByName = byName, PreApprovedAt = at, PreApprovalExpiresAt = expiresAt
            };
            return Task.FromResult(true);
        }
    }

    Task<bool> IPlaybookRepository.WithdrawPreApprovalAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            var index = _playbooks.FindIndex(p => p.Id == id && p.PreApprovedByUserId is not null);
            if (index < 0) return Task.FromResult(false);
            _playbooks[index] = _playbooks[index] with { PreApprovedByUserId = null, PreApprovedByName = null, PreApprovedAt = null, PreApprovalExpiresAt = null };
            return Task.FromResult(true);
        }
    }

    Task<bool> IPlaybookRepository.DeleteAsync(Guid id, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_playbooks.RemoveAll(p => p.Id == id) > 0);
    }

    Task IPlaybookRepository.RecordRunAsync(Guid id, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate)
        {
            var index = _playbooks.FindIndex(p => p.Id == id);
            if (index >= 0) _playbooks[index] = _playbooks[index] with { LastRunAt = at };
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<DeviceActionRequest>> QueryAsync(DeviceActionQuery query, CancellationToken ct = default)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<DeviceActionRequest>>(_actions
                .Where(a => (query.TenantId is null || a.TenantId == query.TenantId)
                            && (query.DeviceId is null || a.DeviceId == query.DeviceId)
                            && (!query.OpenOnly || a.IsOpen))
                .OrderByDescending(a => a.RequestedAt).ThenBy(a => a.Id)
                .Take(Math.Clamp(query.Limit, 1, 1000))
                .ToList());
        }
    }

    public Task<DeviceActionRequest?> DecideAsync(Guid id, bool approve, Guid deciderId, string deciderName, PortalRole deciderRole, string? note,
        DateTimeOffset at, CancellationToken ct = default) =>
        Transition(id, a => a.Status == DeviceActionStatus.PendingApproval && a.ExpiresAt > at, a => a with
        {
            Status = approve ? DeviceActionStatus.Approved : DeviceActionStatus.Rejected,
            DecidedAt = at, DecidedByUserId = deciderId, DecidedByName = deciderName, DecidedByRole = deciderRole, DecisionNote = note
        });

    public Task<DeviceActionRequest?> AutoApproveAsync(Guid id, Guid deciderId, string deciderName, string note, DateTimeOffset at,
        CancellationToken ct = default) =>
        Transition(id, a => a.Status == DeviceActionStatus.PendingApproval && a.ExpiresAt > at && a.PlaybookId is not null, a => a with
        {
            Status = DeviceActionStatus.Approved, AutoApproved = true,
            DecidedAt = at, DecidedByUserId = deciderId, DecidedByName = deciderName, DecidedByRole = PortalRole.Owner, DecisionNote = note
        });

    public Task<int> CountAutoApprovedSinceAsync(Guid playbookId, Guid tenantId, DateTimeOffset since, CancellationToken ct = default)
    {
        lock (_gate)
            return Task.FromResult(_actions.Count(a => a.PlaybookId == playbookId && a.TenantId == tenantId && a.AutoApproved && a.RequestedAt >= since));
    }

    public Task<DeviceActionRequest?> CancelAsync(Guid id, string cancelledBy, string? reason, DateTimeOffset at, CancellationToken ct = default) =>
        Transition(id, a => a.Status is DeviceActionStatus.PendingApproval or DeviceActionStatus.Approved,
            a => a with { Status = DeviceActionStatus.Cancelled, CancelledAt = at, CancelledBy = cancelledBy, Error = reason });

    public Task<IReadOnlyList<DeviceActionRequest>> CancelOpenForTenantAsync(Guid tenantId, string cancelledBy, string reason, DateTimeOffset at,
        CancellationToken ct = default) =>
        TransitionAll(a => a.TenantId == tenantId && a.Status is DeviceActionStatus.PendingApproval or DeviceActionStatus.Approved,
            a => a with { Status = DeviceActionStatus.Cancelled, CancelledAt = at, CancelledBy = cancelledBy, Error = reason });

    public Task<DeviceActionRequest?> ClaimNextApprovedAsync(DateTimeOffset at, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var next = _actions.Where(a => a.Status == DeviceActionStatus.Approved).OrderBy(a => a.DecidedAt).FirstOrDefault();
            if (next is null) return Task.FromResult<DeviceActionRequest?>(null);
            var claimed = next with { Status = DeviceActionStatus.Sending, SentAt = at };
            _actions[_actions.IndexOf(next)] = claimed;
            return Task.FromResult<DeviceActionRequest?>(claimed);
        }
    }

    public async Task CompleteAsync(Guid id, bool succeeded, string? error, DateTimeOffset at, CancellationToken ct = default) =>
        await Transition(id, a => a.Status == DeviceActionStatus.Sending,
            a => a with { Status = succeeded ? DeviceActionStatus.Sent : DeviceActionStatus.Failed, CompletedAt = at, Error = error });

    public async Task<IReadOnlyList<DeviceActionRequest>> ExpireAsync(DateTimeOffset at, TimeSpan sendWindow, DateTimeOffset sendingBefore,
        CancellationToken ct = default)
    {
        var expired = await TransitionAll(
            a => (a.Status == DeviceActionStatus.PendingApproval && a.ExpiresAt <= at)
                 || (a.Status == DeviceActionStatus.Approved && a.DecidedAt < at - sendWindow),
            a => a with
            {
                Status = DeviceActionStatus.Expired, CompletedAt = at,
                Error = a.Status == DeviceActionStatus.PendingApproval
                    ? SecurePulse.Data.EfDeviceActionRepository.ExpiredPendingMessage
                    : SecurePulse.Data.EfDeviceActionRepository.ExpiredApprovedMessage
            });
        var stuck = await TransitionAll(a => a.Status == DeviceActionStatus.Sending && a.SentAt < sendingBefore,
            a => a with { Status = DeviceActionStatus.Failed, CompletedAt = at, Error = SecurePulse.Data.EfDeviceActionRepository.StuckSendingMessage });
        return [.. expired, .. stuck];
    }

    private Task<DeviceActionRequest?> Transition(Guid id, Func<DeviceActionRequest, bool> when, Func<DeviceActionRequest, DeviceActionRequest> change)
    {
        lock (_gate)
        {
            var index = _actions.FindIndex(a => a.Id == id && when(a));
            if (index < 0) return Task.FromResult<DeviceActionRequest?>(null);
            _actions[index] = change(_actions[index]);
            return Task.FromResult<DeviceActionRequest?>(_actions[index]);
        }
    }

    private Task<IReadOnlyList<DeviceActionRequest>> TransitionAll(Func<DeviceActionRequest, bool> when, Func<DeviceActionRequest, DeviceActionRequest> change)
    {
        lock (_gate)
        {
            var changed = new List<DeviceActionRequest>();
            for (var i = 0; i < _actions.Count; i++)
            {
                if (!when(_actions[i])) continue;
                _actions[i] = change(_actions[i]);
                changed.Add(_actions[i]);
            }
            return Task.FromResult<IReadOnlyList<DeviceActionRequest>>(changed);
        }
    }
}

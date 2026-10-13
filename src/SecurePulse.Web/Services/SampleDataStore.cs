using System.Collections.Concurrent;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Services;

/// <summary>
/// In-memory store seeded with fictional tenants and realistic M365 findings so the
/// portal can be designed and demoed before real scans exist. Replace with EF Core
/// repositories once the Worker starts writing real scan results.
/// </summary>
public sealed class SampleDataStore : ITenantRepository, IFindingRepository
{
    private readonly List<Tenant> _tenants;
    private readonly ConcurrentDictionary<Guid, IReadOnlyList<Finding>> _findings = new();

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
        return tenant;
    }

    private static IReadOnlyList<Finding> Generate(Tenant tenant, double passRate)
    {
        // Deterministic per tenant name so the demo looks the same on every run.
        // (string.GetHashCode is randomized per process, so hash the characters ourselves.)
        var stable = new Random(tenant.DisplayName.Aggregate(17, (h, c) => unchecked(h * 31 + c)) & 0x7fffffff);

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

    public Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<Tenant>>(_tenants);

    public Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default) =>
        Task.FromResult(_tenants.FirstOrDefault(t => t.Id == id));

    public Task<IReadOnlyList<Finding>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default) =>
        Task.FromResult(_findings.TryGetValue(tenantId, out var f) ? f : (IReadOnlyList<Finding>)[]);

    Task<IReadOnlyList<Finding>> IFindingRepository.GetAllAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<Finding>>(_findings.Values.SelectMany(f => f).ToList());

    public Task SaveScanAsync(ScanResult result, CancellationToken ct = default)
    {
        if (result.Succeeded)
            _findings[result.TenantId] = result.Findings;
        return Task.CompletedTask;
    }
}

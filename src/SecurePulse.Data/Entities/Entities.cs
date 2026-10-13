using SecurePulse.Core.Models;

namespace SecurePulse.Data.Entities;

// Persistence shapes. Kept separate from the Core records so Core stays free of EF concerns;
// EntityMapping converts between the two.

public sealed class TenantEntity
{
    public Guid Id { get; set; }
    public Guid EntraTenantId { get; set; }
    public string DisplayName { get; set; } = "";
    public string PrimaryDomain { get; set; } = "";
    public string? PartnerName { get; set; }
    public string Industry { get; set; } = "General";

    /// <summary>Certificate thumbprint or vault reference only. Never a secret.</summary>
    public string? CredentialReference { get; set; }

    public TenantConsentState ConsentState { get; set; }
    public DateTimeOffset? LastScanAt { get; set; }
}

public sealed class FindingEntity
{
    public string Id { get; set; } = "";
    public Guid TenantId { get; set; }
    public string Source { get; set; } = "";
    public string? SourceCheckId { get; set; }
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public string Category { get; set; } = "General";
    public Severity Severity { get; set; }
    public FindingStatus Status { get; set; }
    public string? Evidence { get; set; }
    public string? Remediation { get; set; }
    public string? HelpUrl { get; set; }
    public string[] Frameworks { get; set; } = [];
    public string[] Tags { get; set; } = [];
    public DateTimeOffset DetectedAt { get; set; }
}

public sealed class ManagedDeviceEntity
{
    public Guid TenantId { get; set; }
    public string Id { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public string? UserDisplayName { get; set; }
    public string? UserPrincipalName { get; set; }
    public DevicePlatform Platform { get; set; }
    public string? OsVersion { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? SerialNumber { get; set; }
    public DeviceOwnership Ownership { get; set; }
    public DeviceComplianceState ComplianceState { get; set; }
    public bool? IsEncrypted { get; set; }
    public DefenderState Defender { get; set; }
    public DateTimeOffset? EnrolledAt { get; set; }
    public DateTimeOffset? LastSyncAt { get; set; }
    public List<ComplianceSettingEntity> ComplianceSettings { get; set; } = [];
}

/// <summary>Stored as JSON inside the device row.</summary>
public sealed class ComplianceSettingEntity
{
    public string Policy { get; set; } = "";
    public string Setting { get; set; } = "";
    public bool Compliant { get; set; }
    public string? Detail { get; set; }
}

public sealed class DeviceSyncStatusEntity
{
    public Guid TenantId { get; set; }
    public DateTimeOffset LastAttemptAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public bool Succeeded { get; set; }
    public string? Error { get; set; }
    public int DeviceCount { get; set; }
}

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

    /// <summary>Remediation app certificate thumbprint. A reference only, never a secret.</summary>
    public string? RemediationCredentialReference { get; set; }

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

public sealed class OnboardingRequestEntity
{
    public Guid Id { get; set; }
    public OnboardingKind Kind { get; set; }
    public string DisplayName { get; set; } = "";
    public string PrimaryDomain { get; set; } = "";
    public string? PartnerName { get; set; }
    public string Industry { get; set; } = "General";
    public Guid EntraTenantId { get; set; }
    public OnboardingStatus Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsentReceivedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public Guid? TenantId { get; set; }
    public string? LastError { get; set; }
    public string? StartedBy { get; set; }
    public string[] GrantedPermissions { get; set; } = [];
    public int VerificationAttempts { get; set; }

    /// <summary>SHA-256 (hex) of the consent state. The raw state is never stored.</summary>
    public string StateHash { get; set; } = "";

    /// <summary>State encrypted with the portal's data-protection keys, for re-showing the link.</summary>
    public string? ProtectedState { get; set; }
}

public sealed class PortalUserEntity
{
    public Guid Id { get; set; }
    public PortalRole Role { get; set; }
    public Guid EntraTenantId { get; set; }
    public string UserPrincipalName { get; set; } = "";
    public Guid? ObjectId { get; set; }
    public string? DisplayName { get; set; }
    public Guid? ClientTenantId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset? LastSignInAt { get; set; }
}

/// <summary>Append-only; a database trigger rejects UPDATE and DELETE.</summary>
public sealed class AuditEventEntity
{
    public Guid Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string Action { get; set; } = "";
    public string Category { get; set; } = "";
    public AuditOutcome Outcome { get; set; }
    public Guid? ActorUserId { get; set; }
    public string ActorName { get; set; } = "";
    public Guid? TenantId { get; set; }
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }
    public string Summary { get; set; } = "";
    public Dictionary<string, string> Details { get; set; } = [];
    public string? IpAddress { get; set; }
}

public sealed class ScanRunEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Engine { get; set; } = "";
    public ScanTrigger Trigger { get; set; }
    public ScanRunStatus Status { get; set; }
    public DateTimeOffset QueuedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public string? RequestedBy { get; set; }
    public int? FindingCount { get; set; }
    public string? Error { get; set; }
}

public sealed class DeviceActionEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string DeviceId { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public DeviceAction Action { get; set; }
    public string Reason { get; set; } = "";
    public DeviceActionStatus Status { get; set; }
    public DateTimeOffset RequestedAt { get; set; }
    public Guid RequestedByUserId { get; set; }
    public string RequestedByName { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
    public Guid? DecidedByUserId { get; set; }
    public string? DecidedByName { get; set; }
    public PortalRole? DecidedByRole { get; set; }
    public string? DecisionNote { get; set; }
    public DateTimeOffset? CancelledAt { get; set; }
    public string? CancelledBy { get; set; }
    public DateTimeOffset? SentAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public string? Error { get; set; }
}

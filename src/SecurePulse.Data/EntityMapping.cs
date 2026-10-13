using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

internal static class EntityMapping
{
    public static Tenant ToModel(this TenantEntity e) => new()
    {
        Id = e.Id,
        EntraTenantId = e.EntraTenantId,
        DisplayName = e.DisplayName,
        PrimaryDomain = e.PrimaryDomain,
        PartnerName = e.PartnerName,
        Industry = e.Industry,
        CredentialReference = e.CredentialReference,
        ConsentState = e.ConsentState,
        LastScanAt = e.LastScanAt
    };

    public static TenantEntity ToEntity(this Tenant m) => new()
    {
        Id = m.Id,
        EntraTenantId = m.EntraTenantId,
        DisplayName = m.DisplayName,
        PrimaryDomain = m.PrimaryDomain,
        PartnerName = m.PartnerName,
        Industry = m.Industry,
        CredentialReference = m.CredentialReference,
        ConsentState = m.ConsentState,
        LastScanAt = m.LastScanAt
    };

    public static Finding ToModel(this FindingEntity e) => new()
    {
        Id = e.Id,
        TenantId = e.TenantId,
        Source = e.Source,
        SourceCheckId = e.SourceCheckId,
        Title = e.Title,
        Description = e.Description,
        Category = e.Category,
        Severity = e.Severity,
        Status = e.Status,
        Evidence = e.Evidence,
        Remediation = e.Remediation,
        HelpUrl = e.HelpUrl,
        Frameworks = e.Frameworks,
        Tags = e.Tags,
        DetectedAt = e.DetectedAt
    };

    public static FindingEntity ToEntity(this Finding m) => new()
    {
        Id = m.Id,
        TenantId = m.TenantId,
        Source = m.Source,
        SourceCheckId = m.SourceCheckId,
        Title = m.Title,
        Description = m.Description,
        Category = m.Category,
        Severity = m.Severity,
        Status = m.Status,
        Evidence = m.Evidence,
        Remediation = m.Remediation,
        HelpUrl = m.HelpUrl,
        Frameworks = [.. m.Frameworks],
        Tags = [.. m.Tags],
        DetectedAt = m.DetectedAt
    };

    public static ManagedDevice ToModel(this ManagedDeviceEntity e) => new()
    {
        Id = e.Id,
        TenantId = e.TenantId,
        DeviceName = e.DeviceName,
        UserDisplayName = e.UserDisplayName,
        UserPrincipalName = e.UserPrincipalName,
        Platform = e.Platform,
        OsVersion = e.OsVersion,
        Manufacturer = e.Manufacturer,
        Model = e.Model,
        SerialNumber = e.SerialNumber,
        Ownership = e.Ownership,
        ComplianceState = e.ComplianceState,
        IsEncrypted = e.IsEncrypted,
        Defender = e.Defender,
        EnrolledAt = e.EnrolledAt,
        LastSyncAt = e.LastSyncAt,
        ComplianceSettings = e.ComplianceSettings
            .Select(s => new DeviceComplianceSetting(s.Policy, s.Setting, s.Compliant, s.Detail))
            .ToList()
    };

    public static ManagedDeviceEntity ToEntity(this ManagedDevice m) => new()
    {
        Id = m.Id,
        TenantId = m.TenantId,
        DeviceName = m.DeviceName,
        UserDisplayName = m.UserDisplayName,
        UserPrincipalName = m.UserPrincipalName,
        Platform = m.Platform,
        OsVersion = m.OsVersion,
        Manufacturer = m.Manufacturer,
        Model = m.Model,
        SerialNumber = m.SerialNumber,
        Ownership = m.Ownership,
        ComplianceState = m.ComplianceState,
        IsEncrypted = m.IsEncrypted,
        Defender = m.Defender,
        EnrolledAt = m.EnrolledAt,
        LastSyncAt = m.LastSyncAt,
        ComplianceSettings = m.ComplianceSettings
            .Select(s => new ComplianceSettingEntity { Policy = s.Policy, Setting = s.Setting, Compliant = s.Compliant, Detail = s.Detail })
            .ToList()
    };

    public static DeviceSyncStatus ToModel(this DeviceSyncStatusEntity e) => new()
    {
        TenantId = e.TenantId,
        LastAttemptAt = e.LastAttemptAt,
        LastSuccessAt = e.LastSuccessAt,
        Succeeded = e.Succeeded,
        Error = e.Error,
        DeviceCount = e.DeviceCount
    };

    public static OnboardingRequest ToModel(this OnboardingRequestEntity e) => new()
    {
        Id = e.Id,
        DisplayName = e.DisplayName,
        PrimaryDomain = e.PrimaryDomain,
        PartnerName = e.PartnerName,
        Industry = e.Industry,
        EntraTenantId = e.EntraTenantId,
        Status = e.Status,
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
        ConsentReceivedAt = e.ConsentReceivedAt,
        CompletedAt = e.CompletedAt,
        TenantId = e.TenantId,
        LastError = e.LastError,
        GrantedPermissions = e.GrantedPermissions,
        VerificationAttempts = e.VerificationAttempts,
        ProtectedState = e.ProtectedState
    };
}

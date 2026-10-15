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
        RemediationCredentialReference = e.RemediationCredentialReference,
        WazuhAgentGroup = e.WazuhAgentGroup,
        GoPhishEnabled = e.GoPhishEnabled,
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
        RemediationCredentialReference = m.RemediationCredentialReference,
        WazuhAgentGroup = m.WazuhAgentGroup,
        GoPhishEnabled = m.GoPhishEnabled,
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
        DefenderDetails = e.DefenderDetails?.ToModel(),
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
        DefenderDetails = m.DefenderDetails?.ToEntity(),
        EnrolledAt = m.EnrolledAt,
        LastSyncAt = m.LastSyncAt,
        ComplianceSettings = m.ComplianceSettings
            .Select(s => new ComplianceSettingEntity { Policy = s.Policy, Setting = s.Setting, Compliant = s.Compliant, Detail = s.Detail })
            .ToList()
    };

    public static DefenderHealth ToModel(this DefenderHealthEntity e) => new()
    {
        Antivirus = e.Antivirus is { } av ? new DefenderAntivirusStatus
        {
            MalwareProtectionEnabled = av.MalwareProtectionEnabled,
            RealTimeProtectionEnabled = av.RealTimeProtectionEnabled,
            TamperProtectionEnabled = av.TamperProtectionEnabled,
            SignaturesOutOfDate = av.SignaturesOutOfDate,
            QuickScanOverdue = av.QuickScanOverdue,
            RebootRequired = av.RebootRequired,
            ThreatState = av.ThreatState,
            SignatureVersion = av.SignatureVersion,
            EngineVersion = av.EngineVersion,
            LastQuickScanAt = av.LastQuickScanAt,
            LastReportedAt = av.LastReportedAt
        } : null,
        Sensor = e.Sensor is { } s ? new DefenderSensorStatus
        {
            MachineId = s.MachineId,
            Onboarding = s.Onboarding,
            Health = s.Health,
            ExposureLevel = s.ExposureLevel,
            LastSeenAt = s.LastSeenAt
        } : null,
        SensorDataAvailable = e.SensorDataAvailable,
        Issues = [.. e.Issues]
    };

    public static DefenderHealthEntity ToEntity(this DefenderHealth m) => new()
    {
        Antivirus = m.Antivirus is { } av ? new DefenderAntivirusEntity
        {
            MalwareProtectionEnabled = av.MalwareProtectionEnabled,
            RealTimeProtectionEnabled = av.RealTimeProtectionEnabled,
            TamperProtectionEnabled = av.TamperProtectionEnabled,
            SignaturesOutOfDate = av.SignaturesOutOfDate,
            QuickScanOverdue = av.QuickScanOverdue,
            RebootRequired = av.RebootRequired,
            ThreatState = av.ThreatState,
            SignatureVersion = av.SignatureVersion,
            EngineVersion = av.EngineVersion,
            LastQuickScanAt = av.LastQuickScanAt,
            LastReportedAt = av.LastReportedAt
        } : null,
        Sensor = m.Sensor is { } s ? new DefenderSensorEntity
        {
            MachineId = s.MachineId,
            Onboarding = s.Onboarding,
            Health = s.Health,
            ExposureLevel = s.ExposureLevel,
            LastSeenAt = s.LastSeenAt
        } : null,
        SensorDataAvailable = m.SensorDataAvailable,
        Issues = [.. m.Issues]
    };

    public static DeviceSyncStatus ToModel(this DeviceSyncStatusEntity e) => new()
    {
        TenantId = e.TenantId,
        LastAttemptAt = e.LastAttemptAt,
        LastSuccessAt = e.LastSuccessAt,
        Succeeded = e.Succeeded,
        Error = e.Error,
        Warning = e.Warning,
        DeviceCount = e.DeviceCount
    };

    public static OnboardingRequest ToModel(this OnboardingRequestEntity e) => new()
    {
        Id = e.Id,
        Kind = e.Kind,
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
        StartedBy = e.StartedBy,
        GrantedPermissions = e.GrantedPermissions,
        VerificationAttempts = e.VerificationAttempts,
        ProtectedState = e.ProtectedState
    };

    public static PortalUser ToModel(this PortalUserEntity e) => new()
    {
        Id = e.Id,
        Role = e.Role,
        EntraTenantId = e.EntraTenantId,
        UserPrincipalName = e.UserPrincipalName,
        ObjectId = e.ObjectId,
        DisplayName = e.DisplayName,
        ClientTenantId = e.ClientTenantId,
        CreatedAt = e.CreatedAt,
        CreatedBy = e.CreatedBy,
        LastSignInAt = e.LastSignInAt
    };

    public static AuditEvent ToModel(this AuditEventEntity e) => new()
    {
        Id = e.Id,
        OccurredAt = e.OccurredAt,
        Action = e.Action,
        Outcome = e.Outcome,
        ActorUserId = e.ActorUserId,
        ActorName = e.ActorName,
        TenantId = e.TenantId,
        TargetType = e.TargetType,
        TargetId = e.TargetId,
        Summary = e.Summary,
        Details = e.Details,
        IpAddress = e.IpAddress,
        RecordedAt = e.RecordedAt == default ? null : e.RecordedAt
    };

    public static ScanRun ToModel(this ScanRunEntity e) => new()
    {
        Id = e.Id,
        TenantId = e.TenantId,
        Engine = e.Engine,
        Trigger = e.Trigger,
        Status = e.Status,
        QueuedAt = e.QueuedAt,
        StartedAt = e.StartedAt,
        CompletedAt = e.CompletedAt,
        RequestedBy = e.RequestedBy,
        FindingCount = e.FindingCount,
        Error = e.Error
    };

    public static DeviceActionRequest ToModel(this DeviceActionEntity e) => new()
    {
        Id = e.Id,
        TenantId = e.TenantId,
        DeviceId = e.DeviceId,
        DeviceName = e.DeviceName,
        Action = e.Action,
        Reason = e.Reason,
        Status = e.Status,
        RequestedAt = e.RequestedAt,
        RequestedByUserId = e.RequestedByUserId,
        RequestedByName = e.RequestedByName,
        ExpiresAt = e.ExpiresAt,
        DecidedAt = e.DecidedAt,
        DecidedByUserId = e.DecidedByUserId,
        DecidedByName = e.DecidedByName,
        DecidedByRole = e.DecidedByRole,
        DecisionNote = e.DecisionNote,
        CancelledAt = e.CancelledAt,
        CancelledBy = e.CancelledBy,
        SentAt = e.SentAt,
        CompletedAt = e.CompletedAt,
        Error = e.Error,
        PlaybookId = e.PlaybookId
    };

    public static DeviceActionEntity ToEntity(this DeviceActionRequest m) => new()
    {
        Id = m.Id,
        TenantId = m.TenantId,
        DeviceId = m.DeviceId,
        DeviceName = m.DeviceName,
        Action = m.Action,
        Reason = m.Reason,
        Status = m.Status,
        RequestedAt = m.RequestedAt,
        RequestedByUserId = m.RequestedByUserId,
        RequestedByName = m.RequestedByName,
        ExpiresAt = m.ExpiresAt,
        DecidedAt = m.DecidedAt,
        DecidedByUserId = m.DecidedByUserId,
        DecidedByName = m.DecidedByName,
        DecidedByRole = m.DecidedByRole,
        DecisionNote = m.DecisionNote,
        CancelledAt = m.CancelledAt,
        CancelledBy = m.CancelledBy,
        SentAt = m.SentAt,
        CompletedAt = m.CompletedAt,
        Error = m.Error,
        PlaybookId = m.PlaybookId
    };

    public static RemediationPlaybook ToModel(this PlaybookEntity e) => new()
    {
        Id = e.Id, Name = e.Name, Enabled = e.Enabled, Trigger = e.Trigger, Days = e.Days, Action = e.Action, TenantId = e.TenantId,
        MaxPerRun = e.MaxPerRun, Cooldown = e.Cooldown, CreatedAt = e.CreatedAt, UpdatedByUserId = e.UpdatedByUserId,
        UpdatedByName = e.UpdatedByName, UpdatedAt = e.UpdatedAt, LastRunAt = e.LastRunAt
    };

    public static PlaybookEntity ToEntity(this RemediationPlaybook m) => new()
    {
        Id = m.Id, Name = m.Name, Enabled = m.Enabled, Trigger = m.Trigger, Days = m.Days, Action = m.Action, TenantId = m.TenantId,
        MaxPerRun = m.MaxPerRun, Cooldown = m.Cooldown, CreatedAt = m.CreatedAt, UpdatedByUserId = m.UpdatedByUserId,
        UpdatedByName = m.UpdatedByName, UpdatedAt = m.UpdatedAt, LastRunAt = m.LastRunAt
    };
}

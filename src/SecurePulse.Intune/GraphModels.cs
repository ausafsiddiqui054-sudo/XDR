using System.Text.Json.Serialization;

namespace SecurePulse.Intune;

// Subsets of Microsoft Graph v1.0 resources. Internal: Graph shapes never leave this project.

internal sealed class GraphPage<T>
{
    [JsonPropertyName("value")] public List<T> Value { get; set; } = [];
    [JsonPropertyName("@odata.nextLink")] public string? NextLink { get; set; }
}

/// <summary>https://learn.microsoft.com/graph/api/resources/intune-devices-manageddevice</summary>
internal sealed class GraphManagedDevice
{
    public string? Id { get; set; }
    public string? DeviceName { get; set; }
    public string? UserDisplayName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? OperatingSystem { get; set; }
    public string? OsVersion { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? SerialNumber { get; set; }
    public string? ManagedDeviceOwnerType { get; set; }
    public string? ComplianceState { get; set; }
    public bool? IsEncrypted { get; set; }
    public DateTimeOffset? EnrolledDateTime { get; set; }
    public DateTimeOffset? LastSyncDateTime { get; set; }
    public string? AzureADDeviceId { get; set; }

    /// <summary>The $select list matching the properties above.</summary>
    public const string Select =
        "id,deviceName,userDisplayName,userPrincipalName,operatingSystem,osVersion,manufacturer,model," +
        "serialNumber,managedDeviceOwnerType,complianceState,isEncrypted,enrolledDateTime,lastSyncDateTime,azureADDeviceId";
}

/// <summary>https://learn.microsoft.com/graph/api/resources/intune-devices-windowsprotectionstate</summary>
internal sealed class GraphWindowsProtectionState
{
    public bool? MalwareProtectionEnabled { get; set; }
    public bool? RealTimeProtectionEnabled { get; set; }
    public bool? TamperProtectionEnabled { get; set; }
    public bool? SignatureUpdateOverdue { get; set; }
    public bool? QuickScanOverdue { get; set; }
    public bool? RebootRequired { get; set; }
    public string? DeviceState { get; set; }
    public string? SignatureVersion { get; set; }
    public string? EngineVersion { get; set; }
    public DateTimeOffset? LastQuickScanDateTime { get; set; }
    public DateTimeOffset? LastReportedDateTime { get; set; }
}

/// <summary>https://learn.microsoft.com/graph/api/resources/security-huntingqueryresults</summary>
internal sealed class GraphHuntingResults<T>
{
    public List<T> Results { get; set; } = [];
}

/// <summary>One row of <see cref="DefenderHealthMapper.DeviceInfoQuery"/> (advanced hunting DeviceInfo).</summary>
internal sealed class HuntingDeviceRow
{
    public string? DeviceId { get; set; }
    public string? AadDeviceId { get; set; }
    public string? DeviceName { get; set; }
    public string? OnboardingStatus { get; set; }
    public string? SensorHealthState { get; set; }
    public string? ExposureLevel { get; set; }
    public DateTimeOffset? Timestamp { get; set; }
}

/// <summary>https://learn.microsoft.com/graph/api/resources/intune-devices-devicecompliancepolicystate</summary>
internal sealed class GraphCompliancePolicyState
{
    public string? DisplayName { get; set; }
    public string? State { get; set; }
    public List<GraphCompliancePolicySettingState> SettingStates { get; set; } = [];
}

internal sealed class GraphCompliancePolicySettingState
{
    public string? Setting { get; set; }
    public string? SettingName { get; set; }
    public string? State { get; set; }
    public string? ErrorDescription { get; set; }
}

internal sealed class GraphErrorResponse
{
    public GraphError? Error { get; set; }
}

internal sealed class GraphError
{
    public string? Code { get; set; }
    public string? Message { get; set; }
}

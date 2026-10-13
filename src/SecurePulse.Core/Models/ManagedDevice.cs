namespace SecurePulse.Core.Models;

public enum DevicePlatform
{
    Windows,
    MacOS,
    iOS,
    Android,
    Linux
}

public enum DeviceOwnership
{
    Corporate,
    Personal,
    Unknown
}

/// <summary>Normalized Intune compliance state. Conflict, error and unmanaged states map to Unknown.</summary>
public enum DeviceComplianceState
{
    Compliant,
    InGracePeriod,
    Noncompliant,
    Unknown
}

public enum DefenderState
{
    Protected,
    Unhealthy,
    NotOnboarded,
    Unknown
}

/// <summary>Result of one setting in a compliance policy evaluated on a device.</summary>
public sealed record DeviceComplianceSetting(string Policy, string Setting, bool Compliant, string? Detail = null);

/// <summary>
/// A device managed by Intune in a client tenant, read with read-only Graph permissions
/// (DeviceManagementManagedDevices.Read.All). Never carries credentials or recovery keys.
/// </summary>
public sealed record ManagedDevice
{
    /// <summary>Intune managed device ID.</summary>
    public required string Id { get; init; }
    public required Guid TenantId { get; init; }

    public required string DeviceName { get; init; }
    public string? UserDisplayName { get; init; }
    public string? UserPrincipalName { get; init; }

    public required DevicePlatform Platform { get; init; }
    public string? OsVersion { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? SerialNumber { get; init; }

    public DeviceOwnership Ownership { get; init; } = DeviceOwnership.Unknown;
    public required DeviceComplianceState ComplianceState { get; init; }

    /// <summary>Null when the platform doesn't report encryption.</summary>
    public bool? IsEncrypted { get; init; }
    public DefenderState Defender { get; init; } = DefenderState.Unknown;

    public DateTimeOffset? EnrolledAt { get; init; }
    public DateTimeOffset? LastSyncAt { get; init; }

    public IReadOnlyList<DeviceComplianceSetting> ComplianceSettings { get; init; } = [];
}

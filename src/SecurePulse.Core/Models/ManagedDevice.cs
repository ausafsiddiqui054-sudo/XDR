namespace SecurePulse.Core.Models;

public enum DevicePlatform
{
    Windows,
    MacOS,
    iOS,
    Android,
    Linux,
    Other
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

    /// <summary>What <see cref="Defender"/> is based on. Null when Defender health wasn't read.</summary>
    public DefenderHealth? DefenderDetails { get; init; }

    public DateTimeOffset? EnrolledAt { get; init; }
    public DateTimeOffset? LastSyncAt { get; init; }

    public IReadOnlyList<DeviceComplianceSetting> ComplianceSettings { get; init; } = [];
}

/// <summary>Output of one device inventory sync against one tenant.</summary>
public sealed record DeviceSyncResult
{
    public required Guid TenantId { get; init; }
    public required string Source { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }

    /// <summary>The tenant's full inventory. Replaces what was stored when the sync succeeded.</summary>
    public required IReadOnlyList<ManagedDevice> Devices { get; init; }

    public bool Succeeded { get; init; } = true;
    public string? Error { get; init; }

    /// <summary>Parts of a successful sync that were skipped (e.g. Defender data unavailable).</summary>
    public string? Warning { get; init; }
}

/// <summary>Latest device sync outcome for a tenant.</summary>
public sealed record DeviceSyncStatus
{
    public required Guid TenantId { get; init; }
    public required DateTimeOffset LastAttemptAt { get; init; }

    /// <summary>When the stored inventory was last refreshed. Null if no sync has succeeded yet.</summary>
    public DateTimeOffset? LastSuccessAt { get; init; }

    public required bool Succeeded { get; init; }
    public string? Error { get; init; }

    /// <summary>From the last successful sync: data it couldn't read (e.g. Defender for Endpoint).</summary>
    public string? Warning { get; init; }

    public int DeviceCount { get; init; }
}

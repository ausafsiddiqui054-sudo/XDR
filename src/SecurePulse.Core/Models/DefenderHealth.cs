namespace SecurePulse.Core.Models;

/// <summary>Microsoft Defender for Endpoint onboarding, as advanced hunting's DeviceInfo reports it.</summary>
public enum DefenderOnboarding
{
    Onboarded,
    CanBeOnboarded,
    Unsupported,
    InsufficientInfo,
    Unknown
}

/// <summary>Health of the Defender for Endpoint (EDR) sensor on an onboarded device.</summary>
public enum DefenderSensorHealth
{
    Active,
    Inactive,
    ImpairedCommunication,
    NoSensorData,
    Unknown
}

/// <summary>Defender Antivirus threat state (Intune windowsDeviceHealthState).</summary>
public enum DefenderThreatState
{
    Clean,
    FullScanPending,
    RebootPending,
    ManualStepsPending,
    OfflineScanPending,
    Critical,
    Unknown
}

/// <summary>
/// Microsoft Defender Antivirus on a Windows device, as Intune reports it (windowsProtectionState).
/// Null values weren't reported.
/// </summary>
public sealed record DefenderAntivirusStatus
{
    public bool? MalwareProtectionEnabled { get; init; }
    public bool? RealTimeProtectionEnabled { get; init; }
    public bool? TamperProtectionEnabled { get; init; }
    public bool? SignaturesOutOfDate { get; init; }
    public bool? QuickScanOverdue { get; init; }
    public bool? RebootRequired { get; init; }
    public DefenderThreatState ThreatState { get; init; } = DefenderThreatState.Unknown;
    public string? SignatureVersion { get; init; }
    public string? EngineVersion { get; init; }
    public DateTimeOffset? LastQuickScanAt { get; init; }
    public DateTimeOffset? LastReportedAt { get; init; }
}

/// <summary>The device as Defender for Endpoint sees it (advanced hunting DeviceInfo, latest row).</summary>
public sealed record DefenderSensorStatus
{
    /// <summary>Defender for Endpoint's device ID.</summary>
    public string? MachineId { get; init; }

    public DefenderOnboarding Onboarding { get; init; } = DefenderOnboarding.Unknown;
    public DefenderSensorHealth Health { get; init; } = DefenderSensorHealth.Unknown;

    /// <summary>Low, Medium or High (Defender Vulnerability Management), when reported.</summary>
    public string? ExposureLevel { get; init; }

    public DateTimeOffset? LastSeenAt { get; init; }
}

/// <summary>
/// Defender health of one device: antivirus (Intune) and EDR sensor (Defender for Endpoint),
/// with the issues that make it unhealthy. <see cref="DefenderHealthEvaluator"/> derives the
/// summary <see cref="DefenderState"/> stored on the device.
/// </summary>
public sealed record DefenderHealth
{
    /// <summary>Null when Intune reported no antivirus state (non-Windows, or not reported yet).</summary>
    public DefenderAntivirusStatus? Antivirus { get; init; }

    /// <summary>Null when Defender for Endpoint has no record of the device.</summary>
    public DefenderSensorStatus? Sensor { get; init; }

    /// <summary>
    /// False when the tenant's Defender for Endpoint data couldn't be read (no licence, or the
    /// query failed). Then a missing <see cref="Sensor"/> says nothing about onboarding.
    /// </summary>
    public bool SensorDataAvailable { get; init; }

    public IReadOnlyList<string> Issues { get; init; } = [];
}

/// <summary>
/// The rules that turn raw Defender data into a device's <see cref="DefenderState"/>. One place,
/// shared by the Worker (real devices) and the sample data, so the portal never re-derives it.
/// </summary>
public static class DefenderHealthEvaluator
{
    /// <summary>Platforms Defender for Endpoint onboards as endpoints. Mobile onboarding is optional, so its absence isn't flagged.</summary>
    public static bool ExpectsSensor(DevicePlatform platform) =>
        platform is DevicePlatform.Windows or DevicePlatform.MacOS or DevicePlatform.Linux;

    public static (DefenderState State, DefenderHealth Health) Evaluate(DevicePlatform platform, DefenderAntivirusStatus? antivirus,
        DefenderSensorStatus? sensor, bool sensorDataAvailable)
    {
        var issues = new List<string>();

        if (antivirus is { } av)
        {
            if (av.MalwareProtectionEnabled == false) issues.Add("Microsoft Defender Antivirus is turned off.");
            if (av.RealTimeProtectionEnabled == false) issues.Add("Real-time protection is off.");
            if (av.TamperProtectionEnabled == false) issues.Add("Tamper protection is off.");
            if (av.SignaturesOutOfDate == true) issues.Add("Security intelligence (signatures) is out of date.");
            if (ThreatIssue(av.ThreatState) is { } threat) issues.Add(threat);
        }

        var onboarded = sensor is { Onboarding: DefenderOnboarding.Onboarded };
        if (onboarded && SensorIssue(sensor!.Health) is { } sensorIssue) issues.Add(sensorIssue);

        var notOnboarded = sensorDataAvailable && !onboarded
                           && (ExpectsSensor(platform) || sensor is { Onboarding: DefenderOnboarding.CanBeOnboarded });

        var antivirusHealthy = antivirus is { MalwareProtectionEnabled: true, RealTimeProtectionEnabled: true };
        var sensorHealthy = onboarded && sensor!.Health == DefenderSensorHealth.Active;

        var state = issues.Count > 0 ? DefenderState.Unhealthy
            : notOnboarded ? DefenderState.NotOnboarded
            : antivirusHealthy || sensorHealthy ? DefenderState.Protected
            : DefenderState.Unknown;

        if (notOnboarded)
            issues.Add(sensor?.Onboarding switch
            {
                DefenderOnboarding.CanBeOnboarded => "Not onboarded to Defender for Endpoint: it was discovered on the network but has no sensor.",
                DefenderOnboarding.Unsupported => "Not onboarded: Defender for Endpoint doesn't support this OS version.",
                _ => "Not onboarded to Defender for Endpoint."
            });

        return (state, new DefenderHealth
        {
            Antivirus = antivirus,
            Sensor = sensor,
            SensorDataAvailable = sensorDataAvailable,
            Issues = issues
        });
    }

    private static string? ThreatIssue(DefenderThreatState state) => state switch
    {
        DefenderThreatState.Critical => "Defender reports a critical threat state: a threat wasn't remediated.",
        DefenderThreatState.FullScanPending => "A threat needs a full scan to finish remediation.",
        DefenderThreatState.RebootPending => "A threat needs a restart to finish remediation.",
        DefenderThreatState.ManualStepsPending => "A threat needs manual steps to finish remediation.",
        DefenderThreatState.OfflineScanPending => "A threat needs an offline scan to finish remediation.",
        _ => null
    };

    private static string? SensorIssue(DefenderSensorHealth health) => health switch
    {
        DefenderSensorHealth.Inactive => "The Defender for Endpoint sensor is inactive (the device stopped reporting).",
        DefenderSensorHealth.ImpairedCommunication => "The Defender for Endpoint sensor has impaired communication.",
        DefenderSensorHealth.NoSensorData => "The Defender for Endpoint sensor sends no data.",
        _ => null
    };
}

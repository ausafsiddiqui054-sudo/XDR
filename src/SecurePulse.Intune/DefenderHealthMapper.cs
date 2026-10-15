using SecurePulse.Core.Models;

namespace SecurePulse.Intune;

/// <summary>
/// Converts Defender data from Graph into normalized <see cref="DefenderAntivirusStatus"/> and
/// <see cref="DefenderSensorStatus"/>, and matches Defender for Endpoint devices to Intune devices.
/// </summary>
internal static class DefenderHealthMapper
{
    /// <summary>How far back advanced hunting looks for a device's latest DeviceInfo row.</summary>
    public const string HuntingTimespan = "P30D";

    /// <summary>
    /// The latest DeviceInfo row per Defender for Endpoint device. A fixed query: nothing from a
    /// tenant or a user is ever interpolated into it.
    /// </summary>
    public const string DeviceInfoQuery =
        "DeviceInfo " +
        "| where Timestamp > ago(30d) " +
        "| summarize arg_max(Timestamp, *) by DeviceId " +
        "| project DeviceId, AadDeviceId, DeviceName, OnboardingStatus, SensorHealthState, ExposureLevel, Timestamp";

    public static DefenderAntivirusStatus MapAntivirus(GraphWindowsProtectionState s) => new()
    {
        MalwareProtectionEnabled = s.MalwareProtectionEnabled,
        RealTimeProtectionEnabled = s.RealTimeProtectionEnabled,
        TamperProtectionEnabled = s.TamperProtectionEnabled,
        SignaturesOutOfDate = s.SignatureUpdateOverdue,
        QuickScanOverdue = s.QuickScanOverdue,
        RebootRequired = s.RebootRequired,
        ThreatState = MapThreatState(s.DeviceState),
        SignatureVersion = Clean(s.SignatureVersion),
        EngineVersion = Clean(s.EngineVersion),
        LastQuickScanAt = Clean(s.LastQuickScanDateTime),
        LastReportedAt = Clean(s.LastReportedDateTime)
    };

    public static DefenderThreatState MapThreatState(string? state) => Key(state) switch
    {
        "clean" => DefenderThreatState.Clean,
        "fullscanpending" => DefenderThreatState.FullScanPending,
        "rebootpending" => DefenderThreatState.RebootPending,
        "manualstepspending" => DefenderThreatState.ManualStepsPending,
        "offlinescanpending" => DefenderThreatState.OfflineScanPending,
        "critical" => DefenderThreatState.Critical,
        _ => DefenderThreatState.Unknown
    };

    public static DefenderOnboarding MapOnboarding(string? status) => Key(status) switch
    {
        "onboarded" => DefenderOnboarding.Onboarded,
        "canbeonboarded" => DefenderOnboarding.CanBeOnboarded,
        "unsupported" => DefenderOnboarding.Unsupported,
        "insufficientinfo" => DefenderOnboarding.InsufficientInfo,
        _ => DefenderOnboarding.Unknown
    };

    /// <summary>"Active", "Inactive", "Impaired communications", "No sensor data" (or both of the last two).</summary>
    public static DefenderSensorHealth MapSensorHealth(string? state)
    {
        var key = Key(state);
        if (key is null) return DefenderSensorHealth.Unknown;
        if (key.Contains("nosensordata")) return DefenderSensorHealth.NoSensorData;
        if (key.Contains("impaired")) return DefenderSensorHealth.ImpairedCommunication;
        return key switch
        {
            "active" => DefenderSensorHealth.Active,
            "inactive" => DefenderSensorHealth.Inactive,
            _ => DefenderSensorHealth.Unknown
        };
    }

    public static DefenderSensorStatus MapSensor(HuntingDeviceRow row) => new()
    {
        MachineId = Clean(row.DeviceId),
        Onboarding = MapOnboarding(row.OnboardingStatus),
        Health = MapSensorHealth(row.SensorHealthState),
        ExposureLevel = Clean(row.ExposureLevel),
        LastSeenAt = Clean(row.Timestamp)
    };

    /// <summary>
    /// Matches Defender for Endpoint devices to Intune devices by Entra device ID. A device without a
    /// match by ID falls back to its host name, but only when that name is unique on both sides, so
    /// one device's health is never shown on another. Returns Intune device ID → sensor status.
    /// </summary>
    public static Dictionary<string, DefenderSensorStatus> Match(IReadOnlyCollection<GraphManagedDevice> devices, IReadOnlyCollection<HuntingDeviceRow> rows)
    {
        var matched = new Dictionary<string, DefenderSensorStatus>();

        // Re-onboarded devices can have several Defender IDs: the latest row wins.
        var latest = rows.OrderByDescending(r => r.Timestamp ?? DateTimeOffset.MinValue).ToList();
        var byEntraId = latest
            .Where(r => Guid.TryParse(r.AadDeviceId, out var g) && g != Guid.Empty)
            .GroupBy(r => Guid.Parse(r.AadDeviceId!))
            .ToDictionary(g => g.Key, g => g.First());

        var unmatched = new List<GraphManagedDevice>();
        foreach (var d in devices.Where(d => !string.IsNullOrWhiteSpace(d.Id)))
        {
            if (Guid.TryParse(d.AzureADDeviceId, out var entraId) && entraId != Guid.Empty && byEntraId.TryGetValue(entraId, out var row))
                matched[d.Id!] = MapSensor(row);
            else
                unmatched.Add(d);
        }

        var usedMachines = new HashSet<string>(matched.Values.Select(s => s.MachineId).OfType<string>(), StringComparer.OrdinalIgnoreCase);
        var rowsByHost = latest
            .Where(r => HostName(r.DeviceName) is not null && !(r.DeviceId is { } id && usedMachines.Contains(id)))
            .GroupBy(r => HostName(r.DeviceName)!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(r => r.DeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var intuneHostCounts = devices
            .Select(d => HostName(d.DeviceName))
            .OfType<string>()
            .GroupBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        foreach (var d in unmatched)
        {
            if (HostName(d.DeviceName) is { } host && intuneHostCounts[host] == 1 && rowsByHost.TryGetValue(host, out var row))
                matched[d.Id!] = MapSensor(row);
        }

        return matched;
    }

    /// <summary>"pc-01.contoso.local" and "PC-01" are the same host.</summary>
    private static string? HostName(string? name)
    {
        var trimmed = Clean(name);
        if (trimmed is null) return null;
        var dot = trimmed.IndexOf('.');
        return dot > 0 ? trimmed[..dot] : trimmed;
    }

    private static string? Key(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : new string(s.Where(char.IsLetter).ToArray()).ToLowerInvariant();

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    // Graph returns 0001-01-01 for "never".
    private static DateTimeOffset? Clean(DateTimeOffset? d) => d is { Year: > 1 } ? d : null;
}

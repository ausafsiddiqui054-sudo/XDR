using SecurePulse.Core.Models;

namespace SecurePulse.Reporting.Pdf;

/// <summary>Who the report is from: the deployment's brand, or the MSP partner managing the tenant.</summary>
public sealed record ReportBranding
{
    public string CompanyName { get; init; } = "SecurePulse";

    /// <summary>PNG, JPEG or SVG bytes. Null draws the default shield mark.</summary>
    public byte[]? Logo { get; init; }

    /// <summary>Accent colour for headings, rules and the score ring (#RRGGBB).</summary>
    public string AccentColor { get; init; } = "#4F46C8";

    /// <summary>A line for the cover and footer, e.g. "security@msp.example · +971 4 000 0000".</summary>
    public string? ContactLine { get; init; }
}

/// <summary>Device compliance totals for the report (Intune inventory at the last sync).</summary>
public sealed record DeviceSummary
{
    public required int Total { get; init; }
    public required int Compliant { get; init; }
    public required int InGracePeriod { get; init; }
    public required int Noncompliant { get; init; }
    public required int Unknown { get; init; }
    public DateTimeOffset? LastSyncAt { get; init; }

    /// <summary>Non-compliant devices to list (name, platform, last check-in), most stale first.</summary>
    public IReadOnlyList<(string Name, string Platform, DateTimeOffset? LastSyncAt)> NoncompliantDevices { get; init; } = [];

    public static DeviceSummary From(IReadOnlyCollection<ManagedDevice> devices, DateTimeOffset? lastSyncAt, int listLimit = 15) => new()
    {
        Total = devices.Count,
        Compliant = devices.Count(d => d.ComplianceState == DeviceComplianceState.Compliant),
        InGracePeriod = devices.Count(d => d.ComplianceState == DeviceComplianceState.InGracePeriod),
        Noncompliant = devices.Count(d => d.ComplianceState == DeviceComplianceState.Noncompliant),
        Unknown = devices.Count(d => d.ComplianceState == DeviceComplianceState.Unknown),
        LastSyncAt = lastSyncAt,
        NoncompliantDevices = devices.Where(d => d.ComplianceState == DeviceComplianceState.Noncompliant)
            .OrderBy(d => d.LastSyncAt ?? DateTimeOffset.MinValue)
            .ThenBy(d => d.DeviceName, StringComparer.OrdinalIgnoreCase)
            .Take(listLimit)
            .Select(d => (d.DeviceName, d.Platform.ToString(), d.LastSyncAt))
            .ToList()
    };
}

/// <summary>Everything one tenant's posture report shows. Built by the portal after its access checks.</summary>
public sealed record PostureReportData
{
    public required Tenant Tenant { get; init; }

    /// <summary>From <see cref="RiskScoreCalculator"/>; the report never computes its own score.</summary>
    public required RiskScore Score { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
    public required DateTimeOffset GeneratedAt { get; init; }
    public required ReportBranding Branding { get; init; }

    public DeviceSummary? Devices { get; init; }

    /// <summary>Time zone for the dates printed in the report. UTC when null.</summary>
    public TimeZoneInfo? TimeZone { get; init; }
}

using SecurePulse.Core.Models;

namespace SecurePulse.Intune;

/// <summary>Converts Graph managedDevice data into normalized <see cref="ManagedDevice"/>s.</summary>
internal static class IntuneDeviceMapper
{
    public static ManagedDevice Map(GraphManagedDevice d, Guid tenantId, IReadOnlyList<DeviceComplianceSetting>? settings = null) => new()
    {
        Id = d.Id ?? throw new ArgumentException("Graph device has no id.", nameof(d)),
        TenantId = tenantId,
        DeviceName = Clean(d.DeviceName) ?? d.Id,
        UserDisplayName = Clean(d.UserDisplayName),
        UserPrincipalName = Clean(d.UserPrincipalName),
        Platform = MapPlatform(d.OperatingSystem),
        OsVersion = Clean(d.OsVersion),
        Manufacturer = Clean(d.Manufacturer),
        Model = Clean(d.Model),
        SerialNumber = Clean(d.SerialNumber),
        Ownership = MapOwnership(d.ManagedDeviceOwnerType),
        ComplianceState = MapCompliance(d.ComplianceState),
        IsEncrypted = d.IsEncrypted,
        // Defender health isn't on managedDevice in Graph v1.0; it needs the Defender for Endpoint API.
        Defender = DefenderState.Unknown,
        EnrolledAt = Clean(d.EnrolledDateTime),
        LastSyncAt = Clean(d.LastSyncDateTime),
        ComplianceSettings = settings ?? []
    };

    public static DevicePlatform MapPlatform(string? operatingSystem) => operatingSystem?.Trim().ToLowerInvariant() switch
    {
        "windows" => DevicePlatform.Windows,
        "macos" or "mac os" or "macosx" => DevicePlatform.MacOS,
        "ios" or "ipados" => DevicePlatform.iOS,
        "android" or "androidforwork" or "androidenterprise" => DevicePlatform.Android,
        "linux" => DevicePlatform.Linux,
        _ => DevicePlatform.Other
    };

    public static DeviceOwnership MapOwnership(string? ownerType) => ownerType?.Trim().ToLowerInvariant() switch
    {
        "company" => DeviceOwnership.Corporate,
        "personal" => DeviceOwnership.Personal,
        _ => DeviceOwnership.Unknown
    };

    public static DeviceComplianceState MapCompliance(string? state) => state?.Trim().ToLowerInvariant() switch
    {
        "compliant" => DeviceComplianceState.Compliant,
        "noncompliant" => DeviceComplianceState.Noncompliant,
        "ingraceperiod" => DeviceComplianceState.InGracePeriod,
        _ => DeviceComplianceState.Unknown // unknown, conflict, error, configManager
    };

    /// <summary>
    /// Flattens policy states into per-setting results. Settings that are not applicable,
    /// not assigned or unknown are dropped: they say nothing about the device's posture.
    /// </summary>
    public static IReadOnlyList<DeviceComplianceSetting> MapSettings(IEnumerable<GraphCompliancePolicyState> policies) =>
        policies
            .Where(p => !IsIgnored(p.State))
            .SelectMany(p => p.SettingStates.Select(s => (Policy: Clean(p.DisplayName) ?? "Compliance policy", Setting: s)))
            .Select(x => (x.Policy, x.Setting, Compliant: SettingCompliant(x.Setting.State)))
            .Where(x => x.Compliant is not null)
            .Select(x => new DeviceComplianceSetting(
                x.Policy,
                SettingLabel(x.Setting),
                x.Compliant!.Value,
                x.Compliant.Value ? null : Clean(x.Setting.ErrorDescription) ?? FailureLabel(x.Setting.State)))
            .ToList();

    private static bool IsIgnored(string? policyState) =>
        policyState?.Trim().ToLowerInvariant() is "notapplicable" or "notassigned";

    private static bool? SettingCompliant(string? state) => state?.Trim().ToLowerInvariant() switch
    {
        "compliant" or "remediated" => true,
        "noncompliant" or "error" or "conflict" => false,
        _ => null // unknown, notApplicable, notAssigned
    };

    private static string FailureLabel(string? state) => state?.Trim().ToLowerInvariant() switch
    {
        "error" => "Intune reported an error evaluating this setting.",
        "conflict" => "Conflicts with another assigned policy.",
        _ => "Not compliant."
    };

    private static string SettingLabel(GraphCompliancePolicySettingState s)
    {
        if (Clean(s.SettingName) is { } name) return name;
        // "Windows10CompliancePolicy.bitLockerEnabled" -> "bitLockerEnabled"
        var raw = Clean(s.Setting) ?? "Unnamed setting";
        var dot = raw.LastIndexOf('.');
        return dot >= 0 && dot < raw.Length - 1 ? raw[(dot + 1)..] : raw;
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    // Graph returns 0001-01-01 for "never".
    private static DateTimeOffset? Clean(DateTimeOffset? d) => d is { Year: > 1 } ? d : null;
}

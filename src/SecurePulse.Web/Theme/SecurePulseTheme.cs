using MudBlazor;
using SecurePulse.Core.Models;
using Severity = SecurePulse.Core.Models.Severity;

namespace SecurePulse.Web.Theme;

/// <summary>
/// Material 3 Expressive–inspired theme: tonal surfaces, bold primary, large corner radii,
/// Roboto Flex. Regenerate the colors with Material Theme Builder when the brand is final.
/// </summary>
public static class SecurePulseTheme
{
    public static readonly MudTheme Theme = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = "#4F46C8",
            PrimaryContrastText = "#FFFFFF",
            Secondary = "#00796B",
            Tertiary = "#B4386A",
            Info = "#2F6FD0",
            Success = "#1E8E5A",
            Warning = "#C77700",
            Error = "#C62828",
            Background = "#F7F5FC",
            BackgroundGray = "#EEEBF7",
            Surface = "#FFFFFF",
            AppbarBackground = "#F7F5FC",
            AppbarText = "#1C1B22",
            DrawerBackground = "#F1EEF9",
            DrawerText = "#1C1B22",
            DrawerIcon = "#4F46C8",
            TextPrimary = "#1C1B22",
            TextSecondary = "#5E5A6E",
            LinesDefault = "#E2DEEE",
            TableLines = "#ECE9F4"
        },
        PaletteDark = new PaletteDark
        {
            Primary = "#BDB6FF",
            PrimaryContrastText = "#20155F",
            Secondary = "#6FD8C6",
            Tertiary = "#FFB0CB",
            Info = "#9DC2FF",
            Success = "#7CD9A6",
            Warning = "#FFC46B",
            Error = "#FFB4AB",
            Background = "#131218",
            BackgroundGray = "#1E1C25",
            Surface = "#1C1B22",
            AppbarBackground = "#131218",
            AppbarText = "#E6E1EE",
            DrawerBackground = "#18171E",
            DrawerText = "#E6E1EE",
            DrawerIcon = "#BDB6FF",
            TextPrimary = "#E6E1EE",
            TextSecondary = "#B1ABC2",
            LinesDefault = "#2E2B38",
            TableLines = "#2A2733"
        },
        LayoutProperties = new LayoutProperties
        {
            DefaultBorderRadius = "16px",
            DrawerWidthLeft = "272px"
        },
        Typography = new Typography
        {
            Default = new DefaultTypography
            {
                FontFamily = ["Roboto Flex", "Roboto", "Segoe UI", "sans-serif"]
            },
            Button = new ButtonTypography
            {
                FontFamily = ["Roboto Flex", "Roboto", "Segoe UI", "sans-serif"],
                TextTransform = "none"
            }
        }
    };

    public static Color ColorOf(Severity severity) => severity switch
    {
        Severity.Critical => Color.Error,
        Severity.High => Color.Warning,
        Severity.Medium => Color.Info,
        Severity.Low => Color.Default,
        _ => Color.Dark
    };

    public static Color ColorOf(FindingStatus status) => status switch
    {
        FindingStatus.Passed => Color.Success,
        FindingStatus.Failed => Color.Error,
        FindingStatus.Investigate => Color.Warning,
        _ => Color.Default
    };

    public static Color ColorOfScore(int score) => score switch
    {
        >= 80 => Color.Success,
        >= 60 => Color.Warning,
        _ => Color.Error
    };

    public static string Label(FindingStatus status) => status switch
    {
        FindingStatus.NotEvaluated => "Not evaluated",
        _ => status.ToString()
    };

    public static Color ColorOf(DeviceComplianceState state) => state switch
    {
        DeviceComplianceState.Compliant => Color.Success,
        DeviceComplianceState.InGracePeriod => Color.Warning,
        DeviceComplianceState.Noncompliant => Color.Error,
        _ => Color.Default
    };

    public static string Label(DeviceComplianceState state) => state switch
    {
        DeviceComplianceState.InGracePeriod => "In grace period",
        _ => state.ToString()
    };

    public static string IconOf(DevicePlatform platform) => platform switch
    {
        DevicePlatform.Windows => Icons.Material.Rounded.LaptopWindows,
        DevicePlatform.MacOS => Icons.Material.Rounded.LaptopMac,
        DevicePlatform.iOS => Icons.Material.Rounded.PhoneIphone,
        DevicePlatform.Android => Icons.Material.Rounded.PhoneAndroid,
        _ => Icons.Material.Rounded.Computer
    };

    public static string Label(DevicePlatform platform) => platform switch
    {
        DevicePlatform.MacOS => "macOS",
        _ => platform.ToString()
    };

    public static string Label(DefenderState state) => state switch
    {
        DefenderState.Protected => "Protected",
        DefenderState.Unhealthy => "Unhealthy",
        DefenderState.NotOnboarded => "Not onboarded",
        _ => "Unknown"
    };

    public static Color ColorOf(DefenderState state) => state switch
    {
        DefenderState.Protected => Color.Success,
        DefenderState.Unhealthy => Color.Error,
        DefenderState.NotOnboarded => Color.Warning,
        _ => Color.Default
    };

    public static string IconOf(DefenderState state) => state switch
    {
        DefenderState.Protected => Icons.Material.Rounded.GppGood,
        DefenderState.Unhealthy => Icons.Material.Rounded.GppBad,
        DefenderState.NotOnboarded => Icons.Material.Rounded.GppMaybe,
        _ => Icons.Material.Rounded.Shield
    };

    public static string Label(DefenderOnboarding status) => status switch
    {
        DefenderOnboarding.Onboarded => "Onboarded",
        DefenderOnboarding.CanBeOnboarded => "Not onboarded (discovered on the network)",
        DefenderOnboarding.Unsupported => "Unsupported OS",
        DefenderOnboarding.InsufficientInfo => "Insufficient information",
        _ => "Unknown"
    };

    public static string Label(DefenderSensorHealth health) => health switch
    {
        DefenderSensorHealth.Active => "Active",
        DefenderSensorHealth.Inactive => "Inactive",
        DefenderSensorHealth.ImpairedCommunication => "Impaired communication",
        DefenderSensorHealth.NoSensorData => "No sensor data",
        _ => "Unknown"
    };

    public static Color ColorOf(DefenderSensorHealth health) => health switch
    {
        DefenderSensorHealth.Active => Color.Success,
        DefenderSensorHealth.Unknown => Color.Default,
        _ => Color.Error
    };

    public static string Label(DefenderThreatState state) => state switch
    {
        DefenderThreatState.Clean => "No active threats",
        DefenderThreatState.FullScanPending => "Full scan pending",
        DefenderThreatState.RebootPending => "Restart pending",
        DefenderThreatState.ManualStepsPending => "Manual steps pending",
        DefenderThreatState.OfflineScanPending => "Offline scan pending",
        DefenderThreatState.Critical => "Critical",
        _ => "Not reported"
    };

    public static Color ColorOf(DefenderThreatState state) => state switch
    {
        DefenderThreatState.Clean => Color.Success,
        DefenderThreatState.Unknown => Color.Default,
        _ => Color.Error
    };

    public static string Label(OnboardingRequest request, DateTimeOffset now) => request.Status switch
    {
        _ when request.IsExpired(now) => "Link expired",
        OnboardingStatus.AwaitingConsent => "Awaiting consent",
        OnboardingStatus.Verifying => "Verifying",
        OnboardingStatus.Completed => "Connected",
        OnboardingStatus.Failed => "Failed",
        _ => "Cancelled"
    };

    public static Color ColorOf(OnboardingRequest request, DateTimeOffset now) => request.Status switch
    {
        _ when request.IsExpired(now) => Color.Default,
        OnboardingStatus.AwaitingConsent => Color.Info,
        OnboardingStatus.Verifying => Color.Primary,
        OnboardingStatus.Completed => Color.Success,
        OnboardingStatus.Failed => Color.Error,
        _ => Color.Default
    };
}

using MudBlazor;
using SecurePulse.Core.Models;
using Severity = SecurePulse.Core.Models.Severity;

namespace SecurePulse.Web.Theme;

/// <summary>
/// Material 3 Expressive-inspired workspace with Google Sans Flex, generous shapes,
/// tonal containers, and the Viresta-inspired charcoal and orange palette.
/// </summary>
public static class SecurePulseTheme
{
    public static readonly MudTheme Theme = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = "#B84216",
            PrimaryContrastText = "#FFFFFF",
            // Slate and bronze sit beside the charcoal-and-orange brand (the old theme's teal and pink didn't).
            Secondary = "#3F5463",
            SecondaryContrastText = "#FFFFFF",
            Tertiary = "#7A5230",
            TertiaryContrastText = "#FFFFFF",
            Info = "#2F6FD0",
            Success = "#1E8E5A",
            Warning = "#C77700",
            Error = "#C62828",
            Background = "#F5F7FA",
            BackgroundGray = "#EDF2F5",
            Surface = "#FFFFFF",
            AppbarBackground = "#FFFFFF",
            AppbarText = "#172B3A",
            DrawerBackground = "#FFFFFF",
            DrawerText = "#172B3A",
            DrawerIcon = "#718291",
            TextPrimary = "#172B3A",
            TextSecondary = "#687B8A",
            LinesDefault = "#E3EAEE",
            TableLines = "#EDF1F4"
        },
        PaletteDark = new PaletteDark
        {
            Primary = "#EA642A",
            PrimaryContrastText = "#0B0B0B",
            Secondary = "#B9C6CF",
            SecondaryContrastText = "#0B0B0B",
            Tertiary = "#E5BE94",
            TertiaryContrastText = "#0B0B0B",
            Info = "#9DC2FF",
            Success = "#7CD9A6",
            Warning = "#FFC46B",
            Error = "#FFB4AB",
            Background = "#0B0B0B",
            BackgroundGray = "#232323",
            Surface = "#151515",
            AppbarBackground = "#0B0B0B",
            AppbarText = "#FFFFFF",
            DrawerBackground = "#111111",
            DrawerText = "#FFFFFF",
            DrawerIcon = "#A3A3A3",
            TextPrimary = "#FFFFFF",
            TextSecondary = "#B8B8B8",
            LinesDefault = "#333333",
            TableLines = "#292929"
        },
        LayoutProperties = new LayoutProperties
        {
            DefaultBorderRadius = "24px",
            DrawerWidthLeft = "244px"
        },
        Typography = new Typography
        {
            Default = new DefaultTypography
            {
                FontFamily = ["Google Sans Flex", "Segoe UI", "sans-serif"]
            },
            Button = new ButtonTypography
            {
                FontFamily = ["Google Sans Flex", "Segoe UI", "sans-serif"],
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

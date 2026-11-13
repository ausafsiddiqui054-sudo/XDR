using MudBlazor;
using SecurePulse.Core.Models;
using Severity = SecurePulse.Core.Models.Severity;

namespace SecurePulse.Web.Theme;

/// <summary>
/// Material 3 Expressive-inspired workspace with Google Sans Flex, generous shapes,
/// tonal containers, and the Hasinix falcon's palette: navy, orange and a teal accent.
/// </summary>
public static class SecurePulseTheme
{
    public static readonly MudTheme Theme = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = "#C2410C",
            PrimaryContrastText = "#FFFFFF",
            // Mint is an accent; darker teal keeps secondary text readable on light surfaces.
            Secondary = "#087E68",
            SecondaryContrastText = "#FFFFFF",
            Tertiary = "#3F5F7F",
            TertiaryContrastText = "#FFFFFF",
            Info = "#2F6FD0",
            Success = "#1E8E5A",
            Warning = "#C77700",
            Error = "#C62828",
            Background = "#F6F8FB",
            BackgroundGray = "#E9EEF4",
            Surface = "#FFFFFF",
            AppbarBackground = "#FFFFFF",
            AppbarText = "#0F2233",
            DrawerBackground = "#FFFFFF",
            DrawerText = "#0F2233",
            DrawerIcon = "#7C8A99",
            TextPrimary = "#0F2233",
            TextSecondary = "#5B6B7B",
            LinesDefault = "#DEE5EC",
            TableLines = "#EEF2F6"
        },
        PaletteDark = new PaletteDark
        {
            Primary = "#FF8A4C",
            PrimaryContrastText = "#2A0F02",
            Secondary = "#45D6B0",
            SecondaryContrastText = "#052C24",
            Tertiary = "#A9C4E0",
            TertiaryContrastText = "#0F2233",
            Info = "#9DC2FF",
            Success = "#7CD9A6",
            Warning = "#FFC46B",
            Error = "#FFB4AB",
            Background = "#07121D",
            BackgroundGray = "#1A2B3D",
            Surface = "#0E1D2C",
            AppbarBackground = "#0B1826",
            AppbarText = "#F4F8FC",
            DrawerBackground = "#0B1826",
            DrawerText = "#F4F8FC",
            DrawerIcon = "#93A6B8",
            TextPrimary = "#F4F8FC",
            TextSecondary = "#B4C3D2",
            LinesDefault = "#22374B",
            TableLines = "#1A2C3E"
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

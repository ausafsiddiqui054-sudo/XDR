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
}

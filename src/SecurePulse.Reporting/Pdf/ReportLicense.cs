using QuestPDF.Infrastructure;

namespace SecurePulse.Reporting.Pdf;

/// <summary>
/// QuestPDF needs its license tier declared before it generates anything. That's an organisational
/// decision (Community is free only under USD 1M annual gross revenue, and never for public-sector
/// bodies or listed companies), so it comes from configuration and is never defaulted here.
/// </summary>
public static class ReportLicense
{
    public const string SettingName = "Reports:QuestPdfLicense";

    /// <summary>The configured tier, or null when the setting is empty or not a QuestPDF tier.</summary>
    public static LicenseType? Parse(string? configured) =>
        configured?.Trim().ToLowerInvariant() switch
        {
            "community" => LicenseType.Community,
            "professional" => LicenseType.Professional,
            "enterprise" => LicenseType.Enterprise,
            _ => null
        };

    /// <summary>Declares the tier to QuestPDF. Returns false (and leaves reports disabled) when it isn't set.</summary>
    public static bool Apply(string? configured)
    {
        if (Parse(configured) is not { } license) return false;
        QuestPDF.Settings.License = license;
        return true;
    }

    public static bool IsApplied => QuestPDF.Settings.License is not null;
}

/// <summary>Reports were requested before <see cref="ReportLicense.SettingName"/> was set.</summary>
public sealed class ReportLicenseMissingException() : InvalidOperationException(
    $"PDF reports are off until {ReportLicense.SettingName} is set to the QuestPDF license tier your organisation holds " +
    "(Community, Professional or Enterprise). See https://www.questpdf.com/license/guide.html.");

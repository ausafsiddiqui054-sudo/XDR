using QuestPDF.Drawing;

namespace SecurePulse.Reporting.Pdf;

/// <summary>
/// Fonts for reports: QuestPDF's bundled Lato (Latin, Greek, Cyrillic) with Noto Sans Arabic as
/// fallback, since tenant, device and user names in the region are often Arabic. Since QuestPDF
/// 2026.9, system fonts aren't used as fallbacks, so the Arabic font ships embedded in this assembly.
/// </summary>
internal static class ReportFonts
{
    public static readonly string[] Families = ["Lato", "Noto Sans Arabic"];

    private static readonly Lazy<bool> Registered = new(() =>
    {
        var assembly = typeof(ReportFonts).Assembly;
        foreach (var name in assembly.GetManifestResourceNames().Where(n => n.StartsWith("SecurePulse.Reporting.Fonts.", StringComparison.Ordinal)))
            FontManager.RegisterFontFromEmbeddedResource(assembly, name);

        // A character no bundled font covers (another script, an emoji in a device name) prints as a
        // placeholder instead of failing the whole report.
        QuestPDF.Settings.ThrowOnMissingTextGlyphs = false;
        return true;
    });

    /// <summary>Registers the fonts once, before the first report is generated.</summary>
    public static void EnsureRegistered() => _ = Registered.Value;
}

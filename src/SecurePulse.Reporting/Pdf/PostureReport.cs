using QuestPDF.Fluent;

namespace SecurePulse.Reporting.Pdf;

public static class PostureReport
{
    /// <summary>Renders the report as PDF bytes.</summary>
    /// <exception cref="ReportLicenseMissingException">The QuestPDF license tier hasn't been configured.</exception>
    public static byte[] Render(PostureReportData data)
    {
        if (!ReportLicense.IsApplied) throw new ReportLicenseMissingException();
        ReportFonts.EnsureRegistered();
        return new PostureReportDocument(data).GeneratePdf();
    }
}

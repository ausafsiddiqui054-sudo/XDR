using System.Text;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Reporting;
using SecurePulse.Reporting.Pdf;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

/// <summary>The "Reports" settings section.</summary>
public sealed class ReportOptions
{
    /// <summary>QuestPDF license tier your organisation holds: Community, Professional or Enterprise. Empty turns reports off.</summary>
    public string QuestPdfLicense { get; set; } = string.Empty;

    /// <summary>IANA or Windows time zone for dates in reports, e.g. "Asia/Dubai".</summary>
    public string TimeZone { get; set; } = "UTC";

    public BrandingOptions Branding { get; set; } = new();

    public sealed class BrandingOptions
    {
        public string CompanyName { get; set; } = "SecurePulse";

        /// <summary>PNG, JPEG or SVG file shown on the cover. Empty draws the default shield.</summary>
        public string LogoPath { get; set; } = string.Empty;

        public string AccentColor { get; set; } = "#4F46C8";
        public string ContactLine { get; set; } = string.Empty;
    }
}

/// <summary>Branding and time zone, checked and loaded once at startup.</summary>
public sealed class ReportSettings
{
    public const int MaxLogoBytes = 1024 * 1024;

    public required bool Enabled { get; init; }
    public required ReportBranding Branding { get; init; }
    public required TimeZoneInfo TimeZone { get; init; }

    /// <summary>Validates the section and applies the QuestPDF license tier. Throws on settings that would produce a broken report.</summary>
    public static ReportSettings Load(ReportOptions options, string contentRoot)
    {
        var b = options.Branding;
        if (b.AccentColor is not { Length: 7 } color || color[0] != '#' || !color.Skip(1).All(Uri.IsHexDigit))
            throw new InvalidOperationException("Reports:Branding:AccentColor must be a #RRGGBB colour.");
        if (string.IsNullOrWhiteSpace(b.CompanyName) || b.CompanyName.Length > 100)
            throw new InvalidOperationException("Reports:Branding:CompanyName must be 1–100 characters.");
        if (!System.TimeZoneInfo.TryFindSystemTimeZoneById(options.TimeZone, out var timeZone))
            throw new InvalidOperationException($"Reports:TimeZone '{options.TimeZone}' isn't a known time zone (e.g. \"Asia/Dubai\").");

        byte[]? logo = null;
        if (!string.IsNullOrWhiteSpace(b.LogoPath))
        {
            var path = Path.GetFullPath(b.LogoPath, contentRoot);
            var extension = Path.GetExtension(path).ToLowerInvariant();
            if (extension is not (".png" or ".jpg" or ".jpeg" or ".svg"))
                throw new InvalidOperationException("Reports:Branding:LogoPath must be a .png, .jpg or .svg file.");
            var file = new FileInfo(path);
            if (!file.Exists) throw new InvalidOperationException($"Reports:Branding:LogoPath file not found: {path}");
            if (file.Length > MaxLogoBytes) throw new InvalidOperationException("Reports:Branding:LogoPath must be 1 MB or smaller.");
            logo = File.ReadAllBytes(path);
        }

        return new ReportSettings
        {
            Enabled = ReportLicense.Apply(options.QuestPdfLicense),
            TimeZone = timeZone,
            Branding = new ReportBranding
            {
                CompanyName = b.CompanyName.Trim(),
                Logo = logo,
                AccentColor = b.AccentColor,
                ContactLine = string.IsNullOrWhiteSpace(b.ContactLine) ? null : b.ContactLine.Trim()
            }
        };
    }
}

public enum ReportOutcome
{
    Created,
    /// <summary>No such tenant, or one the user can't see (both look the same).</summary>
    NotFound,
    NoResults,
    Disabled
}

public sealed record ReportFile(ReportOutcome Outcome, byte[]? Pdf = null, string? FileName = null);

/// <summary>Builds a tenant's posture report for a user and records the download.</summary>
public sealed class ReportService(
    ITenantRepository tenants,
    IFindingRepository findings,
    IDeviceRepository devices,
    AuditTrail audit,
    ReportSettings settings,
    TimeProvider time)
{
    public bool Enabled => settings.Enabled;

    /// <param name="user">The requester, from the HTTP request (downloads are plain requests, not a Blazor circuit).</param>
    public async Task<ReportFile> CreateAsync(Guid tenantId, UserContext user, string? ipAddress = null, CancellationToken ct = default)
    {
        if (!user.CanSee(tenantId) || await tenants.GetAsync(tenantId, ct) is not { } tenant)
            return new ReportFile(ReportOutcome.NotFound);
        if (!settings.Enabled)
            return new ReportFile(ReportOutcome.Disabled);

        var results = await findings.GetForTenantAsync(tenant.Id, ct);
        if (results.Count == 0)
            return new ReportFile(ReportOutcome.NoResults);

        var inventory = await devices.GetForTenantAsync(tenant.Id, ct);
        var sync = await devices.GetSyncStatusAsync(tenant.Id, ct);
        var now = time.GetUtcNow();
        var pdf = PostureReport.Render(new PostureReportData
        {
            Tenant = tenant,
            Score = RiskScoreCalculator.Calculate(results),
            Findings = results,
            GeneratedAt = now,
            Branding = settings.Branding,
            Devices = inventory.Count > 0 ? DeviceSummary.From(inventory, sync?.LastSuccessAt) : null,
            TimeZone = settings.TimeZone
        });

        await audit.RecordAsync(AuditActions.ReportDownloaded, AuditOutcome.Success, $"Downloaded the posture report for {tenant.DisplayName}",
            tenant.Id, "Tenant", tenant.Id.ToString(), new Dictionary<string, string> { ["findings"] = results.Count.ToString() },
            actor: user, ipAddress: ipAddress);

        return new ReportFile(ReportOutcome.Created, pdf, FileName(tenant, TimeZoneInfo.ConvertTime(now, settings.TimeZone)));
    }

    /// <summary>"Security-posture-al-noor-family-clinic-2026-10-14.pdf": ASCII letters, digits and hyphens only.</summary>
    public static string FileName(Tenant tenant, DateTimeOffset at)
    {
        var slug = new StringBuilder();
        foreach (var ch in tenant.DisplayName.Normalize(NormalizationForm.FormKD).ToLowerInvariant())
        {
            if (System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) == System.Globalization.UnicodeCategory.NonSpacingMark) continue; // é → e
            if (ch is >= 'a' and <= 'z' or >= '0' and <= '9') slug.Append(ch);
            else if (slug.Length > 0 && slug[^1] != '-') slug.Append('-');
            if (slug.Length >= 60) break;
        }
        var name = slug.ToString().Trim('-');
        return $"Security-posture-{(name.Length > 0 ? name : "tenant")}-{at:yyyy-MM-dd}.pdf";
    }

    public static void MapReportDownload(WebApplication app) =>
        app.MapGet("/reports/{tenantId:guid}/posture.pdf", async (Guid tenantId, ReportService reports, HttpContext http, CancellationToken ct) =>
        {
            var file = await reports.CreateAsync(tenantId, UserContext.From(http.User), http.Connection.RemoteIpAddress?.ToString(), ct);
            http.Response.Headers.CacheControl = "no-store";
            return file.Outcome switch
            {
                ReportOutcome.Created => Results.File(file.Pdf!, "application/pdf", file.FileName),
                ReportOutcome.NoResults => Results.Text("This tenant has no scan results yet, so there is nothing to report.", statusCode: StatusCodes.Status409Conflict),
                ReportOutcome.Disabled => Results.Text(new ReportLicenseMissingException().Message, statusCode: StatusCodes.Status503ServiceUnavailable),
                _ => Results.NotFound()
            };
        }).RequireAuthorization(Policies.Member);
}

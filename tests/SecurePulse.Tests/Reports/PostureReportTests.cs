using SecurePulse.Core.Models;
using SecurePulse.Engines.Maester;
using SecurePulse.Engines.ScubaGear;
using SecurePulse.Reporting;
using SecurePulse.Reporting.Pdf;
using UglyToad.PdfPig;

namespace SecurePulse.Tests.Reports;

/// <summary>QuestPDF's license is process-wide, so everything that renders or changes it runs in this one non-parallel collection.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class QuestPdfCollection
{
    public const string Name = "QuestPDF";
}

/// <summary>Helpers shared by the report tests.</summary>
public static class ReportPdf
{
    /// <summary>Declares a tier for tests (development and evaluation). Production takes it from Reports:QuestPdfLicense.</summary>
    public static void License() => ReportLicense.Apply("Community");

    public static string Text(byte[] pdf)
    {
        using var doc = PdfDocument.Open(pdf);
        return string.Join("\n", doc.GetPages().Select(p => string.Join(" ", p.GetWords().Select(w => w.Text))));
    }
}

[Collection(QuestPdfCollection.Name)]
public class PostureReportTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 14, 5, 30, 0, TimeSpan.Zero);

    private static readonly Tenant Tenant = new()
    {
        Id = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000042"), EntraTenantId = Guid.NewGuid(), DisplayName = "Al Noor Family Clinic",
        PrimaryDomain = "alnoorclinic.example", Industry = "Healthcare", PartnerName = "Gulf IT Services", ConsentState = TenantConsentState.ReadOnlyGranted
    };

    private static IReadOnlyList<Finding> SampleFindings() =>
        MaesterResultParser.Parse(File.ReadAllText(Sample("maester-results.sample.json")), Tenant.Id, At)
            .Concat(ScubaGearResultParser.Parse(File.ReadAllText(Sample("scubagear-results.sample.json")), Tenant.Id, At))
            .ToList();

    private static string Sample(string name) => Path.Combine(AppContext.BaseDirectory, "samples", name);

    private static PostureReportData Data(IReadOnlyList<Finding>? findings = null, DeviceSummary? devices = null, ReportBranding? branding = null)
    {
        findings ??= SampleFindings();
        return new PostureReportData
        {
            Tenant = Tenant, Score = RiskScoreCalculator.Calculate(findings), Findings = findings, GeneratedAt = At,
            Branding = branding ?? new ReportBranding(), Devices = devices, TimeZone = TimeZoneInfo.FindSystemTimeZoneById("Asia/Dubai")
        };
    }

    private static byte[] Render(PostureReportData data)
    {
        ReportPdf.License();
        return PostureReport.Render(data);
    }

    private static Finding F(string id, string title, FindingStatus status, Severity severity = Severity.High, string? evidence = null, string? help = null) => new()
    {
        Id = $"test:{id}", TenantId = Tenant.Id, Source = "Maester", SourceCheckId = id, Title = title, Severity = severity, Status = status,
        Category = "Identity", Evidence = evidence, HelpUrl = help, DetectedAt = At
    };

    [Fact]
    public void RendersTheReportFromRealEngineOutput()
    {
        var data = Data(devices: DeviceSummary.From(
        [
            new ManagedDevice { Id = "1", TenantId = Tenant.Id, DeviceName = "ALN-RECEPTION-01", Platform = DevicePlatform.Windows, ComplianceState = DeviceComplianceState.Noncompliant, LastSyncAt = At.AddDays(-9) },
            new ManagedDevice { Id = "2", TenantId = Tenant.Id, DeviceName = "ALN-DOCTOR-02", Platform = DevicePlatform.MacOS, ComplianceState = DeviceComplianceState.Compliant }
        ], At));

        var pdf = Render(data);

        using var doc = PdfDocument.Open(pdf);
        Assert.True(doc.NumberOfPages >= 4);
        Assert.Equal("Microsoft 365 security posture: Al Noor Family Clinic", doc.Information.Title);
        Assert.Equal("Gulf IT Services", doc.Information.Author);

        var text = ReportPdf.Text(pdf);
        Assert.Contains("Microsoft 365 security posture", text);
        Assert.Contains("Prepared for Al Noor Family Clinic by Gulf IT Services", text); // the partner brands its clients' reports
        Assert.Contains($"Score {data.Score.Score} of 100", text);
        Assert.Contains($"Grade {data.Score.Grade}", text);
        Assert.Contains("Report date 14 October 2026", text);
        Assert.Contains("Fix these first", text);
        Assert.Contains(RiskScoreCalculator.TopRisks(data.Findings, 1)[0].Title, text);
        Assert.Contains("Results by area", text);
        Assert.Contains("Device compliance", text);
        Assert.Contains("ALN-RECEPTION-01", text);
        Assert.DoesNotContain("ALN-DOCTOR-02", text); // only non-compliant devices are listed
        Assert.Contains("5 Oct 2026, 09:30 UTC+4", text); // last check-in, in the configured time zone
        Assert.Contains($"Findings to fix ({data.Score.Failed + data.Score.Investigate})", text);
        Assert.Contains($"Checks that pass ({data.Score.Passed})", text);
        Assert.Contains("MS.AAD.1.1v1", text);
        Assert.Contains("About this report", text);
        Assert.Contains("Critical 10, High 6, Medium 3, Low 1, Info 0", text); // weights come from RiskScoreCalculator
        Assert.Contains("Page 2 of", text);
    }

    [Fact]
    public void WithoutAPartnerTheDeploymentBrandIsUsed()
    {
        var text = ReportPdf.Text(Render(Data() with
        {
            Tenant = Tenant with { PartnerName = null },
            Branding = new ReportBranding { CompanyName = "Novomed Security", ContactLine = "security@novomed.example" }
        }));

        Assert.Contains("by Novomed Security", text);
        Assert.Contains("security@novomed.example", text);
        Assert.Contains("Novomed Security · Confidential", text);
    }

    [Fact]
    public void NoDevicesMeansNoDeviceSection()
    {
        Assert.DoesNotContain("Device compliance", ReportPdf.Text(Render(Data())));
    }

    [Fact]
    public void ACleanTenantSaysNothingIsOpen()
    {
        var text = ReportPdf.Text(Render(Data([F("A", "MFA for admins", FindingStatus.Passed), F("B", "Legacy auth blocked", FindingStatus.Passed)])));

        Assert.Contains("Nothing open: every evaluated check passes.", text);
        Assert.Contains("No open findings.", text);
        Assert.Contains("Score 100 of 100", text);
    }

    [Fact]
    public void LongUnbrokenTextAndManyFindingsStillLayOut()
    {
        var findings = Enumerable.Range(1, 250)
            .Select(i => F($"T{i}", $"Check {i} " + new string('x', 300), i % 3 == 0 ? FindingStatus.Passed : FindingStatus.Failed,
                evidence: new string('y', 2000)))
            .ToList();

        var pdf = Render(Data(findings));

        using var doc = PdfDocument.Open(pdf);
        Assert.True(doc.NumberOfPages > 20);
        Assert.Contains("…", ReportPdf.Text(pdf)); // evidence is clipped
    }

    [Fact]
    public void OnlyHttpsHelpLinksBecomeHyperlinks()
    {
        var pdf = Render(Data(
        [
            F("SAFE", "Safe link", FindingStatus.Failed, help: "https://maester.dev/docs/tests/MT.1001"),
            F("JS", "Script link", FindingStatus.Failed, help: "javascript:alert(1)"),
            F("HTTP", "Plain http link", FindingStatus.Failed, help: "http://example.com/x"),
            F("OK", "Passing", FindingStatus.Passed)
        ]));

        using var doc = PdfDocument.Open(pdf);
        var links = doc.GetPages().SelectMany(p => p.GetHyperlinks()).Select(h => h.Uri).Where(u => u is not null).ToList();
        Assert.Equal(["https://maester.dev/docs/tests/MT.1001"], links);
    }

    [Fact]
    public void CustomLogosRender()
    {
        // A 1×1 PNG and a tiny SVG.
        var png = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");
        var svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\"><rect width=\"10\" height=\"10\" fill=\"#00796B\"/></svg>"u8.ToArray();

        foreach (var logo in new[] { png, svg })
            Assert.True(Render(Data(branding: new ReportBranding { Logo = logo, AccentColor = "#00796B" })).Length > 1000);
        // A bad accent colour falls back instead of failing the report.
        Assert.True(Render(Data(branding: new ReportBranding { AccentColor = "red; drop" })).Length > 1000);
    }

    [Fact]
    public void ArabicNamesUseTheBundledArabicFont()
    {
        var pdf = Render(Data() with { Tenant = Tenant with { DisplayName = "عيادة النور الطبية", PartnerName = "شركة الخليج" } });

        using var doc = PdfDocument.Open(pdf);
        var fonts = doc.GetPage(1).Letters.Select(l => l.FontName ?? "").Distinct().ToList();
        Assert.Contains(fonts, f => f.Contains("NotoSansArabic"));
        Assert.Contains(fonts, f => f.Contains("Lato"));
    }

    [Fact]
    public void CharactersNoBundledFontCoversDontFailTheReport()
    {
        var devices = DeviceSummary.From(
        [
            new ManagedDevice { Id = "1", TenantId = Tenant.Id, DeviceName = "受付PC 🖥️ ✓", Platform = DevicePlatform.Windows, ComplianceState = DeviceComplianceState.Noncompliant }
        ], At);

        Assert.True(Render(Data(devices: devices)).Length > 1000);
    }

    [Fact]
    public void RenderingIsRefusedUntilALicenseTierIsConfigured()
    {
        var previous = QuestPDF.Settings.License;
        try
        {
            QuestPDF.Settings.License = null;
            var ex = Assert.Throws<ReportLicenseMissingException>(() => PostureReport.Render(Data()));
            Assert.Contains(ReportLicense.SettingName, ex.Message);
            Assert.False(ReportLicense.Apply(""));
            Assert.False(ReportLicense.Apply("Free"));
            Assert.False(ReportLicense.IsApplied);
        }
        finally
        {
            QuestPDF.Settings.License = previous;
        }
    }

    [Theory]
    [InlineData("Community", QuestPDF.Infrastructure.LicenseType.Community)]
    [InlineData(" professional ", QuestPDF.Infrastructure.LicenseType.Professional)]
    [InlineData("ENTERPRISE", QuestPDF.Infrastructure.LicenseType.Enterprise)]
    [InlineData("", null)]
    [InlineData(null, null)]
    [InlineData("Evaluation", null)]
    public void ParsesOnlyRealTiers(string? configured, QuestPDF.Infrastructure.LicenseType? expected) =>
        Assert.Equal(expected, ReportLicense.Parse(configured));

    [Fact]
    public void DeviceSummaryCountsAndListsTheStalestNoncompliantDevices()
    {
        var devices = Enumerable.Range(1, 30).Select(i => new ManagedDevice
        {
            Id = $"{i}", TenantId = Tenant.Id, DeviceName = $"PC-{i:00}", Platform = DevicePlatform.Windows, LastSyncAt = At.AddDays(-i),
            ComplianceState = i switch { <= 20 => DeviceComplianceState.Noncompliant, <= 25 => DeviceComplianceState.Compliant, 26 => DeviceComplianceState.InGracePeriod, _ => DeviceComplianceState.Unknown }
        }).ToList();

        var summary = DeviceSummary.From(devices, At, listLimit: 3);

        Assert.Equal((30, 5, 1, 20, 4), (summary.Total, summary.Compliant, summary.InGracePeriod, summary.Noncompliant, summary.Unknown));
        Assert.Equal(["PC-20", "PC-19", "PC-18"], summary.NoncompliantDevices.Select(d => d.Name));
    }

    private static ManagedDevice WithDefender(string name, DevicePlatform platform, DefenderAntivirusStatus? av, DefenderSensorStatus? sensor)
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(platform, av, sensor, sensorDataAvailable: true);
        return new ManagedDevice
        {
            Id = name, TenantId = Tenant.Id, DeviceName = name, Platform = platform, ComplianceState = DeviceComplianceState.Compliant,
            Defender = state, DefenderDetails = health
        };
    }

    [Fact]
    public void DeviceSummaryCountsDefenderStatesAndTopIssues()
    {
        var healthyAv = new DefenderAntivirusStatus { MalwareProtectionEnabled = true, RealTimeProtectionEnabled = true };
        var active = new DefenderSensorStatus { Onboarding = DefenderOnboarding.Onboarded, Health = DefenderSensorHealth.Active };
        var devices = new List<ManagedDevice>
        {
            WithDefender("PC-1", DevicePlatform.Windows, healthyAv, active),
            WithDefender("PC-2", DevicePlatform.Windows, healthyAv with { RealTimeProtectionEnabled = false }, active),
            WithDefender("PC-3", DevicePlatform.Windows, healthyAv with { RealTimeProtectionEnabled = false }, null),
            WithDefender("MAC-1", DevicePlatform.MacOS, null, null),
            WithDefender("IPHONE-1", DevicePlatform.iOS, null, null)
        };

        var summary = DeviceSummary.From(devices, At);

        Assert.Equal(1, summary.Defender[DefenderState.Protected]);
        Assert.Equal(2, summary.Defender[DefenderState.Unhealthy]);
        Assert.Equal(1, summary.Defender[DefenderState.NotOnboarded]);
        Assert.Equal(1, summary.Defender[DefenderState.Unknown]);
        Assert.Equal([("Not onboarded to Defender for Endpoint.", 2), ("Real-time protection is off.", 2)], summary.DefenderIssues);
    }

    [Fact]
    public void DefenderSectionAppearsOnlyWithDefenderData()
    {
        var without = ReportPdf.Text(Render(Data(devices: DeviceSummary.From(
            [new ManagedDevice { Id = "1", TenantId = Tenant.Id, DeviceName = "PC-1", Platform = DevicePlatform.Windows, ComplianceState = DeviceComplianceState.Compliant }], At))));
        Assert.Empty(DeviceSummary.From([], At).Defender);
        Assert.DoesNotContain("Microsoft Defender", without);

        var with = ReportPdf.Text(Render(Data(devices: DeviceSummary.From(
            [WithDefender("PC-1", DevicePlatform.Windows, new DefenderAntivirusStatus { MalwareProtectionEnabled = true, RealTimeProtectionEnabled = false }, null)], At))));
        Assert.Contains("Microsoft Defender", with);
        Assert.Contains("Most common Defender issues", with);
        Assert.Contains("Real-time protection is off.", with);
        Assert.Contains("Not onboarded", with);
    }
}

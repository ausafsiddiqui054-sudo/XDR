using System.Globalization;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecurePulse.Core.Models;

namespace SecurePulse.Reporting.Pdf;

/// <summary>
/// The client-ready posture report: cover, summary, what to fix first, results by area, device
/// compliance, every finding to fix, the checks that passed, and how the score works. All numbers
/// come from <see cref="PostureReportData"/>; the score is <see cref="RiskScoreCalculator"/>'s.
/// </summary>
public sealed class PostureReportDocument(PostureReportData data) : IDocument
{
    private const int MaxEvidenceLength = 700;
    private static readonly CultureInfo Culture = CultureInfo.GetCultureInfo("en-GB");

    private const string Ink = "#1C1B22";
    private const string Muted = "#5E5A6E";
    private const string Hairline = "#E2DEEE";
    private const string Tint = "#F4F2FB";
    private const string Pass = "#1E8E5A";
    private const string Fail = "#C62828";
    private const string Amber = "#C77700";

    private string Accent => IsHexColor(data.Branding.AccentColor) ? data.Branding.AccentColor : "#4F46C8";
    private string From => data.Tenant.PartnerName is { Length: > 0 } partner ? partner : data.Branding.CompanyName;

    public DocumentMetadata GetMetadata() => new()
    {
        Title = $"Microsoft 365 security posture: {data.Tenant.DisplayName}",
        Author = From,
        Subject = $"Security posture of {data.Tenant.PrimaryDomain} on {Date(data.GeneratedAt)}",
        Keywords = "Microsoft 365, Entra ID, security posture",
        Creator = "SecurePulse",
        Producer = "SecurePulse",
        CreationDate = data.GeneratedAt,
        ModifiedDate = data.GeneratedAt
    };

    public DocumentSettings GetSettings() => DocumentSettings.Default;

    public void Compose(IDocumentContainer container)
    {
        container.Page(page =>
        {
            Setup(page);
            page.Content().Element(Cover);
        });

        container.Page(page =>
        {
            Setup(page);
            page.Header().Element(Header);
            page.Content().PaddingVertical(12).Column(col =>
            {
                col.Spacing(22);
                col.Item().Element(Summary);
                col.Item().Element(FixFirst);
                col.Item().Element(ByArea);
                if (data.Devices is { Total: > 0 } devices) col.Item().Element(c => Devices(c, devices));
                col.Item().Element(FindingsToFix);
                col.Item().Element(Passed);
                col.Item().Element(Method);
            });
            page.Footer().Element(Footer);
        });
    }

    private static void Setup(PageDescriptor page)
    {
        page.Size(PageSizes.A4);
        page.Margin(40);
        page.PageColor(Colors.White);
        page.DefaultTextStyle(t => t.FontFamily(ReportFonts.Families).FontSize(9.5f).FontColor(Ink).LineHeight(1.35f));
    }

    // --- Cover --------------------------------------------------------------------------------

    private void Cover(IContainer container) => container.Column(col =>
    {
        col.Item().Height(6).Background(Accent);
        col.Item().PaddingTop(28).Row(row =>
        {
            row.ConstantItem(44).Height(44).Element(Logo);
            row.RelativeItem().PaddingLeft(12).AlignMiddle().Column(brand =>
            {
                brand.Item().Text(From).FontSize(16).SemiBold();
                if (data.Branding.ContactLine is { Length: > 0 } contact)
                    brand.Item().Text(contact).FontSize(9).FontColor(Muted);
            });
        });

        col.Item().PaddingTop(110).Text("Microsoft 365 security posture").FontSize(30).Bold().FontColor(Accent);
        col.Item().PaddingTop(6).Text(data.Tenant.DisplayName).FontSize(20).SemiBold();
        col.Item().Text($"{data.Tenant.PrimaryDomain} · {data.Tenant.Industry}").FontSize(11).FontColor(Muted);

        col.Item().PaddingTop(48).Row(row =>
        {
            row.ConstantItem(150).Height(150).Element(c => ScoreRing(c, 150, 34));
            row.RelativeItem().PaddingLeft(28).AlignMiddle().Column(s =>
            {
                s.Spacing(4);
                s.Item().Text(ScoreHeadline()).FontSize(15).SemiBold();
                s.Item().Text(text =>
                {
                    text.DefaultTextStyle(t => t.FontSize(10.5f).FontColor(Muted));
                    text.Span($"{data.Score.Failed} checks to fix, ");
                    text.Span($"{data.Score.FailedBySeverity.GetValueOrDefault(Severity.Critical)} critical").FontColor(Fail).SemiBold();
                    text.Span($" and {data.Score.FailedBySeverity.GetValueOrDefault(Severity.High)} high.");
                });
                s.Item().Text($"{PassRate()}% of evaluated checks pass.").FontSize(10.5f).FontColor(Muted);
            });
        });

        col.Item().ExtendVertical().AlignBottom().Column(meta =>
        {
            meta.Spacing(3);
            meta.Item().LineHorizontal(0.75f).LineColor(Hairline);
            meta.Item().PaddingTop(8).Text(text =>
            {
                text.Span("Prepared for ").FontColor(Muted);
                text.Span(data.Tenant.DisplayName).SemiBold();
                text.Span(" by ").FontColor(Muted);
                text.Span(From).SemiBold();
            });
            meta.Item().Text($"Report date {Date(data.GeneratedAt)} · Results as of {Date(LatestResult())}").FontColor(Muted);
            meta.Item().PaddingTop(6).Text("Confidential. This report describes security weaknesses in the organisation named above; " +
                                           "share it only with people who need it to fix them.").FontSize(8).FontColor(Muted);
        });
    });

    // --- Running header and footer --------------------------------------------------------------

    private void Header(IContainer container) => container.Column(col =>
    {
        col.Item().Row(row =>
        {
            row.RelativeItem().Text(data.Tenant.DisplayName).SemiBold();
            row.RelativeItem().AlignRight().Text($"Security posture · {Date(data.GeneratedAt)}").FontColor(Muted);
        });
        col.Item().PaddingTop(6).LineHorizontal(1.5f).LineColor(Accent);
    });

    private void Footer(IContainer container) => container.Row(row =>
    {
        row.RelativeItem().Text($"{From} · Confidential").FontSize(8).FontColor(Muted);
        row.RelativeItem().AlignRight().Text(text =>
        {
            text.DefaultTextStyle(t => t.FontSize(8).FontColor(Muted));
            text.Span("Page ");
            text.CurrentPageNumber();
            text.Span(" of ");
            text.TotalPages();
        });
    });

    // --- Sections -----------------------------------------------------------------------------

    private void Summary(IContainer container) => container.Column(col =>
    {
        col.Item().Element(c => Heading(c, "Summary"));
        col.Item().Row(row =>
        {
            row.ConstantItem(96).Height(96).Element(c => ScoreRing(c, 96, 22));
            row.RelativeItem().PaddingLeft(18).AlignMiddle().Column(text =>
            {
                text.Spacing(4);
                text.Item().Text(ScoreHeadline()).FontSize(12).SemiBold();
                text.Item().Text("The score is the share of evaluated checks that pass, weighted by severity. Any open critical " +
                                 "finding caps the grade at C. Checks that couldn't be evaluated (for example features the " +
                                 "tenant doesn't license) don't count against it.").FontColor(Muted);
            });
        });
        col.Item().PaddingTop(14).Row(row =>
        {
            row.Spacing(10);
            Tile(row.RelativeItem(), data.Score.FailedBySeverity.GetValueOrDefault(Severity.Critical).ToString(Culture), "Critical to fix", Fail);
            Tile(row.RelativeItem(), data.Score.FailedBySeverity.GetValueOrDefault(Severity.High).ToString(Culture), "High to fix", Amber);
            Tile(row.RelativeItem(), (data.Score.FailedBySeverity.GetValueOrDefault(Severity.Medium) + data.Score.FailedBySeverity.GetValueOrDefault(Severity.Low)).ToString(Culture),
                "Medium and low", Ink);
            Tile(row.RelativeItem(), $"{PassRate()}%", "Checks passing", Pass);
            if (data.Devices is { Total: > 0 } d)
                Tile(row.RelativeItem(), $"{Percent(d.Compliant, d.Total)}%", "Devices compliant", Accent);
        });
        col.Item().PaddingTop(8).Text($"Based on {Evaluated()} evaluated checks from {Sources()}. " +
                                      $"{data.Score.NotEvaluated} more couldn't be evaluated.").FontSize(8.5f).FontColor(Muted);
    });

    private void FixFirst(IContainer container)
    {
        var top = RiskScoreCalculator.TopRisks(data.Findings, 10);
        container.Column(col =>
        {
            col.Item().Element(c => Heading(c, "Fix these first"));
            if (top.Count == 0)
            {
                col.Item().Text("Nothing open: every evaluated check passes.").FontColor(Pass);
                return;
            }
            col.Item().Table(table =>
            {
                table.ColumnsDefinition(c =>
                {
                    c.ConstantColumn(18);
                    c.RelativeColumn(5);
                    c.RelativeColumn(1.6f);
                    c.ConstantColumn(62);
                });
                table.Header(h =>
                {
                    HeaderCell(h.Cell(), "#");
                    HeaderCell(h.Cell(), "Finding");
                    HeaderCell(h.Cell(), "Area");
                    HeaderCell(h.Cell(), "Severity");
                });
                var n = 0;
                foreach (var f in top)
                {
                    var number = ++n;
                    WholeRow(table, 4, [18, 0, 0, 62], [0, 5, 1.6f, 0],
                        c => c.Text(number.ToString(Culture)).FontColor(Muted),
                        c => c.Column(t =>
                        {
                            t.Item().SectionLink(SectionOf(f)).Text(f.Title).SemiBold();
                            t.Item().Text(SourceLine(f)).FontSize(8).FontColor(Muted);
                        }),
                        c => c.Text(f.Category),
                        c => c.Element(b => SeverityBadge(b, f)));
                }
            });
        });
    }

    private void ByArea(IContainer container)
    {
        var areas = data.Findings.GroupBy(f => f.Category)
            .Select(g => (Area: g.Key, Passed: g.Count(f => f.Status == FindingStatus.Passed), Failed: g.Count(f => f.Status == FindingStatus.Failed),
                Investigate: g.Count(f => f.Status == FindingStatus.Investigate), NotEvaluated: g.Count(f => f.Status == FindingStatus.NotEvaluated)))
            .OrderByDescending(a => a.Failed).ThenBy(a => a.Area, StringComparer.OrdinalIgnoreCase)
            .ToList();

        container.Column(col =>
        {
            col.Item().Element(c => Heading(c, "Results by area"));
            col.Item().Table(table =>
            {
                table.ColumnsDefinition(c =>
                {
                    c.RelativeColumn(2.2f);
                    c.RelativeColumn(3);
                    c.ConstantColumn(44);
                    c.ConstantColumn(44);
                    c.ConstantColumn(56);
                    c.ConstantColumn(62);
                });
                table.Header(h =>
                {
                    HeaderCell(h.Cell(), "Area");
                    HeaderCell(h.Cell(), "");
                    HeaderCell(h.Cell(), "Pass", right: true);
                    HeaderCell(h.Cell(), "Fail", right: true);
                    HeaderCell(h.Cell(), "Review", right: true);
                    HeaderCell(h.Cell(), "Not evaluated", right: true);
                });
                foreach (var a in areas)
                {
                    BodyCell(table.Cell()).Text(a.Area).SemiBold();
                    BodyCell(table.Cell()).AlignMiddle().Element(c => Bar(c, a.Passed, a.Investigate, a.Failed));
                    BodyCell(table.Cell()).AlignRight().Text(a.Passed.ToString(Culture)).FontColor(Pass);
                    BodyCell(table.Cell()).AlignRight().Text(a.Failed.ToString(Culture)).FontColor(a.Failed > 0 ? Fail : Muted);
                    BodyCell(table.Cell()).AlignRight().Text(a.Investigate.ToString(Culture)).FontColor(Muted);
                    BodyCell(table.Cell()).AlignRight().Text(a.NotEvaluated.ToString(Culture)).FontColor(Muted);
                }
            });
        });
    }

    private void Devices(IContainer container, DeviceSummary d) => container.Column(col =>
    {
        col.Item().Element(c => Heading(c, "Device compliance"));
        col.Item().Row(row =>
        {
            row.Spacing(10);
            Tile(row.RelativeItem(), d.Total.ToString(Culture), "Managed devices", Ink);
            Tile(row.RelativeItem(), d.Compliant.ToString(Culture), "Compliant", Pass);
            Tile(row.RelativeItem(), d.Noncompliant.ToString(Culture), "Not compliant", d.Noncompliant > 0 ? Fail : Muted);
            Tile(row.RelativeItem(), (d.InGracePeriod + d.Unknown).ToString(Culture), "Grace period or unknown", Amber);
        });
        col.Item().PaddingTop(6).Text($"Intune inventory{(d.LastSyncAt is { } at ? $" as of {DateTime(at)}" : "")}.").FontSize(8.5f).FontColor(Muted);
        if (d.NoncompliantDevices.Count == 0) return;

        col.Item().PaddingTop(10).Text(d.Noncompliant > d.NoncompliantDevices.Count
            ? $"Not compliant (the {d.NoncompliantDevices.Count} longest without a check-in of {d.Noncompliant})"
            : "Not compliant").SemiBold();
        col.Item().PaddingTop(4).Table(table =>
        {
            table.ColumnsDefinition(c =>
            {
                c.RelativeColumn(3);
                c.RelativeColumn(1.4f);
                c.RelativeColumn(2);
            });
            table.Header(h =>
            {
                HeaderCell(h.Cell(), "Device");
                HeaderCell(h.Cell(), "Platform");
                HeaderCell(h.Cell(), "Last check-in");
            });
            foreach (var (name, platform, lastSync) in d.NoncompliantDevices)
            {
                BodyCell(table.Cell()).Text(name);
                BodyCell(table.Cell()).Text(platform);
                BodyCell(table.Cell()).Text(lastSync is { } at ? DateTime(at) : "Never").FontColor(Muted);
            }
        });
    });

    private void FindingsToFix(IContainer container)
    {
        var open = data.Findings.Where(f => f.Status is FindingStatus.Failed or FindingStatus.Investigate)
            .OrderByDescending(f => f.Status == FindingStatus.Failed)
            .ThenByDescending(f => f.Severity)
            .ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();

        container.Column(col =>
        {
            col.Item().PageBreak();
            col.Item().Element(c => Heading(c, $"Findings to fix ({open.Count})"));
            if (open.Count == 0)
            {
                col.Item().Text("No open findings.").FontColor(Pass);
                return;
            }
            col.Item().Text("Failed checks first, by severity; then checks that need someone to review them.").FontColor(Muted);
            foreach (var f in open)
                col.Item().PaddingTop(10).Section(SectionOf(f)).Element(c => FindingBlock(c, f));
        });
    }

    private void FindingBlock(IContainer container, Finding f) => container
        .BorderLeft(3).BorderColor(SeverityColor(f))
        .Background(Tint)
        .PaddingVertical(8).PaddingHorizontal(10)
        .Column(col =>
        {
            col.Spacing(4);
            col.Item().Row(row =>
            {
                row.RelativeItem().PaddingRight(8).Text(f.Title).FontSize(10.5f).SemiBold();
                row.AutoItem().Element(c => SeverityBadge(c, f));
            });
            col.Item().Text(text =>
            {
                text.DefaultTextStyle(t => t.FontSize(8.5f).FontColor(Muted));
                text.Span($"{f.Category} · {SourceLine(f)}");
                if (f.Frameworks.Count > 0) text.Span($" · {string.Join(", ", f.Frameworks)}");
                if (f.Tags.Contains("BOD 25-01")) text.Span(" · BOD 25-01");
            });
            if (Clip(f.Evidence) is { } evidence)
            {
                col.Item().PaddingTop(2).Text("What we found").FontSize(8).SemiBold().FontColor(Muted);
                col.Item().Text(evidence);
            }
            if (!string.IsNullOrWhiteSpace(f.Remediation))
            {
                col.Item().PaddingTop(2).Text("How to fix it").FontSize(8).SemiBold().FontColor(Muted);
                col.Item().Text(f.Remediation);
            }
            if (SafeLink(f.HelpUrl) is { } link)
                col.Item().Hyperlink(link).Text("More about this check").FontSize(8.5f).FontColor(Accent).Underline();
        });

    private void Passed(IContainer container)
    {
        var passed = data.Findings.Where(f => f.Status == FindingStatus.Passed)
            .OrderBy(f => f.Category, StringComparer.OrdinalIgnoreCase).ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (passed.Count == 0) return;

        container.Column(col =>
        {
            col.Item().Element(c => Heading(c, $"Checks that pass ({passed.Count})"));
            col.Item().Table(table =>
            {
                table.ColumnsDefinition(c =>
                {
                    c.RelativeColumn(5);
                    c.RelativeColumn(1.6f);
                    c.RelativeColumn(1.8f);
                });
                table.Header(h =>
                {
                    HeaderCell(h.Cell(), "Check");
                    HeaderCell(h.Cell(), "Area");
                    HeaderCell(h.Cell(), "Source");
                });
                foreach (var f in passed)
                {
                    WholeRow(table, 3, [0, 0, 0], [5, 1.6f, 1.8f],
                        c => c.Text(f.Title),
                        c => c.Text(f.Category).FontColor(Muted),
                        c => c.Text(SourceLine(f)).FontSize(8).FontColor(Muted),
                        compact: true);
                }
            });
        });
    }

    private void Method(IContainer container) => container.ShowEntire().Column(col =>
    {
        col.Item().Element(c => Heading(c, "About this report"));
        col.Item().Text($"SecurePulse assessed this tenant with read-only access granted by its administrator, using {Sources()}. " +
                        "It reads configuration only and changes nothing. Maester checks Microsoft 365 and Entra ID settings; " +
                        "ScubaGear checks the Entra ID configuration against CISA's Secure Cloud Business Applications (SCuBA) " +
                        "baseline. Checks that need wider administrative access, such as some Exchange Online, Teams and " +
                        "SharePoint settings, aren't evaluated.");
        col.Item().PaddingTop(8).Text("How the score is calculated").SemiBold();
        col.Item().Text(text =>
        {
            text.Span("Each evaluated check carries a weight by severity: ");
            text.Span(string.Join(", ", Enum.GetValues<Severity>().OrderByDescending(s => s)
                .Select(s => $"{s} {RiskScoreCalculator.WeightOf(s)}")));
            text.Span(". The score is the share of that weight that passes; checks needing review earn half. Grades: A from 90, " +
                      "B from 80, C from 70, D from 60, otherwise F, and any open critical finding caps the grade at C.");
        });
        col.Item().PaddingTop(8).Text("Results reflect the tenant's configuration when it was last scanned and may have changed since. " +
                                      "They support, but don't replace, a full security audit.").FontColor(Muted);
    });

    // --- Building blocks ----------------------------------------------------------------------

    private void Heading(IContainer container, string text) => container.PaddingBottom(8).Column(col =>
    {
        col.Item().Text(text).FontSize(15).SemiBold().FontColor(Accent);
        col.Item().PaddingTop(3).Width(36).LineHorizontal(2).LineColor(Accent);
    });

    private static void HeaderCell(IContainer cell, string text, bool right = false)
    {
        var c = cell.BorderBottom(1).BorderColor(Hairline).PaddingVertical(5).PaddingRight(6);
        (right ? c.AlignRight() : c).Text(text).FontSize(8).SemiBold().FontColor(Muted);
    }

    private static IContainer BodyCell(IContainer cell, bool compact = false) =>
        cell.BorderBottom(0.5f).BorderColor(Hairline).PaddingVertical(compact ? 3 : 6).PaddingRight(6);

    /// <summary>
    /// One table row drawn as a single cell spanning every column, so a row that doesn't fit moves
    /// to the next page whole instead of splitting its cells across the break. The widths repeat the
    /// table's column definition: a constant width, or 0 to use the relative weight.
    /// </summary>
    private static void WholeRow(TableDescriptor table, uint columns, float[] constant, float[] relative,
        Action<IContainer> first, Action<IContainer> second, Action<IContainer> third, Action<IContainer>? fourth = null, bool compact = false)
    {
        Action<IContainer>[] cells = fourth is null ? [first, second, third] : [first, second, third, fourth];
        BodyCell(table.Cell().ColumnSpan(columns), compact).ShowEntire().Row(row =>
        {
            for (var i = 0; i < cells.Length; i++)
            {
                var item = constant[i] > 0 ? row.ConstantItem(constant[i]) : row.RelativeItem(relative[i]);
                cells[i](i < cells.Length - 1 ? item.PaddingRight(6) : item);
            }
        });
    }

    private static void Tile(IContainer container, string value, string label, string color) => container
        .Background(Tint).PaddingVertical(10).PaddingHorizontal(12)
        .Column(col =>
        {
            col.Item().Text(value).FontSize(18).Bold().FontColor(color);
            col.Item().Text(label).FontSize(8).FontColor(Muted);
        });

    private static void Bar(IContainer container, int passed, int review, int failed) => container.Height(7).Row(row =>
    {
        if (passed + review + failed == 0)
        {
            row.RelativeItem().Background(Hairline);
            return;
        }
        if (passed > 0) row.RelativeItem(passed).Background(Pass);
        if (review > 0) row.RelativeItem(review).Background(Amber);
        if (failed > 0) row.RelativeItem(failed).Background(Fail);
    });

    private static void SeverityBadge(IContainer container, Finding f) => container
        .AlignLeft().AlignTop().Border(0.75f).BorderColor(SeverityColor(f)).PaddingVertical(1).PaddingHorizontal(5)
        .Text(f.Status == FindingStatus.Investigate ? $"{f.Severity} · review" : f.Severity.ToString())
        .FontSize(7.5f).SemiBold().FontColor(SeverityColor(f));

    private void ScoreRing(IContainer container, float size, float fontSize)
    {
        var score = Math.Clamp(data.Score.Score, 0, 100);
        const float stroke = 10, radius = 45; // in a 100×100 viewBox
        var circumference = 2 * MathF.PI * radius;
        var arc = circumference * score / 100f;
        var svg = string.Create(CultureInfo.InvariantCulture, $"""
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="{size}" height="{size}">
              <circle cx="50" cy="50" r="{radius}" fill="none" stroke="{Hairline}" stroke-width="{stroke}"/>
              <circle cx="50" cy="50" r="{radius}" fill="none" stroke="{ScoreColor(score)}" stroke-width="{stroke}" stroke-linecap="round"
                      stroke-dasharray="{arc:0.##} {circumference:0.##}" transform="rotate(-90 50 50)"/>
            </svg>
            """);
        container.Layers(layers =>
        {
            layers.Layer().Svg(svg);
            layers.PrimaryLayer().AlignCenter().AlignMiddle().Column(col =>
            {
                col.Item().AlignCenter().Text(score.ToString(Culture)).FontSize(fontSize).Bold().FontColor(Ink);
                col.Item().AlignCenter().Text($"Grade {data.Score.Grade}").FontSize(fontSize * 0.32f).SemiBold().FontColor(Muted);
            });
        });
    }

    private void Logo(IContainer container)
    {
        if (data.Branding.Logo is { Length: > 0 } logo)
        {
            if (LooksLikeSvg(logo))
                container.Svg(System.Text.Encoding.UTF8.GetString(logo));
            else
                container.Image(logo).FitArea();
            return;
        }
        // Default mark: a shield in the accent colour.
        container.Svg($"""
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
              <path fill="{Accent}" d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5z"/>
              <path fill="#FFFFFF" d="m10 17-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9z"/>
            </svg>
            """);
    }

    // --- Text helpers -------------------------------------------------------------------------

    private string ScoreHeadline() => data.Score.Score switch
    {
        >= 80 => $"Score {data.Score.Score} of 100: in good shape, with a few things to tighten.",
        >= 60 => $"Score {data.Score.Score} of 100: solid foundations, with important gaps to close.",
        _ => $"Score {data.Score.Score} of 100: significant gaps that attackers commonly exploit."
    };

    private int Evaluated() => data.Score.Passed + data.Score.Failed + data.Score.Investigate;

    private int PassRate() => Percent(data.Score.Passed, Evaluated());

    private static int Percent(int part, int whole) => whole == 0 ? 0 : (int)Math.Round(100.0 * part / whole, MidpointRounding.AwayFromZero);

    private string Sources()
    {
        var sources = data.Findings.Select(f => f.Source).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        return sources.Count switch
        {
            0 => "no scan engines",
            1 => sources[0],
            _ => string.Join(", ", sources[..^1]) + " and " + sources[^1]
        };
    }

    private DateTimeOffset LatestResult() => data.Findings.Count > 0 ? data.Findings.Max(f => f.DetectedAt) : data.GeneratedAt;

    private static string SourceLine(Finding f) => f.SourceCheckId is { Length: > 0 } id ? $"{f.Source} {id}" : f.Source;

    private static string SectionOf(Finding f) => "finding-" + f.Id;

    private string Date(DateTimeOffset at) => Local(at).ToString("d MMMM yyyy", Culture);

    private string DateTime(DateTimeOffset at)
    {
        var local = Local(at);
        var offset = local.Offset == TimeSpan.Zero ? "UTC" : $"UTC{local.Offset.Hours:+0;-0}{(local.Offset.Minutes != 0 ? $":{Math.Abs(local.Offset.Minutes):00}" : "")}";
        return $"{local.ToString("d MMM yyyy, HH:mm", Culture)} {offset}";
    }

    private DateTimeOffset Local(DateTimeOffset at) => data.TimeZone is { } tz ? TimeZoneInfo.ConvertTime(at, tz) : at.ToUniversalTime();

    private static string? Clip(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null : text.Length <= MaxEvidenceLength ? text.Trim() : text[..MaxEvidenceLength].TrimEnd() + "…";

    /// <summary>Help links come from engine output: only absolute https links become hyperlinks.</summary>
    private static string? SafeLink(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps ? uri.AbsoluteUri : null;

    private static string SeverityColor(Finding f) => f.Severity switch
    {
        Severity.Critical => Fail,
        Severity.High => "#D84315",
        Severity.Medium => Amber,
        Severity.Low => "#2F6FD0",
        _ => Muted
    };

    private static string ScoreColor(int score) => score switch
    {
        >= 80 => Pass,
        >= 60 => Amber,
        _ => Fail
    };

    private static bool IsHexColor(string? value) =>
        value is { Length: 7 } && value[0] == '#' && value.Skip(1).All(Uri.IsHexDigit);

    private static bool LooksLikeSvg(byte[] bytes)
    {
        var head = System.Text.Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, 512)).TrimStart('﻿', ' ', '\t', '\r', '\n');
        return head.StartsWith("<svg", StringComparison.OrdinalIgnoreCase) || head.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase);
    }
}

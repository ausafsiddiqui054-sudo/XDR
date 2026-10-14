using SecurePulse.Core.Models;
using SecurePulse.Engines.ScubaGear;
using SecurePulse.Reporting;

namespace SecurePulse.Tests.Scans;

/// <summary>Against ScubaGear 1.8.0's own sample report (samples/scubagear-results.sample.json, "Raw" removed).</summary>
public class ScubaGearResultParserTests
{
    private static readonly Guid TenantId = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly string Sample = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "samples", "scubagear-results.sample.json"));

    private static IReadOnlyList<Finding> ParseSample() => ScubaGearResultParser.Parse(Sample, TenantId, new DateTimeOffset(2026, 10, 14, 8, 0, 0, TimeSpan.Zero));

    [Fact]
    public void ParsesEveryControlInTheSample()
    {
        var findings = ParseSample();

        Assert.Equal(92, findings.Count);
        Assert.Equal(30, findings.Count(f => f.Tags.Contains("AAD")));
        // Sample totals: 57 Pass, 14 Fail + 12 Warning, 9 N/A.
        Assert.Equal(57, findings.Count(f => f.Status == FindingStatus.Passed));
        Assert.Equal(26, findings.Count(f => f.Status == FindingStatus.Failed));
        Assert.Equal(9, findings.Count(f => f.Status == FindingStatus.NotEvaluated));
        Assert.All(findings, f =>
        {
            Assert.Equal("ScubaGear", f.Source);
            Assert.Equal(TenantId, f.TenantId);
            Assert.Equal($"scubagear:{TenantId:N}:{f.SourceCheckId}", f.Id);
            Assert.Equal(["CISA SCuBA"], f.Frameworks);
            Assert.DoesNotContain("<", f.Title);
            Assert.DoesNotContain("<", f.Evidence ?? "");
        });
        Assert.Equal(findings.Count, findings.Select(f => f.Id).Distinct().Count());
    }

    [Fact]
    public void MapsAShallControl()
    {
        var f = ParseSample().Single(x => x.SourceCheckId == "MS.AAD.1.1v1");

        Assert.Equal("Legacy authentication SHALL be blocked.", f.Title); // badges stripped
        Assert.Equal(FindingStatus.Passed, f.Status);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal("Identity", f.Category);
        Assert.Equal("CISA Azure Active Directory baseline · Legacy Authentication", f.Description);
        Assert.Contains("BOD 25-01", f.Tags);
        Assert.StartsWith("1 conditional access policy(s) found", f.Evidence);
        Assert.Equal("https://github.com/cisagov/ScubaGear/blob/v1.8.0/PowerShell/ScubaGear/baselines/aad.md#1-legacy-authentication", f.HelpUrl);
    }

    [Fact]
    public void AWarningIsAFailedShouldControl()
    {
        var f = ParseSample().Single(x => x.SourceCheckId == "MS.AAD.3.7v1");

        Assert.Equal("Managed devices SHOULD be required for authentication.", f.Title);
        Assert.Equal(FindingStatus.Failed, f.Status);
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.DoesNotContain("BOD 25-01", f.Tags);
    }

    [Fact]
    public void ManualChecksAreNotEvaluated()
    {
        var f = ParseSample().Single(x => x.SourceCheckId == "MS.AAD.2.2v1");

        Assert.Equal(FindingStatus.NotEvaluated, f.Status);
        Assert.Equal(Severity.Medium, f.Severity); // Should/Not-Implemented
        Assert.Contains("Manual check", f.Tags);
    }

    [Fact]
    public void OtherProductsGetTheirCategories()
    {
        var byProduct = ParseSample().GroupBy(f => f.Tags[0]).ToDictionary(g => g.Key, g => g.Select(f => f.Category).Distinct().Single());

        Assert.Equal("Email", byProduct["EXO"]);
        Assert.Equal("Email", byProduct["Defender"]);
        Assert.Equal("Collaboration", byProduct["SharePoint"]);
        Assert.Equal("Collaboration", byProduct["Teams"]);
        Assert.Equal("Apps and data", byProduct["PowerPlatform"]);
    }

    [Fact]
    public void TheSampleScores()
    {
        var score = RiskScoreCalculator.Calculate(ParseSample());

        Assert.InRange(score.Score, 1, 99);
        Assert.Equal(26, score.Failed);
    }

    [Theory]
    [InlineData("Error", "Shall", FindingStatus.NotEvaluated, Severity.High)]
    [InlineData("Error - Test results missing", "-", FindingStatus.NotEvaluated, Severity.Info)]
    [InlineData("Omitted", "Shall", FindingStatus.NotEvaluated, Severity.High)]
    [InlineData("Incorrect result", "Should", FindingStatus.NotEvaluated, Severity.Medium)]
    [InlineData("N/A", "Shall/3rd Party", FindingStatus.NotEvaluated, Severity.High)]
    [InlineData("Fail", "May", FindingStatus.Failed, Severity.Low)]
    [InlineData("Something new", null, FindingStatus.NotEvaluated, Severity.Info)]
    public void MapsEveryResultAndCriticality(string result, string? criticality, FindingStatus status, Severity severity)
    {
        var json = $$$"""
            {"Results":{"AAD":[{"GroupName":"G","Controls":[{"Control ID":"MS.AAD.9.9v1","Requirement":"R","Result":"{{{result}}}","Criticality":{{{(criticality is null ? "null" : $"\"{criticality}\"")}}},"Details":"d"}]}]}}
            """;

        var f = Assert.Single(ScubaGearResultParser.Parse(json, TenantId));

        Assert.Equal(status, f.Status);
        Assert.Equal(severity, f.Severity);
    }

    [Fact]
    public void HandlesHtmlDuplicatesAndOddShapes()
    {
        const string json = """
            {
              "Results": {
                "AAD": [
                  { "GroupName": "One", "Controls": [
                    { "Control ID": "MS.AAD.1.1v1", "Requirement": "Block &amp; <b>log</b>", "Result": "Fail", "Criticality": "Shall",
                      "Details": "Found:<br/>Policy &quot;A&quot; <a href='#x'>View</a>" },
                    { "Control ID": "MS.AAD.1.1v1", "Requirement": "Duplicate", "Result": "Pass", "Criticality": "Shall" },
                    { "Requirement": "No id", "Result": "Pass" },
                    { "Control ID": "MS.AAD.1.2v1", "Requirement": "", "Result": "Pass", "Criticality": "Should" }
                  ]},
                  { "GroupName": "No controls" },
                  "not an object"
                ],
                "Teams": "not an array"
              }
            }
            """;

        var findings = ScubaGearResultParser.Parse(json, TenantId);

        Assert.Equal(["MS.AAD.1.1v1", "MS.AAD.1.2v1"], findings.Select(f => f.SourceCheckId));
        Assert.Equal("Block & log", findings[0].Title);
        Assert.Equal("Found: Policy \"A\" View", findings[0].Evidence);
        Assert.Equal("CISA AAD baseline · One", findings[0].Description); // no MetaData: abbreviation
        Assert.Equal("MS.AAD.1.2v1", findings[1].Title); // empty requirement falls back to the ID
        Assert.Null(findings[1].Evidence);
    }

    [Fact]
    public void NoResultsMeansNoFindings()
    {
        Assert.Empty(ScubaGearResultParser.Parse("""{"MetaData":{}}""", TenantId));
        Assert.Empty(ScubaGearResultParser.Parse("[]", TenantId));
    }

    [Fact]
    public void LongDetailsAreTrimmed()
    {
        var json = $$$"""{"Results":{"AAD":[{"Controls":[{"Control ID":"X","Requirement":"R","Result":"Fail","Criticality":"Shall","Details":"{{{new string('a', 5000)}}}"}]}]}}""";

        Assert.Equal(2001, Assert.Single(ScubaGearResultParser.Parse(json, TenantId)).Evidence!.Length);
    }
}

public class FindingHelpLinkTests
{
    [Theory]
    [InlineData("https://github.com/cisagov/ScubaGear/blob/v1.8.0/PowerShell/ScubaGear/baselines/aad.md#1-legacy-authentication", true)]
    [InlineData("https://maester.dev/docs/tests/MT.1001", true)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("http://example.com/insecure", false)]
    [InlineData("/relative/path", false)]
    [InlineData("data:text/html,<script>alert(1)</script>", false)]
    [InlineData(null, false)]
    public void OnlyHttpsLinksAreShown(string? url, bool shown) =>
        Assert.Equal(shown, SecurePulse.Web.Components.Pages.Findings.SafeLink(url) is not null);
}

using System.Text.Json;
using SecurePulse.Core.Models;
using SecurePulse.Engines.Maester;

namespace SecurePulse.Tests.Engines;

public class MaesterResultParserTests
{
    private static readonly Guid TenantId = Guid.Parse("6f1c2b8e-3d4a-4f5b-9c7d-0e1f2a3b4c5d");
    private static readonly DateTimeOffset DetectedAt = new(2026, 1, 15, 9, 30, 0, TimeSpan.Zero);

    private static IReadOnlyList<Finding> ParseSample() =>
        MaesterResultParser.Parse(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "samples", "maester-results.sample.json")),
            TenantId, DetectedAt);

    private static Finding SampleCheck(string checkId) =>
        ParseSample().Single(f => f.SourceCheckId == checkId);

    [Fact]
    public void Sample_ProducesOneFindingPerTest()
    {
        var findings = ParseSample();

        Assert.Equal(6, findings.Count);
        Assert.All(findings, f =>
        {
            Assert.Equal(TenantId, f.TenantId);
            Assert.Equal("Maester", f.Source);
            Assert.Equal(DetectedAt, f.DetectedAt);
        });
    }

    [Fact]
    public void Sample_StatusCountsMatchMaesterSummary()
    {
        var findings = ParseSample();

        Assert.Equal(2, findings.Count(f => f.Status == FindingStatus.Passed));
        Assert.Equal(2, findings.Count(f => f.Status == FindingStatus.Failed));
        Assert.Equal(1, findings.Count(f => f.Status == FindingStatus.Investigate));
        Assert.Equal(1, findings.Count(f => f.Status == FindingStatus.NotEvaluated));
    }

    [Fact]
    public void Sample_MapsAllFieldsOfAFullyPopulatedTest()
    {
        var f = SampleCheck("SAMPLE.001");

        Assert.Equal($"maester:{TenantId:N}:SAMPLE.001", f.Id);
        Assert.Equal("Privileged roles require phishing-resistant MFA", f.Title);
        Assert.Equal("Admins must use phishing-resistant authentication.", f.Description);
        Assert.Equal("No Conditional Access policy enforces an authentication strength for directory roles.", f.Evidence);
        Assert.Equal("https://maester.dev/docs/tests", f.HelpUrl);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal(FindingStatus.Failed, f.Status);
        Assert.Equal("Identity", f.Category);
        Assert.Equal(["Entra", "Conditional Access", "Privileged"], f.Tags);
    }

    [Theory]
    [InlineData("SAMPLE.001", "Identity")]      // Conditional Access block
    [InlineData("SAMPLE.003", "Devices")]       // Intune
    [InlineData("SAMPLE.004", "Email")]         // Exchange Online / EXO
    [InlineData("SAMPLE.005", "Collaboration")] // SharePoint
    [InlineData("SAMPLE.006", "Defender")]      // unrecognised block passes through
    public void Sample_MapsCategoryFromBlockAndTags(string checkId, string expected) =>
        Assert.Equal(expected, SampleCheck(checkId).Category);

    [Fact]
    public void Sample_EmptySeverityDefaultsToMedium() =>
        Assert.Equal(Severity.Medium, SampleCheck("SAMPLE.005").Severity);

    [Fact]
    public void Sample_SingleStringTagBecomesOneTag() =>
        Assert.Equal(["SharePoint"], SampleCheck("SAMPLE.005").Tags);

    [Fact]
    public void Sample_SkippedTestIsNotEvaluated() =>
        Assert.Equal(FindingStatus.NotEvaluated, SampleCheck("SAMPLE.006").Status);

    [Fact]
    public void Sample_TestWithoutResultDetailHasNoDescriptionOrEvidence()
    {
        var f = SampleCheck("SAMPLE.002");

        Assert.Null(f.Description);
        Assert.Null(f.Evidence);
    }

    [Theory]
    [InlineData("Critical", Severity.Critical)]
    [InlineData("HIGH", Severity.High)]
    [InlineData(" medium ", Severity.Medium)]
    [InlineData("Low", Severity.Low)]
    [InlineData("Info", Severity.Info)]
    [InlineData("Informational", Severity.Info)]
    [InlineData("", Severity.Medium)]
    [InlineData("Unknown", Severity.Medium)]
    [InlineData(null, Severity.Medium)]
    public void MapSeverity(string? value, Severity expected) =>
        Assert.Equal(expected, MaesterResultParser.MapSeverity(value));

    [Theory]
    [InlineData("Passed", FindingStatus.Passed)]
    [InlineData("FAILED", FindingStatus.Failed)]
    [InlineData(" investigate ", FindingStatus.Investigate)]
    [InlineData("Skipped", FindingStatus.NotEvaluated)]
    [InlineData("NotRun", FindingStatus.NotEvaluated)]
    [InlineData("Error", FindingStatus.NotEvaluated)]
    [InlineData(null, FindingStatus.NotEvaluated)]
    public void MapStatus(string? value, FindingStatus expected) =>
        Assert.Equal(expected, MaesterResultParser.MapStatus(value));

    [Theory]
    [InlineData("{}")]
    [InlineData("""{ "Tests": null }""")]
    [InlineData("""{ "Tests": {} }""")]
    [InlineData("""{ "Tests": [] }""")]
    [InlineData("[]")]
    public void MissingOrEmptyTests_ReturnsNoFindings(string json) =>
        Assert.Empty(MaesterResultParser.Parse(json, TenantId));

    [Fact]
    public void MalformedJson_Throws() =>
        Assert.ThrowsAny<JsonException>(() => MaesterResultParser.Parse("{ not json", TenantId));

    [Fact]
    public void PropertyNamesAreCaseInsensitive()
    {
        const string json = """{ "tests": [ { "id": "X.1", "title": "Lower-case keys", "severity": "High", "result": "Passed" } ] }""";

        var f = Assert.Single(MaesterResultParser.Parse(json, TenantId));

        Assert.Equal("X.1", f.SourceCheckId);
        Assert.Equal("Lower-case keys", f.Title);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(FindingStatus.Passed, f.Status);
    }

    [Fact]
    public void MissingIdAndTitle_FallBackToNameAndIndex()
    {
        const string json = """{ "Tests": [ { "Result": "Passed" }, { "Name": "Named only", "Result": "Failed" } ] }""";

        var findings = MaesterResultParser.Parse(json, TenantId);

        Assert.Equal($"maester:{TenantId:N}:1", findings[0].Id);
        Assert.Null(findings[0].SourceCheckId);
        Assert.Equal("Maester check 1", findings[0].Title);
        Assert.Equal($"maester:{TenantId:N}:2", findings[1].Id);
        Assert.Equal("Named only", findings[1].Title);
    }

    [Fact]
    public void MissingBlockAndTags_CategoryIsGeneral()
    {
        const string json = """{ "Tests": [ { "Id": "X.1", "Result": "Passed" } ] }""";

        var f = Assert.Single(MaesterResultParser.Parse(json, TenantId));

        Assert.Equal("General", f.Category);
        Assert.Empty(f.Tags);
    }

    [Fact]
    public void Tags_SkipNonStringsBlanksAndCaseInsensitiveDuplicates()
    {
        const string json = """{ "Tests": [ { "Id": "X.1", "Tag": ["Entra", "entra", "", 42, null, "CA"] } ] }""";

        var f = Assert.Single(MaesterResultParser.Parse(json, TenantId));

        Assert.Equal(["Entra", "CA"], f.Tags);
    }

    [Fact]
    public void LongEvidence_IsTruncatedTo2000CharsPlusEllipsis()
    {
        var longText = new string('x', 5000);
        var json = $$"""{ "Tests": [ { "Id": "X.1", "Result": "Failed", "ResultDetail": { "TestResult": "{{longText}}" } } ] }""";

        var f = Assert.Single(MaesterResultParser.Parse(json, TenantId));

        Assert.Equal(new string('x', 2000) + "…", f.Evidence);
    }

    [Fact]
    public void EvidenceAtTheLimit_IsNotTruncated()
    {
        var text = new string('x', 2000);
        var json = $$"""{ "Tests": [ { "Id": "X.1", "ResultDetail": { "TestResult": "{{text}}" } } ] }""";

        Assert.Equal(text, Assert.Single(MaesterResultParser.Parse(json, TenantId)).Evidence);
    }
}

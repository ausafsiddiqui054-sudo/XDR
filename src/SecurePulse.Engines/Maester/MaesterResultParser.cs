using System.Text.Json;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.Maester;

/// <summary>
/// Converts Maester's JSON output (Invoke-Maester -OutputJsonFile) into normalized findings.
/// Each entry in the "Tests" array carries Id, Title, Name, HelpUrl, Severity, Tag,
/// Result, Block, Duration and ResultDetail. Parsing is tolerant: unknown or missing
/// fields fall back to safe defaults so a Maester version bump doesn't break scans.
/// </summary>
public static class MaesterResultParser
{
    private const int MaxEvidenceLength = 2000;

    public static IReadOnlyList<Finding> Parse(string json, Guid tenantId, DateTimeOffset? detectedAt = null)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!TryGetPropertyIgnoreCase(root, "Tests", out var tests) || tests.ValueKind != JsonValueKind.Array)
            return [];

        var when = detectedAt ?? DateTimeOffset.UtcNow;
        var findings = new List<Finding>();
        var index = 0;

        foreach (var test in tests.EnumerateArray())
        {
            index++;
            var checkId = GetString(test, "Id");
            var title = GetString(test, "Title") ?? GetString(test, "Name") ?? $"Maester check {index}";

            findings.Add(new Finding
            {
                Id = $"maester:{tenantId:N}:{checkId ?? index.ToString()}",
                TenantId = tenantId,
                Source = "Maester",
                SourceCheckId = checkId,
                Title = title,
                Description = GetNested(test, "ResultDetail", "TestDescription"),
                Category = MapCategory(GetString(test, "Block"), GetTags(test)),
                Severity = MapSeverity(GetString(test, "Severity")),
                Status = MapStatus(GetString(test, "Result")),
                Evidence = Truncate(GetNested(test, "ResultDetail", "TestResult")),
                HelpUrl = GetString(test, "HelpUrl"),
                Tags = GetTags(test),
                DetectedAt = when
            });
        }

        return findings;
    }

    public static Severity MapSeverity(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        "info" or "informational" => Severity.Info,
        // Maester leaves severity empty on many tests; treat unknown as Medium
        // so failures still count without dominating the score.
        _ => Severity.Medium
    };

    public static FindingStatus MapStatus(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "passed" => FindingStatus.Passed,
        "failed" => FindingStatus.Failed,
        "investigate" => FindingStatus.Investigate,
        _ => FindingStatus.NotEvaluated // Skipped, NotRun, Error, unknown
    };

    private static string MapCategory(string? block, IReadOnlyList<string> tags)
    {
        var text = (block + " " + string.Join(' ', tags)).ToLowerInvariant();
        if (text.Contains("conditional access") || text.Contains("entra") || text.Contains("identity") || text.Contains("authentication"))
            return "Identity";
        if (text.Contains("intune") || text.Contains("device")) return "Devices";
        if (text.Contains("exchange") || text.Contains("exo") || text.Contains("mail") || text.Contains("defender for office"))
            return "Email";
        if (text.Contains("sharepoint") || text.Contains("onedrive") || text.Contains("teams")) return "Collaboration";
        return string.IsNullOrWhiteSpace(block) ? "General" : block.Trim();
    }

    private static IReadOnlyList<string> GetTags(JsonElement test)
    {
        if (!TryGetPropertyIgnoreCase(test, "Tag", out var tag)) return [];
        return tag.ValueKind switch
        {
            JsonValueKind.Array => tag.EnumerateArray()
                .Where(t => t.ValueKind == JsonValueKind.String)
                .Select(t => t.GetString()!)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            JsonValueKind.String => [tag.GetString()!],
            _ => []
        };
    }

    private static string? GetString(JsonElement element, string name) =>
        TryGetPropertyIgnoreCase(element, name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? GetNested(JsonElement element, string parent, string child) =>
        TryGetPropertyIgnoreCase(element, parent, out var p) && p.ValueKind == JsonValueKind.Object
            ? GetString(p, child)
            : null;

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in element.EnumerateObject())
            {
                if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = prop.Value;
                    return true;
                }
            }
        }
        value = default;
        return false;
    }

    private static string? Truncate(string? text) =>
        text is null || text.Length <= MaxEvidenceLength ? text : text[..MaxEvidenceLength] + "…";
}

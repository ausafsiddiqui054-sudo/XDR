using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.ScubaGear;

/// <summary>
/// Converts ScubaGear's consolidated results (ScubaResults.json, v1.8.0) into normalized findings.
/// "Results" maps each product (AAD, EXO, ...) to groups of controls; each control carries
/// "Control ID", "Requirement", "Result", "Criticality" and "Details", with HTML in the text.
/// </summary>
/// <remarks>
/// Results: Pass; Fail (a SHALL control not met); Warning (a SHOULD control not met); N/A (manual,
/// third-party or not implemented); Error / "Error - Test results missing"; Omitted and
/// "Incorrect result" (set in a ScubaGear config file). Criticality: Shall, Should or May, optionally
/// with "/3rd Party" or "/Not-Implemented"; "-" for deleted controls.
/// </remarks>
public static partial class ScubaGearResultParser
{
    private const int MaxEvidenceLength = 2000;
    private const string Framework = "CISA SCuBA";

    public static IReadOnlyList<Finding> Parse(string json, Guid tenantId, DateTimeOffset? detectedAt = null)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (!TryGet(root, "Results", out var results) || results.ValueKind != JsonValueKind.Object)
            return [];

        var productNames = ProductNames(root);
        var when = detectedAt ?? DateTimeOffset.UtcNow;
        var findings = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var product in results.EnumerateObject())
        {
            if (product.Value.ValueKind != JsonValueKind.Array) continue;
            foreach (var group in product.Value.EnumerateArray())
            {
                if (!TryGet(group, "Controls", out var controls) || controls.ValueKind != JsonValueKind.Array) continue;
                var groupName = GetString(group, "GroupName");
                var helpUrl = GetString(group, "GroupReferenceURL");

                foreach (var control in controls.EnumerateArray())
                {
                    var controlId = GetString(control, "Control ID");
                    if (string.IsNullOrWhiteSpace(controlId) || !seen.Add(controlId)) continue;

                    var requirementHtml = GetString(control, "Requirement") ?? string.Empty;
                    var result = GetString(control, "Result");
                    var criticality = GetString(control, "Criticality");
                    var productName = productNames.GetValueOrDefault(product.Name, product.Name);

                    List<string> tags = [product.Name];
                    if (requirementHtml.Contains("indicator-bod", StringComparison.Ordinal)) tags.Add("BOD 25-01");
                    if (string.Equals(result, "N/A", StringComparison.OrdinalIgnoreCase)) tags.Add("Manual check");

                    findings.Add(new Finding
                    {
                        Id = $"scubagear:{tenantId:N}:{controlId}",
                        TenantId = tenantId,
                        Source = "ScubaGear",
                        SourceCheckId = controlId,
                        Title = PlainText(PolicyIndicators().Replace(requirementHtml, " ")) is { Length: > 0 } title ? title : controlId,
                        Description = groupName is null ? $"CISA {productName} baseline" : $"CISA {productName} baseline · {groupName}",
                        Category = MapCategory(product.Name),
                        Severity = MapSeverity(criticality),
                        Status = MapStatus(result),
                        Evidence = Truncate(PlainText(GetString(control, "Details"))),
                        HelpUrl = helpUrl,
                        Frameworks = [Framework],
                        Tags = tags,
                        DetectedAt = when
                    });
                }
            }
        }

        return findings;
    }

    /// <summary>SHALL controls are mandatory in the CISA baselines, SHOULD ones recommended.</summary>
    public static Severity MapSeverity(string? criticality) => criticality?.Split('/')[0].Trim().ToLowerInvariant() switch
    {
        "shall" => Severity.High,
        "should" => Severity.Medium,
        "may" => Severity.Low,
        _ => Severity.Info
    };

    public static FindingStatus MapStatus(string? result) => result?.Trim().ToLowerInvariant() switch
    {
        "pass" => FindingStatus.Passed,
        // Warning is ScubaGear's result for a SHOULD control that isn't met: a failure at lower severity.
        "fail" or "warning" => FindingStatus.Failed,
        _ => FindingStatus.NotEvaluated // N/A (manual), Error, Omitted, Incorrect result, unknown
    };

    private static string MapCategory(string product) => product.ToLowerInvariant() switch
    {
        "aad" => "Identity",
        "exo" or "defender" or "securitysuite" => "Email",
        "sharepoint" or "teams" => "Collaboration",
        "powerplatform" or "powerbi" => "Apps and data",
        _ => "General"
    };

    /// <summary>Product abbreviation (the key under Results) → full name, from MetaData.</summary>
    private static Dictionary<string, string> ProductNames(JsonElement root)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (TryGet(root, "MetaData", out var meta) && TryGet(meta, "ProductAbbreviationMapping", out var mapping)
            && mapping.ValueKind == JsonValueKind.Object)
        {
            foreach (var entry in mapping.EnumerateObject())
                if (entry.Value.ValueKind == JsonValueKind.String)
                    names[entry.Value.GetString()!] = entry.Name;
        }
        return names;
    }

    /// <summary>ScubaGear's text carries report HTML (links, line breaks, badges). Keep the words only.</summary>
    private static string PlainText(string? html)
    {
        if (string.IsNullOrEmpty(html)) return string.Empty;
        var text = WebUtility.HtmlDecode(Tags().Replace(html, " "));
        return Whitespace().Replace(text, " ").Trim();
    }

    private static string? GetString(JsonElement element, string name) =>
        TryGet(element, name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool TryGet(JsonElement element, string name, out JsonElement value)
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

    private static string? Truncate(string text) =>
        text.Length == 0 ? null : text.Length <= MaxEvidenceLength ? text : text[..MaxEvidenceLength] + "…";

    /// <summary>The badge block ScubaGear appends to each requirement ("BOD 25-01 Requirement", "Automated Check", ...).</summary>
    [GeneratedRegex("<div class=['\"]policy-indicators['\"]>.*?</div>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex PolicyIndicators();

    [GeneratedRegex("<[^>]*>")]
    private static partial Regex Tags();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}

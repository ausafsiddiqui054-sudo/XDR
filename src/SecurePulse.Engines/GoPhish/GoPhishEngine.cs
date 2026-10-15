using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.GoPhish;

/// <summary>
/// Imports a tenant's phishing simulation results from GoPhish. SecurePulse never creates, launches or
/// changes campaigns and never sends mail: campaigns are run in GoPhish by the tenant's own GoPhish user,
/// and this engine reads only their aggregate counts with that user's key (GET and HEAD only).
/// </summary>
public sealed class GoPhishEngine(
    HttpClient http,
    GoPhishOptions options,
    IGoPhishApiKeyProvider keys,
    TimeProvider time,
    ILogger<GoPhishEngine> logger) : IScanEngine
{
    public string Name => ScanEngines.GoPhish;

    public async Task<ScanResult> RunAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        var started = time.GetUtcNow();
        if (!tenant.GoPhishEnabled)
            return Fail(tenant, started, $"GoPhish results aren't turned on for {tenant.DisplayName}.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        var ct = timeout.Token;
        var keyName = GoPhishSecrets.ApiKeySecretName(tenant.Id);

        try
        {
            var client = new GoPhishClient(http, options, await keys.GetApiKeyAsync(tenant.Id, ct), keyName);
            await client.EnsureStandardUserAsync(ct);
            var campaigns = await client.GetCampaignSummariesAsync(ct);

            var now = time.GetUtcNow();
            var findings = GoPhishMapper.ToFindings(tenant.Id, campaigns, options.FindingSeverity, now - options.Lookback, now);
            var days = (int)options.Lookback.TotalDays;
            if (findings.Count == 0)
                return Fail(tenant, started, $"No GoPhish campaigns launched in the last {days} days by the GoPhish user whose key is in '{keyName}'. " +
                                             "Run the tenant's campaigns as that user.");
            if (findings.All(f => f.Status == FindingStatus.NotEvaluated))
                return Fail(tenant, started, $"None of the {findings.Count} GoPhish campaigns from the last {days} days has finished yet.");

            logger.LogInformation("GoPhish import for {Tenant}: {Campaigns} campaigns", tenant.DisplayName, findings.Count);
            return new ScanResult
            {
                TenantId = tenant.Id,
                Source = Name,
                StartedAt = started,
                CompletedAt = time.GetUtcNow(),
                Findings = findings
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Fail(tenant, started, $"The GoPhish import timed out after {options.Timeout.TotalMinutes:0} minutes.");
        }
        catch (Exception ex) when (ex is GoPhishException or JsonException or HttpRequestException or NotSupportedException)
        {
            return Fail(tenant, started, ex.Message);
        }
    }

    private ScanResult Fail(Tenant tenant, DateTimeOffset started, string error) => new()
    {
        TenantId = tenant.Id,
        Source = Name,
        StartedAt = started,
        CompletedAt = time.GetUtcNow(),
        Findings = [],
        Succeeded = false,
        Error = error.Length > 1000 ? error[..1000] + "…" : error
    };
}

/// <summary>One finding per launched campaign. It fails when anyone entered data on the landing page.</summary>
internal static class GoPhishMapper
{
    public const string Category = "Security awareness";

    // Campaigns in these states haven't sent anything yet.
    private static readonly HashSet<string> NotLaunched = new(StringComparer.OrdinalIgnoreCase) { "Created", "Queued" };

    public static IReadOnlyList<Finding> ToFindings(Guid tenantId, IEnumerable<GoPhishCampaignSummary> campaigns, Severity severity,
        DateTimeOffset launchedAfter, DateTimeOffset now)
    {
        var findings = new List<Finding>();
        foreach (var c in campaigns
                     .Where(c => c.Id > 0 && c.Stats is { Total: > 0 } && !NotLaunched.Contains(c.Status ?? "")
                                 && c.LaunchDate >= launchedAfter && c.LaunchDate <= now)
                     .OrderByDescending(c => c.LaunchDate).ThenBy(c => c.Id))
        {
            var s = c.Stats!;
            var completed = string.Equals(c.Status, "Completed", StringComparison.OrdinalIgnoreCase);
            var status = s.SubmittedData > 0 ? FindingStatus.Failed
                : completed && s.Sent > 0 ? FindingStatus.Passed
                : FindingStatus.NotEvaluated;

            var evidence = s.Sent == 0
                ? $"No email was delivered ({s.Error} of {s.Total} couldn't be sent)."
                : $"{s.SubmittedData} of {s.Sent} recipients entered data on the landing page ({Percent(s.SubmittedData, s.Sent)}). " +
                  $"{s.Clicked} clicked the link ({Percent(s.Clicked, s.Sent)}), {s.Opened} opened the email ({Percent(s.Opened, s.Sent)}) " +
                  $"and {s.EmailReported} reported it ({Percent(s.EmailReported, s.Sent)})." +
                  (s.Error > 0 ? $" {s.Error} email{(s.Error == 1 ? "" : "s")} couldn't be sent." : "") +
                  (completed ? "" : " The campaign is still running; these are the results so far.");

            findings.Add(new Finding
            {
                Id = $"gophish:{tenantId:N}:{c.Id}",
                TenantId = tenantId,
                Source = ScanEngines.GoPhish,
                SourceCheckId = $"campaign:{c.Id}",
                Title = $"Phishing simulation: {Clip(Clean(c.Name) ?? $"campaign {c.Id}", 300)}",
                Description = $"Simulated phishing campaign launched {c.LaunchDate.UtcDateTime:yyyy-MM-dd}" +
                              (completed && c.CompletedDate > c.LaunchDate ? $" and completed {c.CompletedDate.UtcDateTime:yyyy-MM-dd}" : "") +
                              ". Anyone who entered data on the landing page would have given their credentials to a real attacker.",
                Category = Category,
                Severity = severity,
                Status = status,
                Evidence = evidence,
                Remediation = "Give the people who entered data short, targeted awareness training, and have them change any password they " +
                              "typed in. Require phishing-resistant MFA (passkeys, FIDO2 keys or Windows Hello) so a captured password isn't " +
                              "enough on its own, and make reporting easy with the Report button in Outlook.",
                Tags = ["GoPhish", "Phishing simulation"],
                DetectedAt = now
            });
        }
        return findings;
    }

    private static string Percent(long part, long whole) =>
        (whole == 0 ? 0 : Math.Round(100.0 * part / whole)).ToString("0", CultureInfo.InvariantCulture) + "%";

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : string.Join(' ', s.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static string Clip(string s, int max) => s.Length > max ? s[..max] + "…" : s;
}

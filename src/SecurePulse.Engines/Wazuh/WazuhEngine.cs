using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.Wazuh;

/// <summary>
/// The Wazuh API user may only read. In "white" RBAC mode nothing is allowed unless a policy allows it,
/// so every allowed action must be a read; "black" mode allows everything not denied, so it's refused.
/// The scan needs agent:read and sca:read.
/// </summary>
public static class WazuhRbac
{
    public static readonly IReadOnlyList<string> Required = ["agent:read", "sca:read"];

    /// <summary>Why the user's effective policies (GET /security/users/me/policies) aren't acceptable, or null.</summary>
    public static string? Problem(JsonElement policies)
    {
        if (policies.ValueKind != JsonValueKind.Object)
            return "Wazuh didn't return the user's policies.";
        var mode = policies.TryGetProperty("rbac_mode", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
        if (!string.Equals(mode, "white", StringComparison.OrdinalIgnoreCase))
            return $"Not scanning: Wazuh RBAC is in '{mode ?? "unknown"}' mode, where everything not explicitly denied is allowed. " +
                   "Use white mode so the SecurePulse user can only do what its role allows.";

        var allowed = policies.EnumerateObject()
            .Where(p => p.Name != "rbac_mode" && p.Value.ValueKind == JsonValueKind.Object
                        && p.Value.EnumerateObject().Any(r => r.Value.ValueKind == JsonValueKind.String
                                                              && string.Equals(r.Value.GetString(), "allow", StringComparison.OrdinalIgnoreCase)))
            .Select(p => p.Name)
            .ToList();

        var notRead = allowed.Where(a => !a.EndsWith(":read", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        if (notRead.Count > 0)
            return $"Not scanning: the Wazuh user can do more than read ({string.Join(", ", notRead)}). Give it a role with read actions only.";

        var missing = Required.Where(r => !allowed.Contains(r, StringComparer.Ordinal)).ToList();
        return missing.Count > 0 ? $"The Wazuh user's role doesn't allow {string.Join(" and ", missing)}." : null;
    }
}

/// <summary>
/// Reads Security Configuration Assessment (CIS benchmark) results for one tenant's agents from the
/// shared Wazuh manager, over read-only API calls (no process, no shell). Only agents in the tenant's
/// agent group are read, and agents that are also in another tenant's group are left out.
/// </summary>
public sealed class WazuhEngine(
    HttpClient http,
    WazuhOptions options,
    IWazuhPasswordProvider passwords,
    ITenantRepository tenants,
    TimeProvider time,
    ILogger<WazuhEngine> logger) : IScanEngine
{
    public string Name => ScanEngines.Wazuh;

    public async Task<ScanResult> RunAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        var started = time.GetUtcNow();
        if (WazuhAgentGroups.Problem(tenant.WazuhAgentGroup) is { } groupProblem)
            return Fail(tenant, started, $"No usable Wazuh agent group for {tenant.DisplayName}: {groupProblem}");
        var group = tenant.WazuhAgentGroup!;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        var ct = timeout.Token;

        try
        {
            var client = new WazuhClient(http, options, passwords);
            await client.SignInAsync(ct);
            if (WazuhRbac.Problem(await client.GetEffectivePoliciesAsync(ct)) is { } rbac)
                return Fail(tenant, started, rbac);

            var otherGroups = (await tenants.GetAllAsync(ct))
                .Where(t => t.Id != tenant.Id && !string.IsNullOrWhiteSpace(t.WazuhAgentGroup))
                .Select(t => t.WazuhAgentGroup!)
                .ToHashSet(StringComparer.Ordinal);

            var inGroup = (await client.GetAgentsAsync(group, ct))
                .Where(a => a.Id is { Length: > 0 } && a.Id != "000" && (a.Group?.Contains(group, StringComparer.Ordinal) ?? false))
                .ToList();
            var shared = inGroup.Where(a => a.Group!.Any(otherGroups.Contains)).ToList();
            var agents = inGroup.Except(shared).ToList();
            if (shared.Count > 0)
                logger.LogWarning("Wazuh scan for {Tenant}: left out {Count} agents that are also in another tenant's group", tenant.DisplayName, shared.Count);
            if (agents.Count == 0)
                return Fail(tenant, started, shared.Count > 0
                    ? $"Every agent in Wazuh group '{group}' is also in another tenant's group, so none were read."
                    : $"No agents found in Wazuh group '{group}'. Check the group name on the Tenants page and that the agents are assigned to it.");

            var results = new List<AgentChecks>();
            await Parallel.ForEachAsync(agents, new ParallelOptions { MaxDegreeOfParallelism = options.MaxConcurrentRequests, CancellationToken = ct },
                async (agent, token) =>
                {
                    var checks = new List<WazuhScaCheck>();
                    foreach (var policy in await client.GetScaPoliciesAsync(agent.Id!, token))
                    {
                        if (string.IsNullOrWhiteSpace(policy.PolicyId)) continue;
                        checks.AddRange((await client.GetChecksAsync(agent.Id!, policy.PolicyId, token))
                            .Select(c => { c.PolicyId ??= policy.PolicyId; return c; }));
                    }
                    lock (results) results.Add(new AgentChecks(agent.Name ?? agent.Id!, checks));
                });

            var findings = WazuhScaMapper.ToFindings(tenant.Id, results, options.FindingSeverity, time.GetUtcNow());
            if (findings.All(f => f.Status == FindingStatus.NotEvaluated))
                return Fail(tenant, started, $"None of the {agents.Count} agents in Wazuh group '{group}' has SCA results yet. Check that SCA is enabled on them.");

            logger.LogInformation("Wazuh scan for {Tenant}: {Findings} checks from {Agents} agents", tenant.DisplayName, findings.Count, agents.Count);
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
            return Fail(tenant, started, $"The Wazuh scan timed out after {options.Timeout.TotalMinutes:0} minutes.");
        }
        catch (Exception ex) when (ex is WazuhException or JsonException or HttpRequestException)
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

internal sealed record AgentChecks(string AgentName, IReadOnlyList<WazuhScaCheck> Checks);

/// <summary>Turns per-agent SCA check results into one finding per policy check for the tenant.</summary>
internal static class WazuhScaMapper
{
    public const string Category = "Endpoint hardening";
    private const int MaxNamesShown = 10;

    private static readonly Dictionary<string, string> FrameworkNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cis"] = "CIS",
        ["cis_csc"] = "CIS Controls",
        ["cis_csc_v7"] = "CIS Controls v7",
        ["cis_csc_v8"] = "CIS Controls v8",
        ["pci_dss"] = "PCI DSS",
        ["hipaa"] = "HIPAA",
        ["nist_800_53"] = "NIST 800-53",
        ["iso_27001-2013"] = "ISO 27001:2013",
        ["iso_27001-2022"] = "ISO 27001:2022",
        ["gdpr_IV"] = "GDPR",
        ["tsc"] = "SOC 2",
        ["soc_2"] = "SOC 2"
    };

    public static IReadOnlyList<Finding> ToFindings(Guid tenantId, IReadOnlyList<AgentChecks> agents, Severity severity, DateTimeOffset at)
    {
        var byCheck = agents
            .SelectMany(a => a.Checks.Where(c => !string.IsNullOrWhiteSpace(c.PolicyId)).Select(c => (Agent: a.AgentName, Check: c)))
            .GroupBy(x => (x.Check.PolicyId!, x.Check.Id));

        var findings = new List<Finding>();
        foreach (var g in byCheck.OrderBy(g => g.Key.Item1, StringComparer.Ordinal).ThenBy(g => g.Key.Id))
        {
            var (policyId, checkId) = g.Key;
            var check = g.First().Check;
            var failed = g.Where(x => Result(x.Check) == "failed").Select(x => x.Agent).Distinct().Order(StringComparer.OrdinalIgnoreCase).ToList();
            var passed = g.Where(x => Result(x.Check) == "passed").Select(x => x.Agent).Distinct().Count();
            var other = g.Select(x => x.Agent).Distinct().Count() - failed.Count - passed;

            var status = failed.Count > 0 ? FindingStatus.Failed : passed > 0 ? FindingStatus.Passed : FindingStatus.NotEvaluated;
            var evidence = status switch
            {
                FindingStatus.Failed => $"Failed on {failed.Count} of {failed.Count + passed} agents: {Names(failed)}.",
                FindingStatus.Passed => $"Passed on {(passed == 1 ? "the only agent" : $"all {passed} agents")} it applies to.",
                _ => $"Not applicable or not checked on {other} agent{(other == 1 ? "" : "s")}{(Clean(check.Reason) is { } reason ? $" ({reason})" : "")}."
            };

            findings.Add(new Finding
            {
                Id = $"wazuh:{tenantId:N}:{policyId}:{checkId}",
                TenantId = tenantId,
                Source = ScanEngines.Wazuh,
                SourceCheckId = $"{policyId}:{checkId}",
                Title = Clip(Clean(check.Title) ?? $"SCA check {checkId}", 500)!,
                Description = Clip(Clean(string.Join("\n\n", new[] { Clean(check.Description), Clean(check.Rationale) is { } why ? $"Why it matters: {why}" : null }
                    .Where(s => s is not null))), 4000),
                Category = Category,
                Severity = severity,
                Status = status,
                Evidence = Clip(evidence, 2000),
                Remediation = Clip(Clean(check.Remediation), 4000),
                HelpUrl = FirstHttpsLink(check.References),
                Frameworks = Frameworks(check.Compliance),
                Tags = ["Wazuh SCA", policyId],
                DetectedAt = at
            });
        }
        return findings;
    }

    private static string Result(WazuhScaCheck c) => c.Result?.Trim().ToLowerInvariant() ?? "";

    private static string Names(List<string> agents) =>
        agents.Count <= MaxNamesShown ? string.Join(", ", agents) : $"{string.Join(", ", agents.Take(MaxNamesShown))} and {agents.Count - MaxNamesShown} more";

    private static IReadOnlyList<string> Frameworks(List<WazuhCompliance>? compliance) =>
        (compliance ?? [])
            .Where(c => !string.IsNullOrWhiteSpace(c.Key) && !string.IsNullOrWhiteSpace(c.Value) && !c.Key!.StartsWith("mitre", StringComparison.OrdinalIgnoreCase))
            .Select(c => $"{(FrameworkNames.TryGetValue(c.Key!, out var name) ? name : c.Key)} {c.Value!.Trim()}")
            .Select(s => Clip(s, 120)!)
            .Distinct(StringComparer.Ordinal)
            .Take(20)
            .ToList();

    /// <summary>Engine text is untrusted: only an https link is kept.</summary>
    private static string? FirstHttpsLink(string? references) =>
        (references ?? "").Split([',', ' ', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .FirstOrDefault(r => Uri.TryCreate(r, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(u.UserInfo));

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string? Clip(string? s, int max) => s is { Length: > 0 } && s.Length > max ? s[..max] + "…" : s;
}

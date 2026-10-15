using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

/// <summary>The Audit log page's filters; the CSV export takes the same ones from its query string.</summary>
public sealed record AuditFilter
{
    public static readonly IReadOnlyList<(string Key, string Label, TimeSpan? Span)> Periods =
    [
        ("24h", "Last 24 hours", TimeSpan.FromHours(24)),
        ("7d", "Last 7 days", TimeSpan.FromDays(7)),
        ("30d", "Last 30 days", TimeSpan.FromDays(30)),
        ("90d", "Last 90 days", TimeSpan.FromDays(90)),
        ("all", "All time", null)
    ];

    public string Period { get; init; } = "7d";
    public string? Category { get; init; }
    public AuditOutcome? Outcome { get; init; }
    public Guid? TenantId { get; init; }
    public string? Search { get; init; }

    public AuditQuery ToQuery(DateTimeOffset now, int limit, (DateTimeOffset, Guid)? before = null)
    {
        var span = Periods.FirstOrDefault(p => p.Key == Period).Span;
        return new AuditQuery
        {
            From = span is { } s ? now - s : null,
            Category = string.IsNullOrEmpty(Category) ? null : Category,
            Outcome = Outcome,
            TenantId = TenantId,
            Search = string.IsNullOrWhiteSpace(Search) ? null : Search.Trim(),
            Limit = limit,
            Before = before
        };
    }

    public string ToQueryString() => QueryHelpers.AddQueryString("", new Dictionary<string, string?>
    {
        ["period"] = Period,
        ["category"] = Category,
        ["outcome"] = Outcome?.ToString(),
        ["tenant"] = TenantId?.ToString(),
        ["search"] = Search
    }.Where(kv => !string.IsNullOrEmpty(kv.Value)));

    public static AuditFilter FromQuery(IQueryCollection q) => new()
    {
        Period = Periods.Any(p => p.Key == q["period"]) ? q["period"].ToString() : "7d",
        Category = AuditActions.Categories.ContainsKey(q["category"].ToString()) ? q["category"].ToString() : null,
        Outcome = Enum.TryParse<AuditOutcome>(q["outcome"], out var o) ? o : null,
        TenantId = Guid.TryParse(q["tenant"], out var t) ? t : null,
        Search = q["search"].ToString() is { Length: > 0 and <= 200 } s ? s : null
    };
}

public static class AuditExport
{
    /// <summary>Upper bound per export, so one request can't pull an unbounded table into memory.</summary>
    public const int MaxRows = 50_000;

    public static void MapAuditExport(this WebApplication app) =>
        app.MapGet("/settings/audit/export.csv", async (HttpContext http, IAuditLog log, ITenantRepository tenants, AuditTrail audit, TimeProvider time) =>
        {
            var filter = AuditFilter.FromQuery(http.Request.Query);
            var names = (await tenants.GetAllAsync()).ToDictionary(t => t.Id, t => t.DisplayName);
            var now = time.GetUtcNow();

            var csv = new StringBuilder();
            csv.Append(Row("OccurredAtUtc", "Action", "Event", "Outcome", "Actor", "ActorUserId", "TenantId", "Tenant",
                "TargetType", "TargetId", "Summary", "Details", "IpAddress")).Append("\r\n"); // RFC 4180 line endings

            var rows = 0;
            (DateTimeOffset, Guid)? before = null;
            while (rows < MaxRows)
            {
                var page = await log.QueryAsync(filter.ToQuery(now, Math.Min(1000, MaxRows - rows), before));
                foreach (var e in page)
                {
                    csv.Append(Row(e.OccurredAt.UtcDateTime.ToString("O"), e.Action, AuditActions.Label(e.Action), e.Outcome.ToString(),
                        e.ActorName, e.ActorUserId?.ToString(), e.TenantId?.ToString(), e.TenantId is { } id ? names.GetValueOrDefault(id) : null,
                        e.TargetType, e.TargetId, e.Summary, e.Details.Count == 0 ? null : JsonSerializer.Serialize(e.Details), e.IpAddress)).Append("\r\n");
                }
                rows += page.Count;
                if (page.Count == 0 || page.Count < 1000) break;
                before = (page[^1].OccurredAt, page[^1].Id);
            }

            await audit.RecordAsync(AuditActions.AuditExported, AuditOutcome.Success, $"Exported {rows} audit events",
                filter.TenantId, details: new Dictionary<string, string> { ["filter"] = filter.ToQueryString(), ["rows"] = rows.ToString() },
                actor: UserContext.From(http.User), ipAddress: http.Connection.RemoteIpAddress?.ToString());

            var fileName = $"securepulse-audit-{now:yyyyMMdd-HHmm}.csv";
            // UTF-8 BOM so Excel reads non-ASCII names correctly.
            return Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray(), "text/csv", fileName);
        }).RequireAuthorization(Policies.Operator);

    internal static string Row(params string?[] cells) => string.Join(',', cells.Select(Cell));

    /// <summary>
    /// Quotes every cell, and neutralizes values a spreadsheet would run as a formula
    /// (=, +, -, @, tab, CR): audit text includes names and domains other people typed.
    /// </summary>
    internal static string Cell(string? value)
    {
        value ??= "";
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}

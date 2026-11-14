using Hasinix.Core.Abstractions;
using Hasinix.Reporting;
using Hasinix.Web.Security;

namespace Hasinix.Web.Services;

/// <summary>The combined daily score of the tenants the user may see, and each tenant's own.</summary>
public sealed record ScoreTrends(IReadOnlyList<ScoreTrendPoint> Combined, IReadOnlyDictionary<Guid, IReadOnlyList<ScoreTrendPoint>> ByTenant)
{
    public static readonly ScoreTrends Empty = new([], new Dictionary<Guid, IReadOnlyList<ScoreTrendPoint>>());
}

/// <summary>Daily score trends from the recorded snapshots. Days follow the report time zone (Reports:TimeZone).</summary>
/// <remarks>Only covers tenants the current user may see (client viewers: their own).</remarks>
public sealed class ScoreTrendService(IScoreHistory history, IUserContextAccessor users, ReportSettings reports, TimeProvider time)
{
    public const int DefaultDays = 90;

    /// <summary>Snapshots this many days before the window give each tenant its starting score.</summary>
    private const int LeadInDays = 14;

    public async Task<ScoreTrends> GetAsync(int days = DefaultDays, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        // A client viewer's query is narrowed to their tenant; everyone's rows are filtered by CanSee as well.
        if (!user.IsOperator && user.ClientTenantId is null) return ScoreTrends.Empty;

        var now = time.GetUtcNow();
        var to = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, reports.TimeZone).DateTime);
        var from = to.AddDays(-(days - 1));
        var snapshots = (await history.GetSinceAsync(now.AddDays(-(days + LeadInDays)), user.IsOperator ? null : user.ClientTenantId, ct))
            .Where(s => user.CanSee(s.TenantId))
            .ToList();

        var byTenant = snapshots.GroupBy(s => s.TenantId)
            .ToDictionary(g => g.Key, g => ScoreTrend.Daily(g, from, to, reports.TimeZone));
        return new ScoreTrends(ScoreTrend.Daily(snapshots, from, to, reports.TimeZone), byTenant);
    }
}

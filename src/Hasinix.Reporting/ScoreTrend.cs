using Hasinix.Core.Models;

namespace Hasinix.Reporting;

/// <summary>The score on one day. <paramref name="Tenants"/> is how many tenants the score covers.</summary>
public sealed record ScoreTrendPoint(DateOnly Day, int Score, string Grade, int Tenants);

/// <summary>How far the score moved between <paramref name="Since"/> and the latest point.</summary>
public sealed record ScoreChange(int Delta, DateOnly Since);

/// <summary>
/// Turns score snapshots into one point per day. A day's score is each tenant's latest snapshot
/// on or before that day, so days without a scan keep the last known score. With several tenants
/// the points are combined the way the portfolio score is (<see cref="RiskScoreCalculator.AverageOf"/>,
/// grade capped while any tenant has an open critical).
/// </summary>
public static class ScoreTrend
{
    /// <summary>
    /// Daily points from <paramref name="from"/> to <paramref name="to"/> in <paramref name="zone"/>. Snapshots before
    /// <paramref name="from"/> only supply the starting score; the series starts on the first day any tenant has one.
    /// </summary>
    public static IReadOnlyList<ScoreTrendPoint> Daily(IEnumerable<ScoreSnapshot> snapshots, DateOnly from, DateOnly to, TimeZoneInfo zone)
    {
        var byTenant = snapshots
            .Select(s => (Day: DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(s.RecordedAt, zone).DateTime), Snapshot: s))
            .Where(x => x.Day <= to)
            .GroupBy(x => x.Snapshot.TenantId)
            .Select(g => g.OrderBy(x => x.Snapshot.RecordedAt).ToList())
            .ToList();

        var points = new List<ScoreTrendPoint>();
        var next = new int[byTenant.Count];
        var latest = new RiskScore?[byTenant.Count];
        for (var day = from; day <= to; day = day.AddDays(1))
        {
            for (var t = 0; t < byTenant.Count; t++)
            {
                while (next[t] < byTenant[t].Count && byTenant[t][next[t]].Day <= day)
                    latest[t] = byTenant[t][next[t]++].Snapshot.Score;
            }

            var known = latest.Where(s => s is not null).Select(s => s!).ToList();
            if (known.Count == 0) continue;
            var score = RiskScoreCalculator.AverageOf(known.Select(s => s.Score));
            var openCritical = known.Any(s => s.FailedBySeverity.GetValueOrDefault(Severity.Critical) > 0);
            points.Add(new ScoreTrendPoint(day, score, RiskScoreCalculator.GradeFor(score, openCritical), known.Count));
        }
        return points;
    }

    /// <summary>
    /// The change over the last <paramref name="days"/> days: the latest point against the point that many days
    /// earlier, or against the first point when the history is shorter. Null with fewer than two points.
    /// </summary>
    public static ScoreChange? Change(IReadOnlyList<ScoreTrendPoint> points, int days)
    {
        if (points.Count < 2) return null;
        var last = points[^1];
        var target = last.Day.AddDays(-days);
        var start = points.LastOrDefault(p => p.Day <= target) ?? points[0];
        return new ScoreChange(last.Score - start.Score, start.Day);
    }
}

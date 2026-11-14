using Hasinix.Core.Abstractions;
using Hasinix.Core.Models;
using Hasinix.Reporting;
using Hasinix.Reporting.Pdf;
using Hasinix.Tests.Onboarding;
using Hasinix.Web.Services;

namespace Hasinix.Tests.Reporting;

public class ScoreTrendTests
{
    private static readonly Guid A = Guid.NewGuid();
    private static readonly Guid B = Guid.NewGuid();
    private static readonly DateOnly Day1 = new(2026, 11, 1);

    private static ScoreSnapshot Snap(Guid tenant, DateTimeOffset at, int score, int openCritical = 0) => new()
    {
        Id = Guid.NewGuid(), TenantId = tenant, RecordedAt = at, Engine = ScanEngines.Maester,
        Score = new RiskScore
        {
            Score = score, Grade = RiskScoreCalculator.GradeFor(score, openCritical > 0), Passed = 0, Failed = openCritical, Investigate = 0,
            NotEvaluated = 0, FailedBySeverity = new Dictionary<Severity, int> { [Severity.Critical] = openCritical }
        }
    };

    private static DateTimeOffset At(int day, int hour = 6) => new(2026, 11, day, hour, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DaysWithoutAScanKeepTheLastScore()
    {
        var points = ScoreTrend.Daily([Snap(A, At(1), 60), Snap(A, At(4), 70)], Day1, Day1.AddDays(4), TimeZoneInfo.Utc);

        Assert.Equal([60, 60, 60, 70, 70], points.Select(p => p.Score));
        Assert.Equal(Enumerable.Range(0, 5).Select(Day1.AddDays), points.Select(p => p.Day));
    }

    [Fact]
    public void TheLastSnapshotOfADayWins()
    {
        // Four engines can finish on the same day; the day's score is the one after the last of them.
        var points = ScoreTrend.Daily([Snap(A, At(1, 9), 66), Snap(A, At(1, 2), 60), Snap(A, At(1, 5), 63)], Day1, Day1, TimeZoneInfo.Utc);

        Assert.Equal(66, Assert.Single(points).Score);
    }

    [Fact]
    public void SnapshotsBeforeTheWindowOnlyGiveTheStartingScore()
    {
        var points = ScoreTrend.Daily([Snap(A, At(1), 55), Snap(A, At(6), 65)], Day1.AddDays(3), Day1.AddDays(6), TimeZoneInfo.Utc);

        Assert.Equal(Day1.AddDays(3), points[0].Day);
        Assert.Equal([55, 55, 65, 65], points.Select(p => p.Score));
    }

    [Fact]
    public void TheSeriesStartsOnTheFirstDayWithAScore()
    {
        var points = ScoreTrend.Daily([Snap(A, At(3), 70)], Day1, Day1.AddDays(3), TimeZoneInfo.Utc);

        Assert.Equal([Day1.AddDays(2), Day1.AddDays(3)], points.Select(p => p.Day));
        Assert.Empty(ScoreTrend.Daily([], Day1, Day1.AddDays(3), TimeZoneInfo.Utc));
    }

    [Fact]
    public void SeveralTenantsAreAveragedOverThoseThatHaveAScore()
    {
        var points = ScoreTrend.Daily([Snap(A, At(1), 60), Snap(B, At(2), 90), Snap(A, At(3), 80)], Day1, Day1.AddDays(2), TimeZoneInfo.Utc);

        Assert.Equal([(60, 1), (75, 2), (85, 2)], points.Select(p => (p.Score, p.Tenants)));
    }

    [Fact]
    public void TheCombinedGradeIsCappedWhileAnyTenantHasAnOpenCritical()
    {
        var points = ScoreTrend.Daily([Snap(A, At(1), 95), Snap(B, At(1), 95, openCritical: 1), Snap(B, At(2), 95)], Day1, Day1.AddDays(1), TimeZoneInfo.Utc);

        Assert.Equal(["C", "A"], points.Select(p => p.Grade));
    }

    [Fact]
    public void DaysFollowTheTimeZone()
    {
        // 22:00 UTC on the 1st is already the 2nd in Dubai (UTC+4).
        var dubai = TimeZoneInfo.CreateCustomTimeZone("test+4", TimeSpan.FromHours(4), "test+4", "test+4");

        var points = ScoreTrend.Daily([Snap(A, At(1, 22), 70)], Day1, Day1.AddDays(1), dubai);

        Assert.Equal(Day1.AddDays(1), Assert.Single(points).Day);
    }

    [Fact]
    public void ChangeComparesWithThePointThatManyDaysEarlier()
    {
        var points = Enumerable.Range(0, 41).Select(i => new ScoreTrendPoint(Day1.AddDays(i), 50 + i, "F", 1)).ToList();

        Assert.Equal(new ScoreChange(30, Day1.AddDays(10)), ScoreTrend.Change(points, 30));
    }

    [Fact]
    public void ChangeFallsBackToTheFirstPointWhenTheHistoryIsShort()
    {
        var points = new[] { new ScoreTrendPoint(Day1, 70, "C", 1), new ScoreTrendPoint(Day1.AddDays(1), 64, "D", 1) };

        Assert.Equal(new ScoreChange(-6, Day1), ScoreTrend.Change(points, 30));
        Assert.Null(ScoreTrend.Change(points[..1], 30));
        Assert.Null(ScoreTrend.Change([], 30));
    }

    [Fact]
    public void AverageOfRoundsAndTreatsNoScoresAsZero()
    {
        Assert.Equal(0, RiskScoreCalculator.AverageOf([]));
        Assert.Equal(67, RiskScoreCalculator.AverageOf([60, 70, 70]));
    }
}

public class ScoreTrendServiceTests
{
    private static readonly ReportSettings Reports = new() { Enabled = false, Branding = new ReportBranding(), TimeZone = TimeZoneInfo.Utc };

    private static async Task<(SampleDataStore Store, List<Tenant> Scanned)> StoreAsync()
    {
        var store = new SampleDataStore();
        return (store, (await store.GetAllAsync()).Where(t => t.LastScanAt is not null).ToList());
    }

    [Fact]
    public async Task TheSampleHistoryEndsAtEachTenantsCurrentScore()
    {
        var (store, scanned) = await StoreAsync();
        var trends = await new ScoreTrendService(store, FixedUser.Owner(), Reports, TimeProvider.System).GetAsync();

        Assert.Equal(scanned.Select(t => t.Id).Order(), trends.ByTenant.Keys.Order());
        foreach (var tenant in scanned)
        {
            var current = RiskScoreCalculator.Calculate(await store.GetForTenantAsync(tenant.Id));
            var last = trends.ByTenant[tenant.Id][^1];
            Assert.Equal((current.Score, current.Grade), (last.Score, last.Grade));
        }
        Assert.Equal(ScoreTrendService.DefaultDays, trends.Combined.Count);
        Assert.Equal(scanned.Count, trends.Combined[^1].Tenants);
    }

    [Fact]
    public async Task AClientViewerOnlyGetsTheirOwnTenantsTrend()
    {
        var (store, scanned) = await StoreAsync();
        var mine = scanned[0];

        var trends = await new ScoreTrendService(store, FixedUser.Viewer(mine.Id), Reports, TimeProvider.System).GetAsync();

        Assert.Equal([mine.Id], trends.ByTenant.Keys);
        Assert.All(trends.Combined, p => Assert.Equal(1, p.Tenants));
        Assert.Equal(trends.ByTenant[mine.Id], trends.Combined);
    }

    [Fact]
    public async Task NoRoleGetsNoTrend()
    {
        var (store, _) = await StoreAsync();

        var trends = await new ScoreTrendService(store, FixedUser.Anonymous(), Reports, TimeProvider.System).GetAsync();

        Assert.Empty(trends.Combined);
        Assert.Empty(trends.ByTenant);
    }
}

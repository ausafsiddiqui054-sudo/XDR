using SecurePulse.Core.Models;
using SecurePulse.Engines.Maester;
using SecurePulse.Reporting;

namespace SecurePulse.Tests.Reporting;

public class RiskScoreCalculatorTests
{
    private static int _next;

    private static Finding F(Severity severity, FindingStatus status, string category = "Identity") => new()
    {
        Id = $"test:{Interlocked.Increment(ref _next)}",
        TenantId = Guid.Empty,
        Source = "Test",
        Title = $"{severity} {status}",
        Category = category,
        Severity = severity,
        Status = status
    };

    private static IEnumerable<Finding> Many(int count, Severity severity, FindingStatus status) =>
        Enumerable.Range(0, count).Select(_ => F(severity, status));

    [Theory]
    [InlineData(Severity.Critical, 10)]
    [InlineData(Severity.High, 6)]
    [InlineData(Severity.Medium, 3)]
    [InlineData(Severity.Low, 1)]
    [InlineData(Severity.Info, 0)]
    public void WeightOf(Severity severity, int expected) =>
        Assert.Equal(expected, RiskScoreCalculator.WeightOf(severity));

    [Fact]
    public void AllPassed_Scores100GradeA()
    {
        var score = RiskScoreCalculator.Calculate([F(Severity.Critical, FindingStatus.Passed), F(Severity.Low, FindingStatus.Passed)]);

        Assert.Equal(100, score.Score);
        Assert.Equal("A", score.Grade);
    }

    [Fact]
    public void AllFailed_Scores0GradeF()
    {
        var score = RiskScoreCalculator.Calculate([F(Severity.High, FindingStatus.Failed), F(Severity.Low, FindingStatus.Failed)]);

        Assert.Equal(0, score.Score);
        Assert.Equal("F", score.Grade);
    }

    [Fact]
    public void Score_IsShareOfSeverityWeightThatPassed()
    {
        // Passed High (6) + failed Medium (3) + failed Low (1): 6 / 10 = 60.
        var score = RiskScoreCalculator.Calculate([
            F(Severity.High, FindingStatus.Passed),
            F(Severity.Medium, FindingStatus.Failed),
            F(Severity.Low, FindingStatus.Failed)
        ]);

        Assert.Equal(60, score.Score);
    }

    // --- Investigate = half credit -------------------------------------------------------

    [Fact]
    public void Investigate_EarnsHalfCredit()
    {
        var score = RiskScoreCalculator.Calculate([F(Severity.High, FindingStatus.Investigate)]);

        Assert.Equal(50, score.Score);
    }

    [Fact]
    public void Investigate_EarnsHalfOfItsOwnWeight()
    {
        // Investigate Critical (5 of 10) + passed High (6 of 6) + failed Medium (0 of 3): 11 / 19 = 57.9.
        var score = RiskScoreCalculator.Calculate([
            F(Severity.Critical, FindingStatus.Investigate),
            F(Severity.High, FindingStatus.Passed),
            F(Severity.Medium, FindingStatus.Failed)
        ]);

        Assert.Equal(58, score.Score);
    }

    // --- NotEvaluated excluded -----------------------------------------------------------

    [Fact]
    public void NotEvaluated_IsExcludedFromTheScore()
    {
        Finding[] evaluated = [F(Severity.High, FindingStatus.Passed), F(Severity.Medium, FindingStatus.Failed)];

        var without = RiskScoreCalculator.Calculate(evaluated);
        var with = RiskScoreCalculator.Calculate([.. evaluated, .. Many(10, Severity.Critical, FindingStatus.NotEvaluated)]);

        Assert.Equal(67, without.Score);
        Assert.Equal(without.Score, with.Score);
        Assert.Equal(without.Grade, with.Grade);
        Assert.Equal(10, with.NotEvaluated);
    }

    [Fact]
    public void NotEvaluatedCritical_DoesNotCapTheGrade()
    {
        var score = RiskScoreCalculator.Calculate([
            F(Severity.High, FindingStatus.Passed),
            F(Severity.Critical, FindingStatus.NotEvaluated)
        ]);

        Assert.Equal("A", score.Grade);
    }

    [Fact]
    public void InfoFindings_CarryNoWeight()
    {
        var score = RiskScoreCalculator.Calculate([
            F(Severity.High, FindingStatus.Passed),
            .. Many(5, Severity.Info, FindingStatus.Failed)
        ]);

        Assert.Equal(100, score.Score);
    }

    // --- Critical caps the grade ---------------------------------------------------------

    [Fact]
    public void OpenCritical_CapsGradeAtC()
    {
        // 15 passed High (90) + 1 failed Critical (10): 90 / 100 = 90, which would be an A.
        var score = RiskScoreCalculator.Calculate([
            .. Many(15, Severity.High, FindingStatus.Passed),
            F(Severity.Critical, FindingStatus.Failed)
        ]);

        Assert.Equal(90, score.Score);
        Assert.Equal("C", score.Grade);
    }

    [Fact]
    public void OpenCritical_CapsGradeBAtC()
    {
        // 7 passed High (42) + 1 failed Critical (10): 42 / 52 = 80.8, which would be a B.
        var score = RiskScoreCalculator.Calculate([
            .. Many(7, Severity.High, FindingStatus.Passed),
            F(Severity.Critical, FindingStatus.Failed)
        ]);

        Assert.Equal(81, score.Score);
        Assert.Equal("C", score.Grade);
    }

    [Fact]
    public void OpenCritical_DoesNotRaiseALowerGrade()
    {
        // 1 passed High (6) + 1 failed Critical (10): 6 / 16 = 37.5 → 38, stays F.
        var score = RiskScoreCalculator.Calculate([
            F(Severity.High, FindingStatus.Passed),
            F(Severity.Critical, FindingStatus.Failed)
        ]);

        Assert.Equal("F", score.Grade);
    }

    [Fact]
    public void InvestigateCritical_DoesNotCapTheGrade()
    {
        // 20 passed High (120) + 1 Critical under investigation (5 of 10): 125 / 130 = 96.
        var score = RiskScoreCalculator.Calculate([
            .. Many(20, Severity.High, FindingStatus.Passed),
            F(Severity.Critical, FindingStatus.Investigate)
        ]);

        Assert.Equal(96, score.Score);
        Assert.Equal("A", score.Grade);
    }

    // --- Grade bands and rounding --------------------------------------------------------

    [Theory]
    [InlineData(90, "A")]
    [InlineData(89, "B")]
    [InlineData(80, "B")]
    [InlineData(79, "C")]
    [InlineData(70, "C")]
    [InlineData(69, "D")]
    [InlineData(60, "D")]
    [InlineData(59, "F")]
    public void GradeBands(int passedLows, string expected)
    {
        // Low findings weigh 1, so passed out of 100 gives the score directly.
        var score = RiskScoreCalculator.Calculate([
            .. Many(passedLows, Severity.Low, FindingStatus.Passed),
            .. Many(100 - passedLows, Severity.Low, FindingStatus.Failed)
        ]);

        Assert.Equal(passedLows, score.Score);
        Assert.Equal(expected, score.Grade);
    }

    [Fact]
    public void Score_RoundsHalfAwayFromZero()
    {
        // 1 passed Low + 1 Low under investigation (0.5) + 2 failed Low: 1.5 / 4 = 37.5 → 38.
        var score = RiskScoreCalculator.Calculate([
            F(Severity.Low, FindingStatus.Passed),
            F(Severity.Low, FindingStatus.Investigate),
            .. Many(2, Severity.Low, FindingStatus.Failed)
        ]);

        Assert.Equal(38, score.Score);
    }

    // --- Counts --------------------------------------------------------------------------

    [Fact]
    public void Counts_AndFailedBySeverity()
    {
        var score = RiskScoreCalculator.Calculate([
            F(Severity.Critical, FindingStatus.Failed),
            F(Severity.High, FindingStatus.Failed),
            F(Severity.High, FindingStatus.Failed),
            F(Severity.High, FindingStatus.Passed),
            F(Severity.Medium, FindingStatus.Investigate),
            F(Severity.Low, FindingStatus.NotEvaluated)
        ]);

        Assert.Equal(1, score.Passed);
        Assert.Equal(3, score.Failed);
        Assert.Equal(1, score.Investigate);
        Assert.Equal(1, score.NotEvaluated);

        Assert.Equal(Enum.GetValues<Severity>().Length, score.FailedBySeverity.Count);
        Assert.Equal(1, score.FailedBySeverity[Severity.Critical]);
        Assert.Equal(2, score.FailedBySeverity[Severity.High]);
        Assert.Equal(0, score.FailedBySeverity[Severity.Medium]);
        Assert.Equal(0, score.FailedBySeverity[Severity.Low]);
        Assert.Equal(0, score.FailedBySeverity[Severity.Info]);
    }

    // --- End to end with the Maester sample ----------------------------------------------

    [Fact]
    public void MaesterSample_ScoresAsExpected()
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "samples", "maester-results.sample.json"));
        var findings = MaesterResultParser.Parse(json, Guid.NewGuid());

        var score = RiskScoreCalculator.Calculate(findings);

        // Earned: High 6 + Medium 3 + Medium investigate 1.5 = 10.5.
        // Possible: Critical 10 + High 6 + High 6 + Medium 3 + Medium 3 = 28. Skipped Low excluded.
        Assert.Equal(38, score.Score);
        Assert.Equal("F", score.Grade);
        Assert.Equal(2, score.Passed);
        Assert.Equal(2, score.Failed);
        Assert.Equal(1, score.Investigate);
        Assert.Equal(1, score.NotEvaluated);
    }

    // --- Top risks -----------------------------------------------------------------------

    [Fact]
    public void TopRisks_FailedBeforeInvestigateThenSeverityThenCategory()
    {
        var critEmail = F(Severity.Critical, FindingStatus.Failed, "Email");
        var critDevices = F(Severity.Critical, FindingStatus.Failed, "Devices");
        var high = F(Severity.High, FindingStatus.Failed);
        var investigateCritical = F(Severity.Critical, FindingStatus.Investigate);

        var top = RiskScoreCalculator.TopRisks([
            investigateCritical,
            high,
            F(Severity.Critical, FindingStatus.Passed),
            critEmail,
            F(Severity.High, FindingStatus.NotEvaluated),
            critDevices
        ]);

        Assert.Equal([critDevices, critEmail, high, investigateCritical], top);
    }

    [Fact]
    public void TopRisks_RespectsTake() =>
        Assert.Equal(3, RiskScoreCalculator.TopRisks(Many(10, Severity.High, FindingStatus.Failed), take: 3).Count);
}

using SecurePulse.Core.Models;

namespace SecurePulse.Reporting;

/// <summary>
/// Turns findings into one 0–100 score. Each evaluated check carries a weight by severity;
/// the score is the share of weight that passed. "Investigate" earns half credit.
/// Checks that weren't evaluated (skipped, unlicensed, errored) are excluded so clients
/// aren't penalised for features they don't own.
/// </summary>
public static class RiskScoreCalculator
{
    public static int WeightOf(Severity severity) => severity switch
    {
        Severity.Critical => 10,
        Severity.High => 6,
        Severity.Medium => 3,
        Severity.Low => 1,
        _ => 0
    };

    public static RiskScore Calculate(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();

        double earned = 0, possible = 0;
        foreach (var f in list)
        {
            var w = WeightOf(f.Severity);
            switch (f.Status)
            {
                case FindingStatus.Passed: earned += w; possible += w; break;
                case FindingStatus.Investigate: earned += w / 2.0; possible += w; break;
                case FindingStatus.Failed: possible += w; break;
            }
        }

        var score = possible == 0 ? 0 : (int)Math.Round(100 * earned / possible, MidpointRounding.AwayFromZero);

        // A single open critical caps the grade: a client can't be an "A" with MFA off for admins.
        var hasOpenCritical = list.Any(f => f.Status == FindingStatus.Failed && f.Severity == Severity.Critical);
        var grade = ToGrade(score, hasOpenCritical);

        return new RiskScore
        {
            Score = score,
            Grade = grade,
            Passed = list.Count(f => f.Status == FindingStatus.Passed),
            Failed = list.Count(f => f.Status == FindingStatus.Failed),
            Investigate = list.Count(f => f.Status == FindingStatus.Investigate),
            NotEvaluated = list.Count(f => f.Status == FindingStatus.NotEvaluated),
            FailedBySeverity = Enum.GetValues<Severity>().ToDictionary(
                s => s,
                s => list.Count(f => f.Status == FindingStatus.Failed && f.Severity == s))
        };
    }

    private static string ToGrade(int score, bool hasOpenCritical)
    {
        var grade = score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };
        return hasOpenCritical && (grade is "A" or "B") ? "C" : grade;
    }

    /// <summary>Failed findings ordered by impact: severity first, then category.</summary>
    public static IReadOnlyList<Finding> TopRisks(IEnumerable<Finding> findings, int take = 10) =>
        findings.Where(f => f.Status is FindingStatus.Failed or FindingStatus.Investigate)
            .OrderByDescending(f => f.Status == FindingStatus.Failed)
            .ThenByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .Take(take)
            .ToList();
}

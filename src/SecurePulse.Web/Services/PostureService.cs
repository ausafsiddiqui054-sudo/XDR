using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Reporting;

namespace SecurePulse.Web.Services;

public sealed record TenantPosture(Tenant Tenant, RiskScore? Score, IReadOnlyList<Finding> Findings)
{
    public bool HasScan => Tenant.LastScanAt is not null && Findings.Count > 0;
}

public sealed record PortfolioPosture(IReadOnlyList<TenantPosture> Tenants)
{
    public IEnumerable<TenantPosture> Scanned => Tenants.Where(t => t.HasScan);

    public int AverageScore => Scanned.Any() ? (int)Math.Round(Scanned.Average(t => t.Score!.Score)) : 0;

    public int OpenOf(Severity severity) =>
        Scanned.Sum(t => t.Findings.Count(f => f.Status == FindingStatus.Failed && f.Severity == severity));

    public int PassRatePercent
    {
        get
        {
            var evaluated = Scanned.SelectMany(t => t.Findings).Where(f => f.Status != FindingStatus.NotEvaluated).ToList();
            return evaluated.Count == 0 ? 0 : (int)Math.Round(100.0 * evaluated.Count(f => f.Status == FindingStatus.Passed) / evaluated.Count);
        }
    }

    public IReadOnlyList<(TenantPosture Tenant, Finding Finding)> TopRisks(int take = 8) =>
        Scanned.SelectMany(t => RiskScoreCalculator.TopRisks(t.Findings, take).Select(f => (t, f)))
            .OrderByDescending(x => x.f.Status == FindingStatus.Failed)
            .ThenByDescending(x => x.f.Severity)
            .ThenBy(x => x.t.Score!.Score)
            .Take(take)
            .ToList();
}

/// <summary>Assembles tenants, findings and scores for the UI.</summary>
public sealed class PostureService(ITenantRepository tenants, IFindingRepository findings)
{
    public async Task<PortfolioPosture> GetPortfolioAsync(CancellationToken ct = default)
    {
        var list = new List<TenantPosture>();
        foreach (var tenant in await tenants.GetAllAsync(ct))
        {
            var f = await findings.GetForTenantAsync(tenant.Id, ct);
            list.Add(new TenantPosture(tenant, f.Count > 0 ? RiskScoreCalculator.Calculate(f) : null, f));
        }
        return new PortfolioPosture(list.OrderBy(t => t.Score?.Score ?? int.MaxValue).ToList());
    }
}

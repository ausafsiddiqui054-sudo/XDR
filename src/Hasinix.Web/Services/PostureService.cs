using Hasinix.Core.Abstractions;
using Hasinix.Core.Models;
using Hasinix.Reporting;
using Hasinix.Web.Security;

namespace Hasinix.Web.Services;

public sealed record TenantPosture(Tenant Tenant, RiskScore? Score, IReadOnlyList<Finding> Findings)
{
    public bool HasScan => Tenant.LastScanAt is not null && Findings.Count > 0;
}

public sealed record PortfolioPosture(IReadOnlyList<TenantPosture> Tenants)
{
    public IEnumerable<TenantPosture> Scanned => Tenants.Where(t => t.HasScan);

    public int AverageScore => RiskScoreCalculator.AverageOf(Scanned.Select(t => t.Score!.Score));

    /// <summary>The average score's grade, capped like a tenant's when any scanned tenant has an open critical.</summary>
    public string AverageGrade => RiskScoreCalculator.GradeFor(AverageScore, OpenOf(Severity.Critical) > 0);

    /// <summary>Tenants that have granted consent (read-only or remediation); pending and revoked ones aren't connected.</summary>
    public int ConnectedCount => Tenants.Count(t =>
        t.Tenant.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted);

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
/// <remarks>Only returns tenants the current user may see (client viewers: their own).</remarks>
public sealed class PostureService(ITenantRepository tenants, IFindingRepository findings, IUserContextAccessor users)
{
    public async Task<PortfolioPosture> GetPortfolioAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        var list = new List<TenantPosture>();
        foreach (var tenant in (await tenants.GetAllAsync(ct)).Where(t => user.CanSee(t.Id)))
        {
            var f = await findings.GetForTenantAsync(tenant.Id, ct);
            list.Add(new TenantPosture(tenant, f.Count > 0 ? RiskScoreCalculator.Calculate(f) : null, f));
        }
        return new PortfolioPosture(list.OrderBy(t => t.Score?.Score ?? int.MaxValue).ToList());
    }
}

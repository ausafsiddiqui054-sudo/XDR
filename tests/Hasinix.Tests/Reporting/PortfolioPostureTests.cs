using Hasinix.Core.Models;
using Hasinix.Reporting;
using Hasinix.Web.Services;

namespace Hasinix.Tests.Reporting;

public class PortfolioPostureTests
{
    private static int _next;

    private static Finding F(Guid tenantId, Severity severity, FindingStatus status) => new()
    {
        Id = $"test:{Interlocked.Increment(ref _next)}",
        TenantId = tenantId,
        Source = "Test",
        Title = $"{severity} {status}",
        Category = "Identity",
        Severity = severity,
        Status = status
    };

    private static TenantPosture Posture(TenantConsentState consent, params (Severity Severity, FindingStatus Status, int Count)[] findings)
    {
        var tenant = new Tenant
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Clinic", PrimaryDomain = "clinic.example",
            ConsentState = consent, LastScanAt = findings.Length > 0 ? DateTimeOffset.UtcNow : null
        };
        var list = findings.SelectMany(x => Enumerable.Range(0, x.Count).Select(_ => F(tenant.Id, x.Severity, x.Status))).ToList();
        return new TenantPosture(tenant, list.Count > 0 ? RiskScoreCalculator.Calculate(list) : null, list);
    }

    [Fact]
    public void AverageGrade_IsCappedWhenAnyTenantHasAnOpenCritical()
    {
        // Two tenants at 100 and one at 90 (with an open critical) average 97: an A without the cap.
        var portfolio = new PortfolioPosture([
            Posture(TenantConsentState.ReadOnlyGranted, (Severity.High, FindingStatus.Passed, 10)),
            Posture(TenantConsentState.ReadOnlyGranted, (Severity.High, FindingStatus.Passed, 10)),
            Posture(TenantConsentState.ReadOnlyGranted, (Severity.High, FindingStatus.Passed, 15), (Severity.Critical, FindingStatus.Failed, 1))
        ]);

        Assert.Equal(97, portfolio.AverageScore);
        Assert.Equal("C", portfolio.AverageGrade);
    }

    [Fact]
    public void AverageGrade_UsesTheBandsWithoutAnOpenCritical()
    {
        var portfolio = new PortfolioPosture([
            Posture(TenantConsentState.ReadOnlyGranted, (Severity.High, FindingStatus.Passed, 10)),
            Posture(TenantConsentState.RemediationGranted, (Severity.Low, FindingStatus.Passed, 80), (Severity.Low, FindingStatus.Failed, 20))
        ]);

        Assert.Equal(90, portfolio.AverageScore);
        Assert.Equal("A", portfolio.AverageGrade);
    }

    [Fact]
    public void ConnectedCount_LeavesOutPendingAndRevokedTenants()
    {
        var portfolio = new PortfolioPosture([
            Posture(TenantConsentState.ReadOnlyGranted, (Severity.High, FindingStatus.Passed, 1)),
            Posture(TenantConsentState.RemediationGranted),
            Posture(TenantConsentState.Pending),
            Posture(TenantConsentState.Revoked)
        ]);

        Assert.Equal(2, portfolio.ConnectedCount);
        Assert.Equal(4, portfolio.Tenants.Count);
    }
}

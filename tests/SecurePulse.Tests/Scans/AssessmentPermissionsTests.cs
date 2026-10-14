using SecurePulse.Core.Models;

namespace SecurePulse.Tests.Scans;

public class AssessmentPermissionsTests
{
    [Fact]
    public void EveryRequiredPermissionIsReadOnly() =>
        // Guards CLAUDE.md rule 5: nobody can add a write permission to the assessment app by accident.
        Assert.All(AssessmentPermissions.Required, p => Assert.True(AssessmentPermissions.IsReadOnly(p.Name), p.Name));

    [Fact]
    public void NoDuplicatesAndEveryPermissionHasAGroupAndPurpose()
    {
        Assert.Equal(AssessmentPermissions.Required.Count, AssessmentPermissions.Required.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(AssessmentPermissions.Required, p =>
        {
            Assert.False(string.IsNullOrWhiteSpace(p.Purpose));
            Assert.Contains(p.Group, new[] { AssessmentPermissions.DevicesGroup, AssessmentPermissions.SecurityChecksGroup, AssessmentPermissions.CisaBaselineGroup });
        });
    }

    [Fact]
    public void IncludesMaestersUnattendedPermissions()
    {
        var names = AssessmentPermissions.Required.Select(p => p.Name).ToHashSet();

        foreach (var p in new[] { "Directory.Read.All", "Policy.Read.All", "Policy.Read.ConditionalAccess", "AuditLog.Read.All",
                     "RoleManagement.Read.All", "UserAuthenticationMethod.Read.All", "SharePointTenantSettings.Read.All" })
            Assert.Contains(p, names);
        // Maester 2.3.0 lists 25 for unattended runs; the two device-management ones are also Intune's.
        Assert.Equal(23, AssessmentPermissions.Required.Count(p => p.Group == AssessmentPermissions.SecurityChecksGroup));
        Assert.Contains("DeviceManagementConfiguration.Read.All", names);
        Assert.Contains("DeviceManagementManagedDevices.Read.All", names);
        Assert.DoesNotContain("Sites.FullControl.All", names);
        Assert.DoesNotContain("Exchange.ManageAsApp", names);
    }

    [Fact]
    public void MissingFromAndNotReadOnly()
    {
        var all = AssessmentPermissions.Required.Select(p => p.Name).ToList();

        Assert.Empty(AssessmentPermissions.MissingFrom(all.Select(p => p.ToUpperInvariant())));
        Assert.Equal(["Directory.Read.All"], AssessmentPermissions.MissingFrom(all.Where(p => p != "Directory.Read.All")));
        Assert.Equal(["Mail.Send", "User.ReadWrite.All"], AssessmentPermissions.NotReadOnly([.. all, "User.ReadWrite.All", "Mail.Send"]));
    }

    [Fact]
    public void EachEngineHasItsOwnListWithinTheRequiredOnes()
    {
        var required = AssessmentPermissions.Required.Select(p => p.Name).ToHashSet();
        var maester = AssessmentPermissions.RequiredFor(ScanEngines.Maester);
        var scubaGear = AssessmentPermissions.RequiredFor(ScanEngines.ScubaGear);

        Assert.Equal(25, maester.Count);
        // ScubaGear 1.8.0's Entra ID (aad) list for service principals.
        Assert.Equal(["Directory.Read.All", "Policy.Read.All", "PrivilegedAccess.Read.AzureADGroup", "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            "RoleManagement.Read.Directory", "RoleManagementPolicy.Read.AzureADGroup", "User.Read.All"], scubaGear);
        Assert.All(maester.Concat(scubaGear), p => Assert.Contains(p, required));
        // Every required permission is used by some engine (or the device sync, which Maester's list includes).
        Assert.Empty(required.Except(maester).Except(scubaGear));
        Assert.Equal(required.Order(), AssessmentPermissions.RequiredFor("SomethingElse").Order());
        Assert.Equal(5, AssessmentPermissions.Required.Count(p => p.Group == AssessmentPermissions.CisaBaselineGroup));
    }

    [Fact]
    public void ScubaGearsPrivilegedProductPermissionsAreNotRequested()
    {
        var names = AssessmentPermissions.Required.Select(p => p.Name).ToList();

        Assert.DoesNotContain("Exchange.ManageAsApp", names);
        Assert.DoesNotContain("Sites.FullControl.All", names);
        Assert.False(AssessmentPermissions.IsReadOnly("Exchange.ManageAsApp"));
    }

    [Fact]
    public void MissingFromCanCheckOneEngine()
    {
        var maesterOnly = AssessmentPermissions.RequiredFor(ScanEngines.Maester);

        Assert.Empty(AssessmentPermissions.MissingFrom(maesterOnly, maesterOnly));
        Assert.Equal(["PrivilegedAccess.Read.AzureADGroup", "PrivilegedEligibilitySchedule.Read.AzureADGroup", "RoleManagement.Read.Directory",
            "RoleManagementPolicy.Read.AzureADGroup", "User.Read.All"], AssessmentPermissions.MissingFrom(maesterOnly, AssessmentPermissions.RequiredFor(ScanEngines.ScubaGear)));
    }
}

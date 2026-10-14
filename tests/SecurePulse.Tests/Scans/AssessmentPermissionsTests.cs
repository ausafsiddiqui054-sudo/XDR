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
            Assert.Contains(p.Group, new[] { AssessmentPermissions.DevicesGroup, AssessmentPermissions.SecurityChecksGroup });
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
}

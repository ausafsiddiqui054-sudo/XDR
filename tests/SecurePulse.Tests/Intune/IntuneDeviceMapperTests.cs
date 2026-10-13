using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Tests.Intune;

public class IntuneDeviceMapperTests
{
    private static readonly Guid TenantId = Guid.Parse("8d2f5c1a-0b3e-4c6d-9e7f-1a2b3c4d5e6f");

    [Theory]
    [InlineData("Windows", DevicePlatform.Windows)]
    [InlineData("macOS", DevicePlatform.MacOS)]
    [InlineData("iOS", DevicePlatform.iOS)]
    [InlineData("iPadOS", DevicePlatform.iOS)]
    [InlineData("Android", DevicePlatform.Android)]
    [InlineData("AndroidForWork", DevicePlatform.Android)]
    [InlineData("Linux", DevicePlatform.Linux)]
    [InlineData("ChromeOS", DevicePlatform.Other)]
    [InlineData("", DevicePlatform.Other)]
    [InlineData(null, DevicePlatform.Other)]
    public void MapPlatform(string? os, DevicePlatform expected) =>
        Assert.Equal(expected, IntuneDeviceMapper.MapPlatform(os));

    [Theory]
    [InlineData("company", DeviceOwnership.Corporate)]
    [InlineData("personal", DeviceOwnership.Personal)]
    [InlineData("unknown", DeviceOwnership.Unknown)]
    [InlineData(null, DeviceOwnership.Unknown)]
    public void MapOwnership(string? owner, DeviceOwnership expected) =>
        Assert.Equal(expected, IntuneDeviceMapper.MapOwnership(owner));

    [Theory]
    [InlineData("compliant", DeviceComplianceState.Compliant)]
    [InlineData("noncompliant", DeviceComplianceState.Noncompliant)]
    [InlineData("nonCompliant", DeviceComplianceState.Noncompliant)]
    [InlineData("inGracePeriod", DeviceComplianceState.InGracePeriod)]
    [InlineData("conflict", DeviceComplianceState.Unknown)]
    [InlineData("error", DeviceComplianceState.Unknown)]
    [InlineData("configManager", DeviceComplianceState.Unknown)]
    [InlineData("unknown", DeviceComplianceState.Unknown)]
    [InlineData(null, DeviceComplianceState.Unknown)]
    public void MapCompliance(string? state, DeviceComplianceState expected) =>
        Assert.Equal(expected, IntuneDeviceMapper.MapCompliance(state));

    [Fact]
    public void Map_CopiesFieldsAndNormalizesBlanks()
    {
        var enrolled = new DateTimeOffset(2025, 3, 1, 8, 0, 0, TimeSpan.Zero);
        var synced = new DateTimeOffset(2026, 10, 12, 21, 15, 0, TimeSpan.Zero);

        var d = IntuneDeviceMapper.Map(new GraphManagedDevice
        {
            Id = "dev-1",
            DeviceName = " LT-001 ",
            UserDisplayName = "Aisha Rahman",
            UserPrincipalName = "aisha@contoso.example",
            OperatingSystem = "Windows",
            OsVersion = "10.0.22631.4317",
            Manufacturer = "Dell Inc.",
            Model = "Latitude 5440",
            SerialNumber = "   ",
            ManagedDeviceOwnerType = "company",
            ComplianceState = "noncompliant",
            IsEncrypted = false,
            EnrolledDateTime = enrolled,
            LastSyncDateTime = synced
        }, TenantId);

        Assert.Equal("dev-1", d.Id);
        Assert.Equal(TenantId, d.TenantId);
        Assert.Equal("LT-001", d.DeviceName);
        Assert.Equal("Aisha Rahman", d.UserDisplayName);
        Assert.Equal("aisha@contoso.example", d.UserPrincipalName);
        Assert.Equal(DevicePlatform.Windows, d.Platform);
        Assert.Equal("10.0.22631.4317", d.OsVersion);
        Assert.Equal("Dell Inc.", d.Manufacturer);
        Assert.Equal("Latitude 5440", d.Model);
        Assert.Null(d.SerialNumber);
        Assert.Equal(DeviceOwnership.Corporate, d.Ownership);
        Assert.Equal(DeviceComplianceState.Noncompliant, d.ComplianceState);
        Assert.False(d.IsEncrypted);
        Assert.Equal(DefenderState.Unknown, d.Defender);
        Assert.Equal(enrolled, d.EnrolledAt);
        Assert.Equal(synced, d.LastSyncAt);
        Assert.Empty(d.ComplianceSettings);
    }

    [Fact]
    public void Map_GraphNeverDateBecomesNull()
    {
        var d = IntuneDeviceMapper.Map(new GraphManagedDevice
        {
            Id = "dev-1",
            LastSyncDateTime = DateTimeOffset.MinValue,
            EnrolledDateTime = DateTimeOffset.MinValue
        }, TenantId);

        Assert.Null(d.LastSyncAt);
        Assert.Null(d.EnrolledAt);
    }

    [Fact]
    public void Map_MissingNameFallsBackToId() =>
        Assert.Equal("dev-1", IntuneDeviceMapper.Map(new GraphManagedDevice { Id = "dev-1" }, TenantId).DeviceName);

    [Fact]
    public void Map_MissingIdThrows() =>
        Assert.Throws<ArgumentException>(() => IntuneDeviceMapper.Map(new GraphManagedDevice(), TenantId));

    [Fact]
    public void MapSettings_FlattensPoliciesAndMapsStates()
    {
        var settings = IntuneDeviceMapper.MapSettings([
            new GraphCompliancePolicyState
            {
                DisplayName = "Windows baseline",
                State = "nonCompliant",
                SettingStates =
                [
                    new() { Setting = "Windows10CompliancePolicy.bitLockerEnabled", SettingName = "Require BitLocker", State = "nonCompliant", ErrorDescription = "BitLocker is off" },
                    new() { Setting = "Windows10CompliancePolicy.secureBootEnabled", State = "compliant" },
                    new() { Setting = "Windows10CompliancePolicy.osMinimumVersion", SettingName = "Minimum OS", State = "remediated" },
                    new() { Setting = "Windows10CompliancePolicy.firewall", SettingName = "Firewall", State = "conflict" },
                    new() { Setting = "Windows10CompliancePolicy.tpm", SettingName = "TPM", State = "error" },
                    new() { Setting = "Windows10CompliancePolicy.antivirus", SettingName = "Antivirus", State = "notApplicable" },
                    new() { Setting = "Windows10CompliancePolicy.password", SettingName = "Password", State = "unknown" }
                ]
            }
        ]);

        Assert.Equal(
        [
            new DeviceComplianceSetting("Windows baseline", "Require BitLocker", false, "BitLocker is off"),
            new DeviceComplianceSetting("Windows baseline", "secureBootEnabled", true),
            new DeviceComplianceSetting("Windows baseline", "Minimum OS", true),
            new DeviceComplianceSetting("Windows baseline", "Firewall", false, "Conflicts with another assigned policy."),
            new DeviceComplianceSetting("Windows baseline", "TPM", false, "Intune reported an error evaluating this setting.")
        ], settings);
    }

    [Theory]
    [InlineData("notApplicable")]
    [InlineData("notAssigned")]
    public void MapSettings_SkipsPoliciesThatDoNotApply(string policyState)
    {
        var settings = IntuneDeviceMapper.MapSettings([
            new GraphCompliancePolicyState
            {
                DisplayName = "macOS baseline",
                State = policyState,
                SettingStates = [new() { SettingName = "FileVault", State = "nonCompliant" }]
            }
        ]);

        Assert.Empty(settings);
    }

    [Fact]
    public void MapSettings_UnnamedPolicyAndBareFailureGetDefaults()
    {
        var s = Assert.Single(IntuneDeviceMapper.MapSettings([
            new GraphCompliancePolicyState { SettingStates = [new() { Setting = "passcodeRequired", State = "nonCompliant" }] }
        ]));

        Assert.Equal(new DeviceComplianceSetting("Compliance policy", "passcodeRequired", false, "Not compliant."), s);
    }
}

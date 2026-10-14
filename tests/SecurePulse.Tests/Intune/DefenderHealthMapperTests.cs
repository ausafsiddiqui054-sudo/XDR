using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Tests.Intune;

public class DefenderHealthMapperTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 14, 8, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("clean", DefenderThreatState.Clean)]
    [InlineData("fullScanPending", DefenderThreatState.FullScanPending)]
    [InlineData("rebootPending", DefenderThreatState.RebootPending)]
    [InlineData("manualStepsPending", DefenderThreatState.ManualStepsPending)]
    [InlineData("offlineScanPending", DefenderThreatState.OfflineScanPending)]
    [InlineData("critical", DefenderThreatState.Critical)]
    [InlineData("somethingNew", DefenderThreatState.Unknown)]
    [InlineData(null, DefenderThreatState.Unknown)]
    public void MapsThreatState(string? raw, DefenderThreatState expected) => Assert.Equal(expected, DefenderHealthMapper.MapThreatState(raw));

    [Theory]
    [InlineData("Onboarded", DefenderOnboarding.Onboarded)]
    [InlineData("Can be onboarded", DefenderOnboarding.CanBeOnboarded)]
    [InlineData("Unsupported", DefenderOnboarding.Unsupported)]
    [InlineData("Insufficient info", DefenderOnboarding.InsufficientInfo)]
    [InlineData("", DefenderOnboarding.Unknown)]
    [InlineData(null, DefenderOnboarding.Unknown)]
    public void MapsOnboarding(string? raw, DefenderOnboarding expected) => Assert.Equal(expected, DefenderHealthMapper.MapOnboarding(raw));

    [Theory]
    [InlineData("Active", DefenderSensorHealth.Active)]
    [InlineData("Inactive", DefenderSensorHealth.Inactive)]
    [InlineData("Impaired communications", DefenderSensorHealth.ImpairedCommunication)]
    [InlineData("No sensor data", DefenderSensorHealth.NoSensorData)]
    [InlineData("No sensor data, impaired communications", DefenderSensorHealth.NoSensorData)]
    [InlineData("Misconfigured", DefenderSensorHealth.Unknown)]
    [InlineData(null, DefenderSensorHealth.Unknown)]
    public void MapsSensorHealth(string? raw, DefenderSensorHealth expected) => Assert.Equal(expected, DefenderHealthMapper.MapSensorHealth(raw));

    [Fact]
    public void MapsAntivirus_DroppingNeverDates()
    {
        var av = DefenderHealthMapper.MapAntivirus(new GraphWindowsProtectionState
        {
            MalwareProtectionEnabled = true,
            RealTimeProtectionEnabled = false,
            TamperProtectionEnabled = true,
            SignatureUpdateOverdue = true,
            QuickScanOverdue = false,
            RebootRequired = true,
            DeviceState = "rebootPending",
            SignatureVersion = " 1.419.200.0 ",
            EngineVersion = "",
            LastQuickScanDateTime = DateTimeOffset.MinValue,
            LastReportedDateTime = T0
        });

        Assert.Equal(new DefenderAntivirusStatus
        {
            MalwareProtectionEnabled = true,
            RealTimeProtectionEnabled = false,
            TamperProtectionEnabled = true,
            SignaturesOutOfDate = true,
            QuickScanOverdue = false,
            RebootRequired = true,
            ThreatState = DefenderThreatState.RebootPending,
            SignatureVersion = "1.419.200.0",
            EngineVersion = null,
            LastQuickScanAt = null,
            LastReportedAt = T0
        }, av);
    }

    private static GraphManagedDevice Intune(string id, string name, Guid? entraId = null) =>
        new() { Id = id, DeviceName = name, OperatingSystem = "Windows", AzureADDeviceId = entraId?.ToString() };

    private static HuntingDeviceRow Row(string machineId, string name, Guid? entraId = null, string health = "Active", DateTimeOffset? at = null,
        bool upperCaseId = false) => new()
    {
        DeviceId = machineId, DeviceName = name, AadDeviceId = upperCaseId ? entraId?.ToString().ToUpperInvariant() : entraId?.ToString(),
        OnboardingStatus = "Onboarded",
        SensorHealthState = health, ExposureLevel = "Medium", Timestamp = at ?? T0
    };

    [Fact]
    public void MatchesByEntraDeviceId_IgnoringCaseAndName()
    {
        var entra = Guid.NewGuid();
        var matched = DefenderHealthMapper.Match(
            [Intune("i1", "RECEPTION-01", entra)],
            [Row("m1", "something-else.contoso.local", entra, upperCaseId: true)]);

        var sensor = Assert.Single(matched).Value;
        Assert.Equal(new DefenderSensorStatus
        {
            MachineId = "m1", Onboarding = DefenderOnboarding.Onboarded, Health = DefenderSensorHealth.Active, ExposureLevel = "Medium", LastSeenAt = T0
        }, sensor);
        Assert.Equal("i1", matched.Keys.Single());
    }

    [Fact]
    public void SeveralDefenderRecordsForOneDevice_TheLatestWins()
    {
        var entra = Guid.NewGuid();
        var matched = DefenderHealthMapper.Match(
            [Intune("i1", "PC-01", entra)],
            [Row("old", "pc-01", entra, "Inactive", T0.AddDays(-10)), Row("new", "pc-01", entra, "Active", T0), Row("older", "pc-01", entra, "Inactive", T0.AddDays(-20))]);

        Assert.Equal("new", matched["i1"].MachineId);
        Assert.Equal(DefenderSensorHealth.Active, matched["i1"].Health);
    }

    [Fact]
    public void WithoutAnEntraMatch_FallsBackToAUniqueHostName()
    {
        var matched = DefenderHealthMapper.Match(
            [Intune("i1", "PC-01"), Intune("i2", "PC-02", Guid.NewGuid())],
            [Row("m1", "pc-01.contoso.local"), Row("m2", "pc-02.contoso.local")]);

        Assert.Equal("m1", matched["i1"].MachineId);
        Assert.Equal("m2", matched["i2"].MachineId); // its Entra ID has no Defender record, so the name decides
    }

    [Fact]
    public void AmbiguousHostNames_AreNeverMatched()
    {
        var matched = DefenderHealthMapper.Match(
            [Intune("i1", "PC-01"), Intune("i2", "pc-01"), Intune("i3", "PC-03")],
            [Row("m1", "pc-01.contoso.local"), Row("m3a", "pc-03.contoso.local"), Row("m3b", "PC-03")]);

        Assert.Empty(matched); // two Intune PC-01s; two Defender PC-03s
    }

    [Fact]
    public void ARecordMatchedByEntraId_IsNotReusedByName()
    {
        var entra = Guid.NewGuid();
        var matched = DefenderHealthMapper.Match(
            [Intune("i1", "LAPTOP-RENAMED", entra), Intune("i2", "PC-01")],
            [Row("m1", "pc-01", entra)]);

        Assert.Equal(["i1"], matched.Keys);
    }

    [Fact]
    public void SameRecordUnderSeveralRows_StillCountsAsOneForNames()
    {
        var matched = DefenderHealthMapper.Match(
            [Intune("i1", "PC-01")],
            [Row("m1", "pc-01", at: T0.AddDays(-1)), Row("m1", "pc-01", at: T0)]);

        Assert.Equal("m1", matched["i1"].MachineId);
    }

    [Fact]
    public void TheHuntingQueryIsFixed()
    {
        // Nothing tenant- or user-supplied is ever put into the KQL.
        Assert.StartsWith("DeviceInfo ", DefenderHealthMapper.DeviceInfoQuery);
        Assert.Contains("arg_max(Timestamp, *) by DeviceId", DefenderHealthMapper.DeviceInfoQuery);
        Assert.DoesNotContain("{", DefenderHealthMapper.DeviceInfoQuery);
    }
}

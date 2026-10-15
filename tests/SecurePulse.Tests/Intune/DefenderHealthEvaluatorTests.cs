using SecurePulse.Core.Models;

namespace SecurePulse.Tests.Intune;

public class DefenderHealthEvaluatorTests
{
    private static readonly DefenderAntivirusStatus HealthyAv = new()
    {
        MalwareProtectionEnabled = true,
        RealTimeProtectionEnabled = true,
        TamperProtectionEnabled = true,
        SignaturesOutOfDate = false,
        ThreatState = DefenderThreatState.Clean
    };

    private static readonly DefenderSensorStatus ActiveSensor = new() { Onboarding = DefenderOnboarding.Onboarded, Health = DefenderSensorHealth.Active };

    [Fact]
    public void HealthyAntivirusAndActiveSensor_AreProtected()
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, HealthyAv, ActiveSensor, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Protected, state);
        Assert.Empty(health.Issues);
        Assert.Same(HealthyAv, health.Antivirus);
        Assert.Same(ActiveSensor, health.Sensor);
        Assert.True(health.SensorDataAvailable);
    }

    public static TheoryData<string, string> AntivirusProblems => new()
    {
        { "antivirus off", "Microsoft Defender Antivirus is turned off." },
        { "real-time off", "Real-time protection is off." },
        { "tamper off", "Tamper protection is off." },
        { "signatures old", "Security intelligence (signatures) is out of date." },
        { "critical", "Defender reports a critical threat state: a threat wasn't remediated." },
        { "reboot pending", "A threat needs a restart to finish remediation." },
        { "full scan pending", "A threat needs a full scan to finish remediation." },
        { "manual steps", "A threat needs manual steps to finish remediation." },
        { "offline scan", "A threat needs an offline scan to finish remediation." }
    };

    [Theory]
    [MemberData(nameof(AntivirusProblems))]
    public void AnyAntivirusProblem_IsUnhealthyWithItsIssue(string scenario, string issue)
    {
        var av = scenario switch
        {
            "antivirus off" => HealthyAv with { MalwareProtectionEnabled = false },
            "real-time off" => HealthyAv with { RealTimeProtectionEnabled = false },
            "tamper off" => HealthyAv with { TamperProtectionEnabled = false },
            "signatures old" => HealthyAv with { SignaturesOutOfDate = true },
            "critical" => HealthyAv with { ThreatState = DefenderThreatState.Critical },
            "reboot pending" => HealthyAv with { ThreatState = DefenderThreatState.RebootPending },
            "full scan pending" => HealthyAv with { ThreatState = DefenderThreatState.FullScanPending },
            "manual steps" => HealthyAv with { ThreatState = DefenderThreatState.ManualStepsPending },
            "offline scan" => HealthyAv with { ThreatState = DefenderThreatState.OfflineScanPending },
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };

        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, av, ActiveSensor, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Unhealthy, state);
        Assert.Equal([issue], health.Issues);
    }

    [Fact]
    public void UnreportedAntivirusValues_AreNotIssues()
    {
        var av = new DefenderAntivirusStatus { MalwareProtectionEnabled = true, RealTimeProtectionEnabled = true };

        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, av, ActiveSensor, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Protected, state);
        Assert.Empty(health.Issues);
    }

    [Theory]
    [InlineData(DefenderSensorHealth.Inactive, "The Defender for Endpoint sensor is inactive (the device stopped reporting).")]
    [InlineData(DefenderSensorHealth.ImpairedCommunication, "The Defender for Endpoint sensor has impaired communication.")]
    [InlineData(DefenderSensorHealth.NoSensorData, "The Defender for Endpoint sensor sends no data.")]
    public void OnboardedSensorThatIsntActive_IsUnhealthy(DefenderSensorHealth sensorHealth, string issue)
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, HealthyAv,
            ActiveSensor with { Health = sensorHealth }, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Unhealthy, state);
        Assert.Equal([issue], health.Issues);
    }

    [Theory]
    [InlineData(DevicePlatform.Windows)]
    [InlineData(DevicePlatform.MacOS)]
    [InlineData(DevicePlatform.Linux)]
    public void EndpointWithoutSensor_IsNotOnboarded(DevicePlatform platform)
    {
        var av = platform == DevicePlatform.Windows ? HealthyAv : null;

        var (state, health) = DefenderHealthEvaluator.Evaluate(platform, av, sensor: null, sensorDataAvailable: true);

        Assert.Equal(DefenderState.NotOnboarded, state);
        Assert.Equal(["Not onboarded to Defender for Endpoint."], health.Issues);
    }

    [Theory]
    [InlineData(DefenderOnboarding.CanBeOnboarded, "Not onboarded to Defender for Endpoint: it was discovered on the network but has no sensor.")]
    [InlineData(DefenderOnboarding.Unsupported, "Not onboarded: Defender for Endpoint doesn't support this OS version.")]
    [InlineData(DefenderOnboarding.InsufficientInfo, "Not onboarded to Defender for Endpoint.")]
    public void SeenButNotOnboarded_SaysWhy(DefenderOnboarding onboarding, string issue)
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, HealthyAv,
            new DefenderSensorStatus { Onboarding = onboarding }, sensorDataAvailable: true);

        Assert.Equal(DefenderState.NotOnboarded, state);
        Assert.Equal([issue], health.Issues);
    }

    [Theory]
    [InlineData(DevicePlatform.iOS)]
    [InlineData(DevicePlatform.Android)]
    [InlineData(DevicePlatform.Other)]
    public void PhonesWithoutSensor_AreNotFlagged(DevicePlatform platform)
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(platform, antivirus: null, sensor: null, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Unknown, state);
        Assert.Empty(health.Issues);
    }

    [Fact]
    public void PhoneWithMobileDefender_IsProtected()
    {
        var (state, _) = DefenderHealthEvaluator.Evaluate(DevicePlatform.iOS, antivirus: null, ActiveSensor, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Protected, state);
    }

    [Fact]
    public void PhoneDiscoveredOnTheNetwork_IsNotOnboarded()
    {
        var (state, _) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Android, antivirus: null,
            new DefenderSensorStatus { Onboarding = DefenderOnboarding.CanBeOnboarded }, sensorDataAvailable: true);

        Assert.Equal(DefenderState.NotOnboarded, state);
    }

    [Fact]
    public void WithoutSensorData_AMissingSensorSaysNothing()
    {
        // No Defender for Endpoint data (no licence, or the query failed): judge the antivirus alone.
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, HealthyAv, sensor: null, sensorDataAvailable: false);

        Assert.Equal(DefenderState.Protected, state);
        Assert.Empty(health.Issues);
        Assert.False(health.SensorDataAvailable);
    }

    [Fact]
    public void NoDataAtAll_IsUnknown()
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.MacOS, antivirus: null, sensor: null, sensorDataAvailable: false);

        Assert.Equal(DefenderState.Unknown, state);
        Assert.Empty(health.Issues);
    }

    [Fact]
    public void AntivirusThatIsntConfirmedOn_IsNotProtected()
    {
        var av = new DefenderAntivirusStatus { RealTimeProtectionEnabled = true }; // malware protection not reported

        var (state, _) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, av, sensor: null, sensorDataAvailable: false);

        Assert.Equal(DefenderState.Unknown, state);
    }

    [Fact]
    public void OnboardedSensorWithUnknownHealthAndNoAntivirus_IsUnknown()
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, antivirus: null,
            ActiveSensor with { Health = DefenderSensorHealth.Unknown }, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Unknown, state);
        Assert.Empty(health.Issues);
    }

    [Fact]
    public void UnhealthyWins_OverNotOnboarded_AndBothIssuesAreListed()
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows, HealthyAv with { RealTimeProtectionEnabled = false },
            sensor: null, sensorDataAvailable: true);

        Assert.Equal(DefenderState.Unhealthy, state);
        Assert.Equal(["Real-time protection is off.", "Not onboarded to Defender for Endpoint."], health.Issues);
    }
}

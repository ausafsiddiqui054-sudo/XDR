using SecurePulse.Core.Models;
using SecurePulse.Engines.ScubaGear;

namespace SecurePulse.Tests.Scans;

/// <summary>
/// Exercises ScubaGearEngine's real out-of-process path with a stand-in for Windows PowerShell that
/// records its arguments and then behaves like a successful, failing, broken or hung ScubaGear run.
/// ScubaGear writes its report into a timestamped folder under -OutPath, so the stand-in does too.
/// </summary>
public sealed class ScubaGearEngineTests : IDisposable
{
    private const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    private readonly string _root = Directory.CreateTempSubdirectory("sp-scuba-test-").FullName;

    private string ArgsFile => Path.Combine(_root, "args.txt");
    private string WorkRoot => Path.Combine(_root, "work");

    private static readonly string Sample = Path.Combine(AppContext.BaseDirectory, "samples", "scubagear-results.sample.json");

    /// <summary>Writes <paramref name="json"/> where ScubaGear would ($out/scuba_<timestamp>/ScubaResults.json).</summary>
    private static string Report(string copyFrom) =>
        $"mkdir -p \"$out/scuba_2026_10_14_08_00_00\" && cp '{copyFrom}' \"$out/scuba_2026_10_14_08_00_00/ScubaResults.json\"";

    private string FakePowerShell(string behaviour)
    {
        var path = Path.Combine(_root, "fake-powershell");
        File.WriteAllText(path, $$"""
            #!/bin/bash
            printf '%s\n' "$@" > '{{ArgsFile}}'
            out=""; prev=""
            for a in "$@"; do [ "$prev" = "-OutPath" ] && out="$a"; prev="$a"; done
            {{behaviour}}
            """.Replace("\r\n", "\n"));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private string Json(string name, string content)
    {
        var path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private ScubaGearEngine Engine(string powershell, Action<ScubaGearOptions>? configure = null)
    {
        var options = new ScubaGearOptions
        {
            PowerShellPath = powershell, AppClientId = "11111111-2222-3333-4444-555555555555", WorkRoot = WorkRoot, Timeout = TimeSpan.FromSeconds(30)
        };
        configure?.Invoke(options);
        return new ScubaGearEngine(options);
    }

    private static Tenant Tenant(TenantConsentState consent = TenantConsentState.ReadOnlyGranted, string? credential = Thumbprint) => new()
    {
        Id = Guid.NewGuid(), EntraTenantId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), DisplayName = "Contoso'; Remove-Item C:\\ -Recurse #",
        PrimaryDomain = "contoso.com", ConsentState = consent, CredentialReference = credential
    };

    [UnixFact]
    public async Task RunsWindowsPowerShellWithExactArgumentsAndParsesResults()
    {
        var tenant = Tenant();

        var result = await Engine(FakePowerShell(Report(Sample))).RunAsync(tenant);

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("ScubaGear", result.Source);
        Assert.Equal(92, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal(tenant.Id, f.TenantId));

        var args = await File.ReadAllLinesAsync(ArgsFile);
        Assert.Equal(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File"], args[..5]);
        Assert.EndsWith("scan.ps1", args[5]);
        Assert.Equal(["-TenantId", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "-ClientId", "11111111-2222-3333-4444-555555555555",
            "-Thumbprint", Thumbprint, "-OutPath"], args[6..13]);
        Assert.Equal(["-Products", "aad"], args[14..]); // nothing pinned, no OPA path
        Assert.DoesNotContain(args, a => a.Contains("Contoso"));
    }

    [UnixFact]
    public async Task PinnedVersionAndOpaPathArePassed()
    {
        var opa = Directory.CreateDirectory(Path.Combine(_root, "opa")).FullName;

        await Engine(FakePowerShell(Report(Sample)), o => { o.ModuleVersion = "1.8.0"; o.OpaPath = opa; }).RunAsync(Tenant());

        Assert.Equal(["-ModuleVersion", "1.8.0", "-OpaPath", opa], (await File.ReadAllLinesAsync(ArgsFile))[^4..]);
    }

    [UnixFact]
    public async Task WorkFolderIsDeletedAfterwards()
    {
        await Engine(FakePowerShell(Report(Sample))).RunAsync(Tenant());
        await Engine(FakePowerShell("exit 1")).RunAsync(Tenant());

        Assert.Empty(Directory.EnumerateFileSystemEntries(WorkRoot));
    }

    [UnixFact]
    public async Task NoReportIsAFailureWithExitCodeAndStderr()
    {
        var result = await Engine(FakePowerShell("echo 'Import-Module : The specified module ScubaGear was not loaded' >&2; exit 1")).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("exit 1", result.Error);
        Assert.Contains("ScubaGear was not loaded", result.Error);
    }

    [UnixFact]
    public async Task AReportWithNothingEvaluatedIsAFailureNotAnEmptyResult()
    {
        // What ScubaGear writes when it can't sign in: every control errors.
        var errors = Json("errors.json", """
            {"Results":{"AAD":[{"GroupName":"G","Controls":[
              {"Control ID":"MS.AAD.1.1v1","Requirement":"R","Result":"Error","Criticality":"Shall","Details":"This test depends on the following command(s) which did not execute successfully: get-mgbetaidentityconditionalaccesspolicy."},
              {"Control ID":"MS.AAD.2.1v1","Requirement":"R","Result":"Error","Criticality":"Shall","Details":"same"}]}]}}
            """);

        var result = await Engine(FakePowerShell(Report(errors))).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("couldn't evaluate any controls (2 not evaluated)", result.Error);
        Assert.Contains("did not execute successfully", result.Error);
        Assert.Empty(result.Findings);
    }

    [UnixFact]
    public async Task InvalidJsonIsAFailedScan()
    {
        var result = await Engine(FakePowerShell(Report(Json("bad.json", "{ not json")))).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("valid JSON", result.Error);
    }

    [UnixFact]
    public async Task HungScanIsKilledAtTheTimeout()
    {
        var started = DateTimeOffset.UtcNow;

        var result = await Engine(FakePowerShell("sleep 60"), o => o.Timeout = TimeSpan.FromSeconds(1)).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Error);
        Assert.True(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(20));
    }

    [Fact]
    public async Task MissingPowerShellIsAFailedScanNotAnException()
    {
        var result = await Engine(Path.Combine(_root, "no-such-powershell")).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("Could not start Windows PowerShell", result.Error);
    }

    public static TheoryData<string, Action<ScubaGearOptions>?, TenantConsentState, string?> RefusedBeforeStarting => new()
    {
        { "consent", null, TenantConsentState.Pending, Thumbprint },
        { "thumbprint", null, TenantConsentState.ReadOnlyGranted, "not-a-thumbprint" },
        { "ScubaGear:AppClientId", o => o.AppClientId = "", TenantConsentState.ReadOnlyGranted, Thumbprint },
        { "ScubaGear:ModuleVersion", o => o.ModuleVersion = "latest; Remove-Item", TenantConsentState.ReadOnlyGranted, Thumbprint },
        { "ScubaGear:OpaPath", o => o.OpaPath = "/definitely/not/here", TenantConsentState.ReadOnlyGranted, Thumbprint }
    };

    [Theory]
    [MemberData(nameof(RefusedBeforeStarting))]
    public async Task InvalidSetupIsRefusedWithoutStartingPowerShell(string expected, Action<ScubaGearOptions>? configure, TenantConsentState consent, string? credential)
    {
        // A PowerShell that doesn't exist: if validation let the run through, the error would be "Could not start".
        var result = await Engine(Path.Combine(_root, "no-such-powershell"), configure).RunAsync(Tenant(consent, credential));

        Assert.False(result.Succeeded);
        Assert.Contains(expected, result.Error, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(WorkRoot) && Directory.EnumerateFileSystemEntries(WorkRoot).Any());
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }
}

using SecurePulse.Core.Models;
using SecurePulse.Engines.Maester;

namespace SecurePulse.Tests.Scans;

/// <summary>Runs on Unix only: the stand-in for pwsh is a bash script.</summary>
public sealed class UnixFactAttribute : FactAttribute
{
    public UnixFactAttribute()
    {
        if (OperatingSystem.IsWindows()) Skip = "Uses a bash stand-in for pwsh.";
    }
}

/// <summary>
/// Exercises MaesterEngine's real out-of-process path with a stand-in "pwsh" that records the
/// arguments it was given and then behaves like a successful, failing, broken or hung Maester run.
/// </summary>
public sealed class MaesterEngineTests : IDisposable
{
    private const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    private readonly string _root = Directory.CreateTempSubdirectory("sp-maester-test-").FullName;

    private string ArgsFile => Path.Combine(_root, "args.txt");
    private string WorkRoot => Path.Combine(_root, "work");
    private string TestsPath => Directory.CreateDirectory(Path.Combine(_root, "maester-tests")).FullName;

    private static readonly string Sample = Path.Combine(AppContext.BaseDirectory, "samples", "maester-results.sample.json");

    private string FakePwsh(string behaviour)
    {
        var path = Path.Combine(_root, "fake-pwsh");
        File.WriteAllText(path, $$"""
            #!/bin/bash
            printf '%s\n' "$@" > '{{ArgsFile}}'
            out=""; prev=""
            for a in "$@"; do [ "$prev" = "-OutputJson" ] && out="$a"; prev="$a"; done
            {{behaviour}}
            """.Replace("\r\n", "\n"));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private MaesterEngine Engine(string pwsh, Action<MaesterOptions>? configure = null)
    {
        var options = new MaesterOptions
        {
            PwshPath = pwsh, AppClientId = "11111111-2222-3333-4444-555555555555", TestsPath = TestsPath, WorkRoot = WorkRoot,
            Timeout = TimeSpan.FromSeconds(30)
        };
        configure?.Invoke(options);
        return new MaesterEngine(options);
    }

    private static Tenant Tenant(TenantConsentState consent = TenantConsentState.ReadOnlyGranted, string? credential = Thumbprint) => new()
    {
        Id = Guid.NewGuid(), EntraTenantId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), DisplayName = "Contoso; rm -rf / $(whoami)",
        PrimaryDomain = "contoso.com", ConsentState = consent, CredentialReference = credential
    };

    [UnixFact]
    public async Task RunsPwshWithExactArgumentsAndParsesResults()
    {
        var tenant = Tenant();

        var result = await Engine(FakePwsh($"cp '{Sample}' \"$out\"")).RunAsync(tenant);

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("Maester", result.Source);
        Assert.Equal(6, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal(tenant.Id, f.TenantId));

        var args = await File.ReadAllLinesAsync(ArgsFile);
        Assert.Equal("-NoProfile", args[0]);
        Assert.Equal("-NonInteractive", args[1]);
        Assert.Equal("-File", args[2]);
        Assert.EndsWith("scan.ps1", args[3]);
        Assert.Equal(["-TenantId", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "-ClientId", "11111111-2222-3333-4444-555555555555",
            "-Thumbprint", Thumbprint, "-TestsPath", TestsPath, "-OutputJson"], args[4..13]);
        Assert.Equal(14, args.Length); // no -ModuleVersion when none is pinned
        // Tenant names never reach the command line.
        Assert.DoesNotContain(args, a => a.Contains("Contoso"));
    }

    [UnixFact]
    public async Task PinnedModuleVersionIsPassed()
    {
        await Engine(FakePwsh($"cp '{Sample}' \"$out\""), o => o.ModuleVersion = "2.3.0").RunAsync(Tenant());

        Assert.Equal(["-ModuleVersion", "2.3.0"], (await File.ReadAllLinesAsync(ArgsFile))[^2..]);
    }

    [UnixFact]
    public async Task WorkFolderIsDeletedAfterwards()
    {
        await Engine(FakePwsh($"cp '{Sample}' \"$out\"")).RunAsync(Tenant());
        await Engine(FakePwsh("exit 1")).RunAsync(Tenant());

        Assert.Empty(Directory.EnumerateFileSystemEntries(WorkRoot));
    }

    [UnixFact]
    public async Task FailureReportsExitCodeAndStderr()
    {
        var result = await Engine(FakePwsh("echo 'Connect-MgGraph: AADSTS700016 application not found' >&2; exit 3")).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("exit 3", result.Error);
        Assert.Contains("AADSTS700016", result.Error);
        Assert.Empty(result.Findings);
    }

    [UnixFact]
    public async Task InvalidJsonIsAFailedScan()
    {
        var result = await Engine(FakePwsh("echo '{ not json' > \"$out\"")).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("valid JSON", result.Error);
    }

    [UnixFact]
    public async Task HungScanIsKilledAtTheTimeout()
    {
        var started = DateTimeOffset.UtcNow;

        var result = await Engine(FakePwsh("sleep 60"), o => o.Timeout = TimeSpan.FromSeconds(1)).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Error);
        Assert.True(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(20));
    }

    [UnixFact]
    public async Task MissingPwshIsAFailedScanNotAnException()
    {
        var result = await Engine(Path.Combine(_root, "no-such-pwsh")).RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("Could not start PowerShell 7", result.Error);
    }

    public static TheoryData<string, Action<MaesterOptions>?, TenantConsentState, string?> RefusedBeforeStarting => new()
    {
        { "consent", null, TenantConsentState.Pending, Thumbprint },
        { "thumbprint", null, TenantConsentState.ReadOnlyGranted, "not-a-thumbprint" },
        { "AppClientId", o => o.AppClientId = "", TenantConsentState.ReadOnlyGranted, Thumbprint },
        { "ModuleVersion", o => o.ModuleVersion = "latest; Remove-Item", TenantConsentState.ReadOnlyGranted, Thumbprint },
        { "tests folder", o => o.TestsPath = "/definitely/not/here", TenantConsentState.ReadOnlyGranted, Thumbprint }
    };

    [Theory]
    [MemberData(nameof(RefusedBeforeStarting))]
    public async Task InvalidSetupIsRefusedWithoutStartingPwsh(string expected, Action<MaesterOptions>? configure, TenantConsentState consent, string? credential)
    {
        // A pwsh that doesn't exist: if validation let the run through, the error would be "Could not start".
        var result = await Engine(Path.Combine(_root, "no-such-pwsh"), configure).RunAsync(Tenant(consent, credential));

        Assert.False(result.Succeeded);
        Assert.Contains(expected, result.Error, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(ArgsFile));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }
}

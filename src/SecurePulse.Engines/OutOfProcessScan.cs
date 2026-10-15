using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines;

/// <summary>How an out-of-process engine run ended.</summary>
internal sealed record ProcessOutcome(int ExitCode, string StandardError, bool TimedOut, string? StartError);

/// <summary>
/// The parts every PowerShell-based engine shares: input validation, a private work folder per
/// run, starting the process with <see cref="ProcessStartInfo.ArgumentList"/>, and killing it at
/// the timeout. Engines add their script, arguments and result parsing.
/// </summary>
internal static partial class OutOfProcessScan
{
    /// <summary>
    /// Checks the tenant and engine settings before anything starts. Returns an error message, or
    /// null with the parsed client ID when the run can go ahead.
    /// </summary>
    public static string? Validate(Tenant tenant, string settingsSection, string appClientId, string moduleVersion, out Guid clientId)
    {
        clientId = Guid.Empty;
        if (tenant.ConsentState is not (TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted))
            return "Tenant has not granted consent.";
        if (!ThumbprintPattern().IsMatch(tenant.CredentialReference ?? string.Empty))
            return "Tenant credential reference is not a valid certificate thumbprint.";
        if (tenant.EntraTenantId == Guid.Empty)
            return "Tenant has no Entra tenant ID.";
        if (!Guid.TryParse(appClientId, out clientId) || clientId == Guid.Empty)
            return $"{settingsSection}:AppClientId is not configured as a valid GUID.";
        if (!string.IsNullOrEmpty(moduleVersion) && !Version.TryParse(moduleVersion, out _))
            return $"{settingsSection}:ModuleVersion is not a valid version number.";
        return null;
    }

    /// <summary>A new folder only this user can read, unique to this run. Delete it with <see cref="TryDeleteDirectory"/>.</summary>
    public static string CreateWorkDirectory(string workRoot, Guid tenantId, DateTimeOffset started)
    {
        var workDir = Path.Combine(workRoot, $"{tenantId:N}-{started:yyyyMMddHHmmss}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workRoot);
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(workDir);
        else
            Directory.CreateDirectory(workDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return workDir;
    }

    /// <summary>Runs <paramref name="executable"/> to completion, or kills it (and its children) at the timeout.</summary>
    public static async Task<ProcessOutcome> RunAsync(string executable, IEnumerable<string> arguments, string workDir,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = workDir
        };
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        Process process;
        try
        {
            process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {executable}.");
        }
        catch (Win32Exception ex)
        {
            return new ProcessOutcome(-1, string.Empty, false, ex.Message);
        }

        using var owned = process;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var stderrTask = process.StandardError.ReadToEndAsync(deadline.Token);
        _ = process.StandardOutput.ReadToEndAsync(deadline.Token); // drain so the process never blocks on a full pipe

        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            return new ProcessOutcome(-1, string.Empty, true, null);
        }

        string stderr;
        try
        {
            stderr = await stderrTask;
        }
        catch (OperationCanceledException)
        {
            stderr = string.Empty;
        }
        return new ProcessOutcome(process.ExitCode, stderr, false, null);
    }

    public static ScanResult Failed(Tenant tenant, string source, DateTimeOffset started, string error) => new()
    {
        TenantId = tenant.Id,
        Source = source,
        StartedAt = started,
        CompletedAt = DateTimeOffset.UtcNow,
        Findings = [],
        Succeeded = false,
        Error = error
    };

    public static string Clip(string s, int max = 500) => s.Length > max ? s[..max] + "…" : s;

    public static void TryDeleteDirectory(string path)
    {
        try { Directory.Delete(path, recursive: true); } catch { /* best effort */ }
    }

    [GeneratedRegex("^[A-Fa-f0-9]{40}$")]
    private static partial Regex ThumbprintPattern();
}

using System.Diagnostics;
using System.Text.RegularExpressions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.Maester;

public sealed class MaesterOptions
{
    /// <summary>Path to PowerShell 7 (pwsh).</summary>
    public string PwshPath { get; set; } = "pwsh";

    /// <summary>Client ID of SecurePulse's multi-tenant Entra app registration.</summary>
    public string AppClientId { get; set; } = string.Empty;

    /// <summary>Folder containing the Maester test files (Install-MaesterTests output).</summary>
    public string TestsPath { get; set; } = "./maester-tests";

    /// <summary>Scratch folder for per-scan output. Each scan gets its own subfolder.</summary>
    public string WorkRoot { get; set; } = Path.Combine(Path.GetTempPath(), "securepulse-scans");

    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(20);
}

/// <summary>
/// Runs Maester out of process with certificate-based app-only auth against one tenant,
/// then parses the JSON output. The certificate must already be installed in the worker's
/// certificate store; the tenant's <see cref="Tenant.CredentialReference"/> holds its thumbprint.
/// </summary>
public sealed partial class MaesterEngine(MaesterOptions options) : IScanEngine
{
    public string Name => "Maester";

    // Parameters are passed through -File with ArgumentList (never string-concatenated),
    // so tenant data can't inject PowerShell. Verify cmdlet parameters against the
    // Maester version you install.
    private const string ScanScript = """
        param(
            [Parameter(Mandatory)][string]$TenantId,
            [Parameter(Mandatory)][string]$ClientId,
            [Parameter(Mandatory)][string]$Thumbprint,
            [Parameter(Mandatory)][string]$TestsPath,
            [Parameter(Mandatory)][string]$OutputJson
        )
        $ErrorActionPreference = 'Stop'
        Import-Module Maester
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -NoWelcome
        try {
            Invoke-Maester -Path $TestsPath -OutputJsonFile $OutputJson -NonInteractive -SkipVersionCheck | Out-Null
        }
        finally {
            Disconnect-MgGraph | Out-Null
        }
        """;

    public async Task<ScanResult> RunAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.UtcNow;

        if (tenant.ConsentState is not (TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted))
            return Fail(tenant, started, "Tenant has not granted consent.");

        var thumbprint = tenant.CredentialReference ?? string.Empty;
        if (!ThumbprintPattern().IsMatch(thumbprint))
            return Fail(tenant, started, "Tenant credential reference is not a valid certificate thumbprint.");

        var workDir = Path.Combine(options.WorkRoot, $"{tenant.Id:N}-{started:yyyyMMddHHmmss}");
        Directory.CreateDirectory(workDir);
        var scriptPath = Path.Combine(workDir, "scan.ps1");
        var outputJson = Path.Combine(workDir, "maester-results.json");
        await File.WriteAllTextAsync(scriptPath, ScanScript, cancellationToken);

        var psi = new ProcessStartInfo(options.PwshPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = workDir
        };
        foreach (var arg in new[]
                 {
                     "-NoProfile", "-NonInteractive", "-File", scriptPath,
                     "-TenantId", tenant.EntraTenantId.ToString(),
                     "-ClientId", options.AppClientId,
                     "-Thumbprint", thumbprint,
                     "-TestsPath", Path.GetFullPath(options.TestsPath),
                     "-OutputJson", outputJson
                 })
        {
            psi.ArgumentList.Add(arg);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);

        try
        {
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start pwsh.");
            var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
            _ = process.StandardOutput.ReadToEndAsync(timeout.Token); // drain to avoid blocking

            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                return Fail(tenant, started, "Maester scan timed out or was cancelled.");
            }

            if (!File.Exists(outputJson))
            {
                var stderr = await stderrTask;
                return Fail(tenant, started, $"Maester produced no results (exit {process.ExitCode}). {Trim(stderr)}");
            }

            var json = await File.ReadAllTextAsync(outputJson, cancellationToken);
            return new ScanResult
            {
                TenantId = tenant.Id,
                Source = Name,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Findings = MaesterResultParser.Parse(json, tenant.Id, started)
            };
        }
        finally
        {
            TryDelete(scriptPath);
        }
    }

    private ScanResult Fail(Tenant tenant, DateTimeOffset started, string error) => new()
    {
        TenantId = tenant.Id,
        Source = Name,
        StartedAt = started,
        CompletedAt = DateTimeOffset.UtcNow,
        Findings = [],
        Succeeded = false,
        Error = error
    };

    private static string Trim(string s) => s.Length > 500 ? s[..500] + "…" : s;

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* best effort */ }
    }

    [GeneratedRegex("^[A-Fa-f0-9]{40}$")]
    private static partial Regex ThumbprintPattern();
}

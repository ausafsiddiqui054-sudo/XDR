using System.Text.Json;
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

    /// <summary>
    /// Exact Maester module version to load (e.g. "2.3.0"). Empty loads the newest installed one;
    /// pin it so a module update can't change scan results without you knowing.
    /// </summary>
    public string ModuleVersion { get; set; } = string.Empty;
}

/// <summary>
/// Runs Maester out of process with certificate-based app-only auth against one tenant,
/// then parses the JSON output. The certificate must already be installed in the worker's
/// certificate store; the tenant's <see cref="Tenant.CredentialReference"/> holds its thumbprint.
/// </summary>
public sealed class MaesterEngine(MaesterOptions options) : IScanEngine
{
    public string Name => ScanEngines.Maester;

    // Parameters are passed through -File with ArgumentList (never string-concatenated),
    // so tenant data can't inject PowerShell. Verify cmdlet parameters against the
    // Maester version you install.
    private const string ScanScript = """
        param(
            [Parameter(Mandatory)][string]$TenantId,
            [Parameter(Mandatory)][string]$ClientId,
            [Parameter(Mandatory)][string]$Thumbprint,
            [Parameter(Mandatory)][string]$TestsPath,
            [Parameter(Mandatory)][string]$OutputJson,
            [string]$ModuleVersion = ''
        )
        $ErrorActionPreference = 'Stop'
        if ($ModuleVersion) { Import-Module Maester -RequiredVersion $ModuleVersion } else { Import-Module Maester }
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -NoWelcome
        try {
            # Parameters verified against Maester 2.3.0. Telemetry off: scans cover client tenants.
            Invoke-Maester -Path $TestsPath -OutputJsonFile $OutputJson -NonInteractive -SkipVersionCheck -DisableTelemetry -NoLogo | Out-Null
        }
        finally {
            Disconnect-MgGraph | Out-Null
        }
        """;

    public async Task<ScanResult> RunAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.UtcNow;

        if (OutOfProcessScan.Validate(tenant, "Maester", options.AppClientId, options.ModuleVersion, out var clientId) is { } invalid)
            return Fail(tenant, started, invalid);
        var testsPath = Path.GetFullPath(options.TestsPath);
        if (!Directory.Exists(testsPath))
            return Fail(tenant, started, $"Maester tests folder not found at {testsPath}. Run Install-MaesterTests there first.");

        // A unique folder per run; deleted afterwards because it holds the tenant's results.
        var workDir = OutOfProcessScan.CreateWorkDirectory(options.WorkRoot, tenant.Id, started);
        try
        {
            var scriptPath = Path.Combine(workDir, "scan.ps1");
            var outputJson = Path.Combine(workDir, "maester-results.json");
            await File.WriteAllTextAsync(scriptPath, ScanScript, cancellationToken);

            List<string> args =
            [
                "-NoProfile", "-NonInteractive", "-File", scriptPath,
                "-TenantId", tenant.EntraTenantId.ToString(),
                "-ClientId", clientId.ToString(),
                "-Thumbprint", tenant.CredentialReference!,
                "-TestsPath", testsPath,
                "-OutputJson", outputJson
            ];
            if (!string.IsNullOrEmpty(options.ModuleVersion))
                args.AddRange(["-ModuleVersion", options.ModuleVersion]);

            var outcome = await OutOfProcessScan.RunAsync(options.PwshPath, args, workDir, options.Timeout, cancellationToken);
            if (outcome.StartError is not null)
                return Fail(tenant, started, $"Could not start PowerShell 7 at '{options.PwshPath}': {outcome.StartError}");
            if (outcome.TimedOut)
                return Fail(tenant, started, "Maester scan timed out or was cancelled.");
            if (!File.Exists(outputJson))
                return Fail(tenant, started, $"Maester produced no results (exit {outcome.ExitCode}). {OutOfProcessScan.Clip(outcome.StandardError)}");

            var json = await File.ReadAllTextAsync(outputJson, cancellationToken);
            IReadOnlyList<Finding> findings;
            try
            {
                findings = MaesterResultParser.Parse(json, tenant.Id, started);
            }
            catch (JsonException ex)
            {
                return Fail(tenant, started, $"Maester results weren't valid JSON: {ex.Message}");
            }

            return new ScanResult
            {
                TenantId = tenant.Id,
                Source = Name,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                Findings = findings
            };
        }
        finally
        {
            OutOfProcessScan.TryDeleteDirectory(workDir);
        }
    }

    private ScanResult Fail(Tenant tenant, DateTimeOffset started, string error) => OutOfProcessScan.Failed(tenant, Name, started, error);
}

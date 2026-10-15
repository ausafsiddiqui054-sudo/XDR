using System.Text.Json;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Engines.ScubaGear;

public sealed class ScubaGearOptions
{
    /// <summary>
    /// Windows PowerShell 5.1. ScubaGear needs it (one of Microsoft's modules it uses is tied to 5.1),
    /// so it runs only on a Windows Worker.
    /// </summary>
    public string PowerShellPath { get; set; } = "powershell.exe";

    /// <summary>Client ID of SecurePulse's multi-tenant Entra app registration.</summary>
    public string AppClientId { get; set; } = string.Empty;

    /// <summary>Scratch folder for per-scan output. Each scan gets its own subfolder.</summary>
    public string WorkRoot { get; set; } = Path.Combine(Path.GetTempPath(), "securepulse-scans");

    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Exact ScubaGear module version to load (e.g. "1.8.0"). Empty loads the newest installed one;
    /// pin it so a module update can't change results (or the output format) without you knowing.
    /// </summary>
    public string ModuleVersion { get; set; } = string.Empty;

    /// <summary>Folder holding OPA (opa_windows_amd64.exe). Empty uses ScubaGear's default (~/.scubagear/Tools).</summary>
    public string OpaPath { get; set; } = string.Empty;
}

/// <summary>
/// Runs CISA's ScubaGear out of process against one tenant's Entra ID configuration with
/// certificate app-only auth, then parses ScubaResults.json. Only the Entra ID (aad) baseline is
/// assessed: ScubaGear's other products need Exchange.ManageAsApp, Sites.FullControl.All or
/// directory roles, which SecurePulse's read-only consent doesn't grant.
/// </summary>
public sealed class ScubaGearEngine(ScubaGearOptions options) : IScanEngine
{
    public string Name => ScanEngines.ScubaGear;

    /// <summary>Products passed to Invoke-SCuBA. See the class remarks before adding any.</summary>
    public const string Products = "aad";

    // Values arrive as script parameters through ArgumentList, never string-concatenated, so
    // tenant data can't inject PowerShell. Parameters verified against ScubaGear 1.8.0.
    // Organization is the tenant ID: for aad ScubaGear only passes it to Connect-MgGraph -TenantId.
    private const string ScanScript = """
        param(
            [Parameter(Mandatory)][string]$TenantId,
            [Parameter(Mandatory)][string]$ClientId,
            [Parameter(Mandatory)][string]$Thumbprint,
            [Parameter(Mandatory)][string]$OutPath,
            [Parameter(Mandatory)][string]$Products,
            [string]$ModuleVersion = '',
            [string]$OpaPath = ''
        )
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        $env:SCUBAGEAR_SKIP_VERSION_CHECK = 'true'
        if ($ModuleVersion) { Import-Module ScubaGear -RequiredVersion $ModuleVersion } else { Import-Module ScubaGear }
        $scuba = @{
            ProductNames = $Products.Split(',')
            AppID = $ClientId
            CertificateThumbprint = $Thumbprint
            Organization = $TenantId
            OutPath = $OutPath
            OutFolderName = 'scuba'
            OutJsonFileName = 'ScubaResults'
            NumberOfUUIDCharactersToTruncate = 36
            Quiet = $true
            SilenceBODWarnings = $true
            DisconnectOnExit = $true
        }
        if ($OpaPath) { $scuba.OPAPath = $OpaPath }
        Invoke-SCuBA @scuba
        """;

    public async Task<ScanResult> RunAsync(Tenant tenant, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.UtcNow;

        if (OutOfProcessScan.Validate(tenant, "ScubaGear", options.AppClientId, options.ModuleVersion, out var clientId) is { } invalid)
            return Fail(tenant, started, invalid);
        string? opaPath = null;
        if (!string.IsNullOrEmpty(options.OpaPath))
        {
            opaPath = Path.GetFullPath(options.OpaPath);
            if (!Directory.Exists(opaPath))
                return Fail(tenant, started, $"ScubaGear:OpaPath folder not found at {opaPath}. Run Install-OPAforSCuBA or fix the setting.");
        }

        // A unique folder per run; deleted afterwards because it holds the tenant's configuration export.
        var workDir = OutOfProcessScan.CreateWorkDirectory(options.WorkRoot, tenant.Id, started);
        try
        {
            var scriptPath = Path.Combine(workDir, "scan.ps1");
            var outPath = Path.Combine(workDir, "out");
            await File.WriteAllTextAsync(scriptPath, ScanScript, cancellationToken);

            List<string> args =
            [
                // RemoteSigned lets this locally written script run where the default policy is Restricted;
                // a policy set by Group Policy still wins.
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", scriptPath,
                "-TenantId", tenant.EntraTenantId.ToString(),
                "-ClientId", clientId.ToString(),
                "-Thumbprint", tenant.CredentialReference!,
                "-OutPath", outPath,
                "-Products", Products
            ];
            if (!string.IsNullOrEmpty(options.ModuleVersion))
                args.AddRange(["-ModuleVersion", options.ModuleVersion]);
            if (opaPath is not null)
                args.AddRange(["-OpaPath", opaPath]);

            var outcome = await OutOfProcessScan.RunAsync(options.PowerShellPath, args, workDir, options.Timeout, cancellationToken);
            if (outcome.StartError is not null)
                return Fail(tenant, started, $"Could not start Windows PowerShell at '{options.PowerShellPath}': {outcome.StartError}");
            if (outcome.TimedOut)
                return Fail(tenant, started, "ScubaGear scan timed out or was cancelled.");

            var resultsFile = Directory.Exists(outPath)
                ? Directory.EnumerateFiles(outPath, "ScubaResults*.json", SearchOption.AllDirectories).OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault()
                : null;
            if (resultsFile is null)
                return Fail(tenant, started, $"ScubaGear produced no results (exit {outcome.ExitCode}). {OutOfProcessScan.Clip(outcome.StandardError)}");

            IReadOnlyList<Finding> findings;
            try
            {
                findings = ScubaGearResultParser.Parse(await File.ReadAllTextAsync(resultsFile, cancellationToken), tenant.Id, started);
            }
            catch (JsonException ex)
            {
                return Fail(tenant, started, $"ScubaGear results weren't valid JSON: {ex.Message}");
            }

            // ScubaGear still writes a report when it can't read the tenant (e.g. sign-in failed); every
            // control is then an error. Saving that would wipe the tenant's last good results.
            if (!findings.Any(f => f.Status is FindingStatus.Passed or FindingStatus.Failed))
            {
                var reason = findings.Select(f => f.Evidence).FirstOrDefault(e => !string.IsNullOrWhiteSpace(e))
                             ?? OutOfProcessScan.Clip(outcome.StandardError);
                return Fail(tenant, started, $"ScubaGear couldn't evaluate any controls ({findings.Count} not evaluated). {reason}".Trim());
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

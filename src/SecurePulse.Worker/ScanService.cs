using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

/// <summary>
/// Scheduled engine scans. Due tenants are queued in scan_runs; queued runs (scheduled or requested
/// from the portal) are claimed and executed here, so restarts don't rescan everyone and several
/// Workers can share the queue.
/// </summary>
public sealed class ScanService(
    ITenantRepository tenants,
    IScanRunRepository runs,
    IFindingRepository findings,
    IEnumerable<IScanEngine> engines,
    IGraphTokenProvider tokens,
    IOptions<ScanOptions> options,
    TimeProvider time,
    ILogger<ScanService> logger,
    FindingPlaybookRunner? findingPlaybooks = null)
{
    private readonly IReadOnlyDictionary<string, IScanEngine> _engines = engines.ToDictionary(e => e.Name, StringComparer.Ordinal);

    public IReadOnlyCollection<string> EngineNames => _engines.Keys.ToList();

    /// <summary>Queues a scheduled run for every onboarded tenant and engine that is due. Returns how many were queued.</summary>
    public async Task<int> EnqueueDueAsync(CancellationToken ct = default)
    {
        var o = options.Value;
        var now = time.GetUtcNow();
        var latest = (await runs.GetLatestAsync(ct)).ToDictionary(r => (r.TenantId, r.Engine));
        var queued = 0;

        foreach (var tenant in (await tenants.GetAllAsync(ct)).Where(IsOnboarded))
        {
            foreach (var engine in _engines.Keys.Where(e => ScanEngines.AppliesTo(e, tenant)))
            {
                latest.TryGetValue((tenant.Id, engine), out var last);
                var due = last switch
                {
                    null => true,
                    { IsActive: true } => false,
                    { Status: ScanRunStatus.Failed } => now - (last.CompletedAt ?? last.QueuedAt) >= o.RetryFailedAfter,
                    _ => now - (last.CompletedAt ?? last.QueuedAt) >= o.Interval
                };
                if (!due) continue;

                var (_, created) = await runs.EnqueueAsync(tenant.Id, engine, ScanTrigger.Scheduled, null, now, ct);
                if (created) queued++;
            }
        }

        if (queued > 0) logger.LogInformation("Queued {Count} scheduled scans", queued);
        return queued;
    }

    /// <summary>Claims and runs the next queued scan. Returns false when the queue is empty.</summary>
    public async Task<bool> RunNextAsync(CancellationToken ct = default)
    {
        var run = await runs.ClaimNextAsync(EngineNames, time.GetUtcNow(), ct);
        if (run is null) return false;

        string? error;
        int? count = null;
        try
        {
            (count, error) = await ExecuteAsync(run, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            error = "The Worker stopped during the scan.";
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Scan {RunId} ({Engine}) for tenant {TenantId} threw", run.Id, run.Engine, run.TenantId);
            error = $"Unexpected error: {ex.Message}";
        }

        // Record the outcome even if we're shutting down, so the run doesn't sit in Running.
        await runs.CompleteAsync(run.Id, error is null, count, error, time.GetUtcNow(), CancellationToken.None);
        if (error is null)
            logger.LogInformation("Scan {RunId} ({Engine}) for tenant {TenantId} finished with {Count} findings", run.Id, run.Engine, run.TenantId, count);
        else
            logger.LogWarning("Scan {RunId} ({Engine}) for tenant {TenantId} failed: {Error}", run.Id, run.Engine, run.TenantId, error);
        return true;
    }

    /// <summary>Runs queued scans with up to MaxParallelScans at a time until the queue is empty.</summary>
    public Task DrainAsync(CancellationToken ct = default) =>
        Parallel.ForEachAsync(Enumerable.Range(0, Math.Max(1, options.Value.MaxParallelScans)),
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Value.MaxParallelScans), CancellationToken = ct },
            async (_, token) =>
            {
                while (!token.IsCancellationRequested && await RunNextAsync(token)) { }
            });

    public Task<int> FailStaleAsync(CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        return runs.FailStaleAsync(now - options.Value.StaleAfter, "The scan didn't finish (its Worker stopped or timed out); it will be retried.", now, ct);
    }

    private async Task<(int? Count, string? Error)> ExecuteAsync(ScanRun run, CancellationToken ct)
    {
        if (!_engines.TryGetValue(run.Engine, out var engine))
            return (null, $"No '{run.Engine}' engine is configured in this Worker.");
        if (await tenants.GetAsync(run.TenantId, ct) is not { } tenant || !IsOnboarded(tenant))
            return (null, "The tenant isn't onboarded (consent or certificate missing).");

        if (!ScanEngines.AppliesTo(engine.Name, tenant))
            return (null, $"{tenant.DisplayName} isn't set up for {engine.Name} " +
                          (engine.Name == ScanEngines.GoPhish ? "(GoPhish is turned off on the Tenants page)." : "(no Wazuh agent group on the Tenants page)."));

        // Graph engines: check the token's roles first. Wazuh and GoPhish check their own API user instead.
        if (options.Value.CheckPermissions && ScanEngines.UsesGraph(engine.Name) && await CheckPermissionsAsync(tenant, engine.Name, ct) is { } permissionError)
            return (null, permissionError);

        var result = await engine.RunAsync(tenant, ct);
        if (!result.Succeeded)
            return (null, result.Error ?? "The scan failed without an error message.");

        await findings.SaveScanAsync(result, ct);

        // Finding playbooks look at the stored findings only after a successful scan replaced them.
        if (findingPlaybooks is not null)
        {
            try
            {
                await findingPlaybooks.RunForTenantAsync(tenant, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                logger.LogError(ex, "Finding playbooks for {Tenant} failed; the scan itself succeeded", tenant.DisplayName);
            }
        }
        return (result.Findings.Count, null);
    }

    /// <summary>
    /// A token carries the permissions actually granted. Checking first turns "re-consent needed"
    /// into one clear error instead of a long scan full of 403s, and refuses to scan with a grant
    /// that isn't read-only (CLAUDE.md rule 5). Only the engine's own permissions must be present,
    /// so a tenant that hasn't re-consented for a new engine keeps its other scans.
    /// </summary>
    private async Task<string?> CheckPermissionsAsync(Tenant tenant, string engine, CancellationToken ct)
    {
        string token;
        try
        {
            token = await tokens.GetTokenAsync(tenant, ct);
        }
        catch (GraphAuthException ex)
        {
            return ex.Message;
        }

        AccessTokenClaims claims;
        try
        {
            claims = AccessTokenClaims.Parse(token);
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
        {
            return $"Couldn't read the access token: {ex.Message}";
        }
        if (claims.TenantId != tenant.EntraTenantId)
            return $"The token was issued for tenant {claims.TenantId}, not {tenant.EntraTenantId}.";

        var notReadOnly = AssessmentPermissions.NotReadOnly(claims.Roles);
        if (notReadOnly.Count > 0)
            return $"Not scanning: the app has permissions that aren't read-only ({string.Join(", ", notReadOnly)}). Remove them from the app registration.";

        var missing = AssessmentPermissions.MissingFrom(claims.Roles, AssessmentPermissions.RequiredFor(engine));
        return missing.Count == 0
            ? null
            : $"Re-consent needed: the tenant hasn't granted {string.Join(", ", missing)}. Use Re-consent on the Tenants page.";
    }

    private static bool IsOnboarded(Tenant t) =>
        t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted
        && !string.IsNullOrWhiteSpace(t.CredentialReference);
}

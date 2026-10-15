using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Worker.Siem;

public sealed record AuditExportResult(int Sent, bool Busy = false, string? Error = null);

/// <summary>
/// Sends audit events to Sentinel in the order the database stored them. The checkpoint moves only
/// after Sentinel accepted a call, so a failure or a crash re-sends (at least once, never lost); each
/// record carries its EventId for de-duplication. Not audited itself: every export would add an audit
/// event that then needs exporting.
/// </summary>
public sealed class AuditExportService(IAuditExportStore store, ISentinelAuditSink sink, SentinelOptions options, ILogger<AuditExportService> logger)
{
    public async Task<AuditExportResult> RunOnceAsync(CancellationToken ct = default)
    {
        var sent = 0;
        for (var call = 0; call < options.MaxCallsPerRun && !ct.IsCancellationRequested; call++)
        {
            await using var lease = await store.TryLeaseAsync(AuditExportDestinations.Sentinel, options.ExportLag, options.MaxEventsPerCall, ct);
            if (lease is null)
            {
                logger.LogDebug("Audit export: another Worker is exporting");
                return new AuditExportResult(sent, Busy: true);
            }
            if (lease.Events.Count == 0)
            {
                await lease.CommitAsync(0, ct);
                break;
            }

            var (records, count) = SentinelAuditSink.Take(lease.Events);
            try
            {
                await sink.SendAsync(records, ct);
            }
            catch (AuditExportException ex)
            {
                logger.LogError("Audit export to Sentinel failed ({Sent} sent this run): {Error}", sent, ex.Message);
                await lease.DisposeAsync(); // release the checkpoint unmoved before recording the failure
                await store.RecordFailureAsync(AuditExportDestinations.Sentinel, ex.Message, CancellationToken.None);
                return new AuditExportResult(sent, Error: ex.Message);
            }

            // Sentinel has these events. If this commit fails they are sent again next time: duplicates, not gaps.
            await lease.CommitAsync(count, ct);
            sent += count;
            if (lease.Events.Count < options.MaxEventsPerCall && count == lease.Events.Count) break; // caught up
        }

        if (sent > 0) logger.LogInformation("Audit export: sent {Sent} events to Sentinel", sent);
        return new AuditExportResult(sent);
    }
}

/// <summary>Runs <see cref="AuditExportService"/> every <see cref="SentinelOptions.Interval"/>.</summary>
public sealed class AuditExportWorker(AuditExportService service, SentinelOptions options, ILogger<AuditExportWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Audit export to Sentinel: {Uri}, every {Interval}", options.IngestionUri(), options.Interval);
        using var timer = new PeriodicTimer(options.Interval);
        do
        {
            try
            {
                await service.RunOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                // e.g. database unreachable; the checkpoint hasn't moved, so nothing is lost.
                logger.LogError(ex, "Audit export pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

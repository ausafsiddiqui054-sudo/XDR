using Microsoft.Extensions.Options;

namespace SecurePulse.Worker;

/// <summary>
/// Every <see cref="ScanOptions.PollInterval"/>: fail stuck runs, queue due tenants, then run the
/// queue (scheduled and portal-requested runs) until it's empty.
/// </summary>
public sealed class ScanWorker(ScanService scans, IOptions<ScanOptions> options, ILogger<ScanWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        if (!o.Enabled)
        {
            logger.LogInformation("Scheduled scans are disabled (Scans:Enabled = false)");
            return;
        }

        logger.LogInformation("Scheduled scans with {Engines} every {Interval}, up to {Parallel} at a time",
            string.Join(", ", scans.EngineNames), o.Interval, o.MaxParallelScans);

        using var timer = new PeriodicTimer(o.PollInterval);
        do
        {
            try
            {
                await scans.FailStaleAsync(stoppingToken);
                await scans.EnqueueDueAsync(stoppingToken);
                await scans.DrainAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                // e.g. database unreachable: keep the loop alive and try again next tick.
                logger.LogError(ex, "Scan pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

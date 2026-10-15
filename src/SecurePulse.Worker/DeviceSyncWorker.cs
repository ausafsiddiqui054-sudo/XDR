using Microsoft.Extensions.Options;

namespace SecurePulse.Worker;

/// <summary>Runs <see cref="DeviceSyncService"/> on startup and then every <see cref="DeviceSyncOptions.Interval"/>.</summary>
public sealed class DeviceSyncWorker(DeviceSyncService sync, IOptions<DeviceSyncOptions> options, ILogger<DeviceSyncWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        if (!o.Enabled)
        {
            logger.LogInformation("Device sync is disabled (DeviceSync:Enabled = false)");
            return;
        }

        logger.LogInformation("Device sync every {Interval}", o.Interval);
        using var timer = new PeriodicTimer(o.Interval);

        if (o.RunOnStartup)
            await RunPassAsync(stoppingToken);

        while (await timer.WaitForNextTickAsync(stoppingToken))
            await RunPassAsync(stoppingToken);
    }

    private async Task RunPassAsync(CancellationToken ct)
    {
        try
        {
            await sync.SyncAllAsync(ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // e.g. database unreachable. Keep the loop alive and try again next interval.
            logger.LogError(ex, "Device sync pass failed");
        }
    }
}

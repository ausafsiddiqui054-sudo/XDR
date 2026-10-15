using System.Globalization;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Worker;

/// <summary>The <c>AuditRetention</c> section. Nothing is deleted until <see cref="RetainFor"/> is set.</summary>
public sealed class AuditRetentionOptions
{
    /// <summary>Keep audit events this long; older ones are deleted. Null keeps them forever (the default).</summary>
    public TimeSpan? RetainFor { get; set; }

    /// <summary>How often the Worker checks for events past the retention period.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Rows deleted per transaction.</summary>
    public int BatchSize { get; set; } = 5000;

    public bool Enabled => RetainFor is not null;
}

public sealed record AuditRetentionResult(DateTimeOffset Cutoff, long Deleted, bool Skipped = false, string? Error = null);

/// <summary>
/// Deletes audit events older than <see cref="AuditRetentionOptions.RetainFor"/>. Deleting the
/// security record is itself audited and fail-closed: "purge started" (with the cutoff and the
/// count) is written first, and nothing is deleted if that write fails. The result is recorded after.
/// </summary>
public sealed class AuditRetentionService(
    IAuditPurger purger,
    IAuditLog audit,
    IOptions<AuditRetentionOptions> options,
    TimeProvider time,
    ILogger<AuditRetentionService> logger)
{
    private const string WorkerActor = "SecurePulse Worker";

    public async Task<AuditRetentionResult?> RunOnceAsync(CancellationToken ct = default)
    {
        var o = options.Value;
        if (o.RetainFor is not { } retainFor) return null;
        if (AuditRetention.Problem(retainFor) is { } problem)
            throw new InvalidOperationException($"AuditRetention:RetainFor {problem}");

        var cutoff = time.GetUtcNow() - retainFor;
        var due = await purger.CountOlderThanAsync(cutoff, ct);
        if (due == 0)
        {
            logger.LogDebug("Audit retention: nothing older than {Cutoff}", cutoff);
            return new AuditRetentionResult(cutoff, 0);
        }

        var details = new Dictionary<string, string>
        {
            ["cutoff"] = cutoff.ToString("O", CultureInfo.InvariantCulture),
            ["retainForDays"] = retainFor.TotalDays.ToString("0.##", CultureInfo.InvariantCulture),
            ["due"] = due.ToString(CultureInfo.InvariantCulture)
        };

        try
        {
            await audit.RecordAsync(Event(AuditActions.AuditPurgeStarted, AuditOutcome.Success,
                $"Removing {due:N0} audit events older than {cutoff:yyyy-MM-dd} (kept for {retainFor.TotalDays:0} days)", details), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed before purging audit events older than {Cutoff}; nothing deleted", cutoff);
            return new AuditRetentionResult(cutoff, 0, Error: "The audit log couldn't be written, so nothing was deleted.");
        }

        long deleted;
        try
        {
            if (await purger.PurgeOlderThanAsync(cutoff, o.BatchSize, ct) is not { } count)
            {
                logger.LogInformation("Audit retention: another Worker is purging; skipped");
                await TryAuditAsync(AuditActions.AuditPurged, AuditOutcome.Failure,
                    "Skipped: another Worker was already removing old audit events", details, ct);
                return new AuditRetentionResult(cutoff, 0, Skipped: true);
            }
            deleted = count;
        }
        catch (AuditPurgeException ex)
        {
            logger.LogError(ex, "Audit retention failed after deleting {Deleted} events", ex.Deleted);
            details["deleted"] = ex.Deleted.ToString(CultureInfo.InvariantCulture);
            await TryAuditAsync(AuditActions.AuditPurged, AuditOutcome.Failure,
                $"Removed {ex.Deleted:N0} of {due:N0} audit events older than {cutoff:yyyy-MM-dd}, then failed: {ex.InnerException?.Message}", details,
                CancellationToken.None);
            return new AuditRetentionResult(cutoff, ex.Deleted, Error: ex.InnerException?.Message);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Failed before deleting anything, e.g. the maintenance login can't connect or isn't a member of the purge role.
            logger.LogError(ex, "Audit retention failed before deleting anything");
            details["deleted"] = "0";
            await TryAuditAsync(AuditActions.AuditPurged, AuditOutcome.Failure,
                $"Couldn't remove audit events older than {cutoff:yyyy-MM-dd}: {ex.Message}", details, ct);
            return new AuditRetentionResult(cutoff, 0, Error: ex.Message);
        }

        details["deleted"] = deleted.ToString(CultureInfo.InvariantCulture);
        logger.LogInformation("Audit retention removed {Deleted} events older than {Cutoff}", deleted, cutoff);
        await TryAuditAsync(AuditActions.AuditPurged, AuditOutcome.Success,
            $"Removed {deleted:N0} audit events older than {cutoff:yyyy-MM-dd}", details, ct);
        return new AuditRetentionResult(cutoff, deleted);
    }

    /// <summary>Outcome entries record what already happened: a failed write is logged, not fatal.</summary>
    private async Task TryAuditAsync(string action, AuditOutcome outcome, string summary, Dictionary<string, string> details, CancellationToken ct)
    {
        try
        {
            await audit.RecordAsync(Event(action, outcome, summary, details), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed for {AuditAction} ({Outcome}): {Summary}", action, outcome, summary);
        }
    }

    private AuditEvent Event(string action, AuditOutcome outcome, string summary, Dictionary<string, string> details) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow(),
        Action = action,
        Outcome = outcome,
        ActorName = WorkerActor,
        TargetType = "AuditLog",
        Summary = summary,
        Details = new Dictionary<string, string>(details)
    };
}

/// <summary>Runs <see cref="AuditRetentionService"/> at startup and then every <see cref="AuditRetentionOptions.Interval"/>.</summary>
public sealed class AuditRetentionWorker(AuditRetentionService service, IOptions<AuditRetentionOptions> options, ILogger<AuditRetentionWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        logger.LogInformation("Audit retention: keeping events for {Days} days, checking every {Interval}", o.RetainFor!.Value.TotalDays, o.Interval);

        using var timer = new PeriodicTimer(o.Interval);
        do
        {
            try
            {
                await service.RunOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Audit retention pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

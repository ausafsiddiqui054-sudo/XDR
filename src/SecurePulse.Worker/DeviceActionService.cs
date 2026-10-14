using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

public sealed class DeviceActionOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>How often the Worker looks for approved actions.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>An action still Sending after this long is failed as "outcome unknown" (its Worker stopped mid-call).</summary>
    public TimeSpan StuckSendingAfter { get; set; } = TimeSpan.FromMinutes(10);
}

/// <summary>
/// Sends approved remote actions to Intune through the separate remediation app. Before each send
/// it re-checks everything the portal checked (remediation access, the approval policy, the
/// app's granted permissions), then writes the audit entry and only sends if that write
/// succeeded (fail-closed). A write is never retried: a failure needs a new request and approval.
/// </summary>
public sealed class DeviceActionService(
    IDeviceActionRepository actions,
    ITenantRepository tenants,
    IRemediationTokenProvider tokens,
    IDeviceActionSender sender,
    IAuditLog audit,
    IOptions<DeviceActionOptions> options,
    TimeProvider time,
    ILogger<DeviceActionService> logger)
{
    private const string WorkerActor = "SecurePulse Worker";

    /// <summary>Expires stale requests, then sends every approved action. Returns how many were processed.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        foreach (var a in await actions.ExpireAsync(now, DeviceActionPolicy.SendWindow, now - options.Value.StuckSendingAfter, ct))
        {
            var stuck = a.Status == DeviceActionStatus.Failed;
            await TryAuditAsync(stuck ? AuditActions.DeviceActionResult : AuditActions.DeviceActionExpired, AuditOutcome.Failure,
                $"{a.Action} of {a.DeviceName}: {a.Error}", a, ct);
        }

        var processed = 0;
        while (!ct.IsCancellationRequested && await actions.ClaimNextApprovedAsync(time.GetUtcNow(), ct) is { } claimed)
        {
            processed++;
            await ProcessAsync(claimed, ct);
        }
        return processed;
    }

    private async Task ProcessAsync(DeviceActionRequest a, CancellationToken ct)
    {
        // 1. Re-check what made the request sendable; anything off means it isn't sent.
        if (await RefusalAsync(a, ct) is { } refusal)
        {
            await FinishAsync(a, new DeviceActionSendResult(false, $"Not sent: {refusal}"), ct);
            return;
        }
        var tenant = (await tenants.GetAsync(a.TenantId, ct))!;

        // 2. A fresh token for the remediation app, carrying exactly the permission it needs.
        string token;
        try
        {
            token = await tokens.GetTokenAsync(tenant.EntraTenantId, tenant.RemediationCredentialReference!, ct);
        }
        catch (GraphAuthException ex)
        {
            await FinishAsync(a, new DeviceActionSendResult(false, $"Not sent: {ex.Message}"), ct);
            return;
        }
        if (TokenProblem(token, tenant) is { } problem)
        {
            await FinishAsync(a, new DeviceActionSendResult(false, $"Not sent: {problem}"), ct);
            return;
        }

        // 3. Fail-closed: the audit entry is written before anything reaches Intune.
        try
        {
            await audit.RecordAsync(Event(AuditActions.DeviceActionSending, AuditOutcome.Success,
                $"Sending {a.Action} to {a.DeviceName} (approved by {a.DecidedByName})", a), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed before sending {Action} {ActionId}; not sending", a.Action, a.Id);
            await actions.CompleteAsync(a.Id, false, "Not sent: the audit log couldn't be written, and actions are never sent unaudited.",
                time.GetUtcNow(), CancellationToken.None);
            return;
        }

        // 4. Send once. Cancellation from here on would leave the outcome unknown, so the call isn't cancelled by shutdown.
        var result = await sender.SendAsync(tenant.EntraTenantId, a.DeviceId, a.Action, token, CancellationToken.None);
        await FinishAsync(a, result, ct);
    }

    /// <summary>Why the claimed action mustn't be sent, or null.</summary>
    private async Task<string?> RefusalAsync(DeviceActionRequest a, CancellationToken ct)
    {
        if (await tenants.GetAsync(a.TenantId, ct) is not { } tenant)
            return "the tenant no longer exists.";
        if (!tenant.CanRemediate)
            return "remediation access for this tenant was turned off.";
        if (a.DecidedByUserId is null || a.DecidedAt is null || a.DecidedByRole is null)
            return "it has no recorded approval.";
        if (DeviceActionPolicy.WhyCannotApprove(a, a.DecidedByUserId, a.DecidedByRole) is { } policy)
            return $"the approval doesn't meet the policy ({policy})";
        if (!Guid.TryParse(a.DeviceId, out _))
            return "the device ID isn't a valid Intune managed device ID.";
        return null;
    }

    private static string? TokenProblem(string token, Tenant tenant)
    {
        AccessTokenClaims claims;
        try
        {
            claims = AccessTokenClaims.Parse(token);
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
        {
            return $"couldn't read the remediation token ({ex.Message}).";
        }
        if (claims.TenantId != tenant.EntraTenantId)
            return $"the token was issued for tenant {claims.TenantId}, not {tenant.EntraTenantId}.";
        if (RemediationPermissions.Unexpected(claims.Roles) is { Count: > 0 } extra)
            return $"the remediation app holds permissions it shouldn't ({string.Join(", ", extra)}). Remove them and have the tenant consent again.";
        if (RemediationPermissions.MissingFrom(claims.Roles) is { Count: > 0 } missing)
            return $"the tenant hasn't granted {string.Join(", ", missing)} to the remediation app any more.";
        return null;
    }

    private async Task FinishAsync(DeviceActionRequest a, DeviceActionSendResult result, CancellationToken ct)
    {
        await actions.CompleteAsync(a.Id, result.Succeeded, result.Error, time.GetUtcNow(), CancellationToken.None);
        if (result.Succeeded)
            logger.LogInformation("{Action} {ActionId} for device {DeviceId} accepted by Intune", a.Action, a.Id, a.DeviceId);
        else
            logger.LogWarning("{Action} {ActionId} for device {DeviceId} failed: {Error}", a.Action, a.Id, a.DeviceId, result.Error);

        await TryAuditAsync(AuditActions.DeviceActionResult, result.Succeeded ? AuditOutcome.Success : AuditOutcome.Failure,
            result.Succeeded ? $"Intune accepted {a.Action} for {a.DeviceName}; it runs when the device next checks in"
                : $"{a.Action} of {a.DeviceName} failed: {result.Error}", a, ct);
    }

    /// <summary>Outcome entries record what already happened: a failed write is logged, not fatal.</summary>
    private async Task TryAuditAsync(string action, AuditOutcome outcome, string summary, DeviceActionRequest a, CancellationToken ct)
    {
        try
        {
            await audit.RecordAsync(Event(action, outcome, summary, a), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed for {AuditAction} ({Outcome}): {Summary}", action, outcome, summary);
        }
    }

    private AuditEvent Event(string action, AuditOutcome outcome, string summary, DeviceActionRequest a) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow(),
        Action = action,
        Outcome = outcome,
        ActorName = WorkerActor,
        TenantId = a.TenantId,
        TargetType = "DeviceAction",
        TargetId = a.Id.ToString(),
        Summary = summary.Length > 1000 ? summary[..1000] + "…" : summary,
        Details = new Dictionary<string, string>
        {
            ["action"] = a.Action.ToString(),
            ["deviceId"] = a.DeviceId,
            ["deviceName"] = a.DeviceName,
            ["requestedBy"] = a.RequestedByName,
            ["approvedBy"] = a.DecidedByName ?? ""
        }
    };
}

/// <summary>Every <see cref="DeviceActionOptions.PollInterval"/>: expire stale requests and send approved ones.</summary>
public sealed class DeviceActionWorker(DeviceActionService service, IOptions<DeviceActionOptions> options, ILogger<DeviceActionWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Device actions are disabled (DeviceActions:Enabled = false)");
            return;
        }

        using var timer = new PeriodicTimer(options.Value.PollInterval);
        do
        {
            try
            {
                await service.RunOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Device action pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

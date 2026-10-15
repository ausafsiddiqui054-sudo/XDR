using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Worker;

public sealed class PlaybookOptions
{
    /// <summary>Check playbooks after each successful device sync. Off: playbooks propose nothing.</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// After a tenant's devices are synced, matches them against the enabled playbooks and adds a pending
/// device action for each match. It never approves or sends anything: every proposal waits for a second
/// person's approval in the Device actions queue, and the send path re-checks everything as for manual requests.
/// </summary>
public sealed class PlaybookRunner(
    IPlaybookRepository playbooks,
    IDeviceRepository devices,
    IDeviceActionRepository actions,
    IAuditLog audit,
    TimeProvider time,
    ILogger<PlaybookRunner> logger)
{
    /// <summary>Returns how many actions were proposed for <paramref name="tenant"/>.</summary>
    public async Task<int> RunForTenantAsync(Tenant tenant, CancellationToken ct = default)
    {
        if (!tenant.CanRemediate) return 0;
        var applicable = (await playbooks.GetAllAsync(ct))
            .Where(p => p.Enabled && (p.TenantId is null || p.TenantId == tenant.Id))
            .ToList();
        if (applicable.Count == 0) return 0;

        var inventory = await devices.GetForTenantAsync(tenant.Id, ct);
        var proposed = 0;
        foreach (var playbook in applicable)
        {
            var now = time.GetUtcNow();
            if (PlaybookRules.Problem(playbook) is { } problem)
            {
                logger.LogWarning("Playbook {Playbook} ({PlaybookId}) skipped: {Problem}", playbook.Name, playbook.Id, problem);
                continue;
            }

            var recent = await actions.GetPlaybookDevicesSinceAsync(playbook.Id, tenant.Id, now - playbook.Cooldown, ct);
            foreach (var proposal in PlaybookEvaluator.Evaluate(playbook, tenant, inventory, recent, now))
                if (await ProposeAsync(playbook, tenant, proposal, now, ct)) proposed++;

            await playbooks.RecordRunAsync(playbook.Id, now, ct);
        }

        if (proposed > 0)
            logger.LogInformation("Playbooks proposed {Count} device actions for {Tenant}; they wait for approval", proposed, tenant.DisplayName);
        return proposed;
    }

    private async Task<bool> ProposeAsync(RemediationPlaybook playbook, Tenant tenant, PlaybookProposal proposal, DateTimeOffset now, CancellationToken ct)
    {
        var (request, created) = await actions.AddAsync(new DeviceActionRequest
        {
            Id = Guid.NewGuid(),
            TenantId = tenant.Id,
            DeviceId = proposal.Device.Id,
            DeviceName = proposal.Device.DeviceName,
            Action = playbook.Action,
            Reason = proposal.Reason,
            Status = DeviceActionStatus.PendingApproval,
            RequestedAt = now,
            // In the name of whoever last saved the playbook, so they can't approve its proposals (four eyes).
            RequestedByUserId = playbook.UpdatedByUserId,
            RequestedByName = Clip($"{playbook.UpdatedByName} (playbook \"{playbook.Name.Trim()}\")", 512),
            ExpiresAt = now + DeviceActionPolicy.ApprovalWindow,
            PlaybookId = playbook.Id
        }, ct);
        if (!created) return false; // the device already has an open action; leave it alone

        try
        {
            await audit.RecordAsync(new AuditEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = now,
                Action = AuditActions.DeviceActionRequested,
                Outcome = AuditOutcome.Success,
                ActorName = $"Playbook \"{playbook.Name.Trim()}\"",
                TenantId = tenant.Id,
                TargetType = "DeviceAction",
                TargetId = request.Id.ToString(),
                Summary = Clip($"Proposed {request.Action} of {request.DeviceName}: {request.Reason}", 1000),
                Details = new Dictionary<string, string>
                {
                    ["action"] = request.Action.ToString(),
                    ["deviceId"] = request.DeviceId,
                    ["deviceName"] = request.DeviceName,
                    ["reason"] = request.Reason,
                    ["requestedBy"] = request.RequestedByName,
                    ["playbookId"] = playbook.Id.ToString()
                }
            }, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // A proposal changes nothing on the device; the approval and the send are the fail-closed steps.
            logger.LogCritical(ex, "Audit write failed for playbook proposal {ActionId} ({Action} of {Device})", request.Id, request.Action, request.DeviceName);
        }
        return true;
    }

    private static string Clip(string s, int max) => s.Length > max ? s[..(max - 1)] + "…" : s;
}

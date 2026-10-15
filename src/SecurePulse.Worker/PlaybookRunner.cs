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
/// device action for each match. Proposals wait for a second person's approval in the Device actions queue,
/// unless another Owner pre-approved the playbook (<see cref="PlaybookPreApproval"/>): then they're approved
/// here, within the playbook's daily limit, with the audit entry written first. It never sends anything; the
/// send path re-checks everything, the pre-approval included.
/// </summary>
public sealed class PlaybookRunner(
    IPlaybookRepository playbooks,
    IDeviceRepository devices,
    IDeviceActionRepository actions,
    IAuditLog audit,
    IPortalUserRepository users,
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
            var created = new List<DeviceActionRequest>();
            foreach (var proposal in PlaybookEvaluator.Evaluate(playbook, tenant, inventory, recent, now))
                if (await ProposeAsync(playbook, tenant, proposal, now, ct) is { } request) created.Add(request);
            proposed += created.Count;

            if (created.Count > 0 && await IsPreApprovedAsync(playbook, now, ct))
                await AutoApproveAsync(playbook, tenant, created, now, ct);

            await playbooks.RecordRunAsync(playbook.Id, now, ct);
        }

        if (proposed > 0)
            logger.LogInformation("Playbooks proposed {Count} device actions for {Tenant}", proposed, tenant.DisplayName);
        return proposed;
    }

    /// <summary>The pre-approval is current and the Owner who gave it is still an Owner.</summary>
    private async Task<bool> IsPreApprovedAsync(RemediationPlaybook playbook, DateTimeOffset now, CancellationToken ct)
    {
        if (playbook.PreApprovedByUserId is not { } granter) return false;
        var stillOwner = (await users.GetAsync(granter, ct))?.Role == PortalRole.Owner;
        return PlaybookPreApproval.IsActive(playbook, now, stillOwner);
    }

    private async Task AutoApproveAsync(RemediationPlaybook playbook, Tenant tenant, List<DeviceActionRequest> created, DateTimeOffset now,
        CancellationToken ct)
    {
        var used = await actions.CountAutoApprovedSinceAsync(playbook.Id, tenant.Id, now - TimeSpan.FromDays(1), ct);
        var name = playbook.Name.Trim();
        foreach (var request in created)
        {
            if (used >= playbook.DailyAutoLimit)
            {
                logger.LogInformation("Playbook {Playbook} reached its daily limit of {Limit} for {Tenant}; the rest wait for a person",
                    name, playbook.DailyAutoLimit, tenant.DisplayName);
                return;
            }

            var decider = Clip($"{playbook.PreApprovedByName} (pre-approved playbook \"{name}\")", 512);
            var note = $"Pre-approved by {playbook.PreApprovedByName} on {playbook.PreApprovedAt!.Value.UtcDateTime:yyyy-MM-dd}, " +
                       $"valid until {playbook.PreApprovalExpiresAt!.Value.UtcDateTime:yyyy-MM-dd}.";
            // Fail-closed: the approval authorises a write, so its audit entry comes first; without it the request waits for a person.
            try
            {
                await audit.RecordAsync(Event(AuditActions.DeviceActionAutoApproved, $"Playbook \"{name}\"",
                    $"Approved {request.Action} of {request.DeviceName} under the pre-approval by {playbook.PreApprovedByName}", tenant, request,
                    playbook, new() { ["approvedBy"] = playbook.PreApprovedByName ?? "", ["note"] = note }), ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                logger.LogCritical(ex, "Audit write failed before auto-approving {ActionId}; it waits for a person", request.Id);
                continue;
            }
            if (await actions.AutoApproveAsync(request.Id, playbook.PreApprovedByUserId!.Value, decider, note, now, ct) is not null) used++;
        }
    }

    private async Task<DeviceActionRequest?> ProposeAsync(RemediationPlaybook playbook, Tenant tenant, PlaybookProposal proposal, DateTimeOffset now, CancellationToken ct)
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
        if (!created) return null; // the device already has an open action; leave it alone

        try
        {
            await audit.RecordAsync(Event(AuditActions.DeviceActionRequested, $"Playbook \"{playbook.Name.Trim()}\"",
                $"Proposed {request.Action} of {request.DeviceName}: {request.Reason}", tenant, request, playbook, new()), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // A proposal changes nothing on the device; the approval and the send are the fail-closed steps.
            logger.LogCritical(ex, "Audit write failed for playbook proposal {ActionId} ({Action} of {Device})", request.Id, request.Action, request.DeviceName);
        }
        return request;
    }

    private AuditEvent Event(string action, string actor, string summary, Tenant tenant, DeviceActionRequest request, RemediationPlaybook playbook,
        Dictionary<string, string> extra)
    {
        var details = new Dictionary<string, string>
        {
            ["action"] = request.Action.ToString(),
            ["deviceId"] = request.DeviceId,
            ["deviceName"] = request.DeviceName,
            ["reason"] = request.Reason,
            ["requestedBy"] = request.RequestedByName,
            ["playbookId"] = playbook.Id.ToString()
        };
        foreach (var (k, v) in extra) details[k] = v;
        return new AuditEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = time.GetUtcNow(),
            Action = action,
            Outcome = AuditOutcome.Success,
            ActorName = actor,
            TenantId = tenant.Id,
            TargetType = "DeviceAction",
            TargetId = request.Id.ToString(),
            Summary = Clip(summary, 1000),
            Details = details
        };
    }

    private static string Clip(string s, int max) => s.Length > max ? s[..(max - 1)] + "…" : s;
}

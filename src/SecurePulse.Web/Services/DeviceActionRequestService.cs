using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

public sealed record DeviceActionOutcome(bool Ok, string Message, DeviceActionRequest? Request = null);

/// <summary>A pending or recent action with the names the UI shows next to it.</summary>
public sealed record DeviceActionView(DeviceActionRequest Request, string TenantName, string? WhyCannotApprove, bool CanCancel);

/// <summary>
/// Portal side of remote actions: requests, approvals, rejections and cancellations. Every rule is
/// enforced here, not just in the UI. Nothing here talks to Intune; the Worker sends approved actions.
/// </summary>
public sealed class DeviceActionRequestService(
    IDeviceActionRepository actions,
    ITenantRepository tenants,
    IDeviceRepository devices,
    IUserContextAccessor users,
    AuditTrail audit,
    TimeProvider time)
{
    /// <summary>The action history of one device, for anyone who can see its tenant.</summary>
    public async Task<IReadOnlyList<DeviceActionView>> GetForDeviceAsync(Guid tenantId, string deviceId, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.CanSee(tenantId) || await tenants.GetAsync(tenantId, ct) is not { } tenant) return [];
        var list = await actions.QueryAsync(new DeviceActionQuery { TenantId = tenantId, DeviceId = deviceId, Limit = 50 }, ct);
        return list.Select(a => View(a, tenant.DisplayName, user)).ToList();
    }

    /// <summary>All open actions and recent history, for operators.</summary>
    public async Task<IReadOnlyList<DeviceActionView>> GetQueueAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOperator) return [];
        var names = (await tenants.GetAllAsync(ct)).ToDictionary(t => t.Id, t => t.DisplayName);
        var list = await actions.QueryAsync(new DeviceActionQuery { Limit = 200 }, ct);
        return list.Where(a => user.CanSee(a.TenantId))
            .Select(a => View(a, names.GetValueOrDefault(a.TenantId, "Removed tenant"), user)).ToList();
    }

    public async Task<int> CountAwaitingMyApprovalAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOperator) return 0;
        var open = await actions.QueryAsync(new DeviceActionQuery { OpenOnly = true }, ct);
        return open.Count(a => a.Status == DeviceActionStatus.PendingApproval && DeviceActionPolicy.WhyCannotApprove(a, user.UserId, user.Role) is null);
    }

    public async Task<DeviceActionOutcome> RequestAsync(Guid tenantId, string deviceId, DeviceAction action, string? reason, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!DeviceActionPolicy.CanRequest(user.Role) || user.UserId is not { } userId)
            return new(false, "Only Owners and MSP admins can request device actions.");
        if (!user.CanSee(tenantId) || await tenants.GetAsync(tenantId, ct) is not { } tenant)
            return new(false, "Tenant not found.");
        if (!tenant.CanRemediate)
            return new(false, $"{tenant.DisplayName} hasn't granted remediation access, so device actions can't be requested.");
        if (!Enum.IsDefined(action))
            return new(false, "Unknown action.");
        if (await devices.GetAsync(tenantId, deviceId, ct) is not { } device)
            return new(false, "Device not found in this tenant's inventory.");
        if (!DeviceActionPolicy.AppliesTo(action, device.Platform))
            return new(false, $"{DeviceActions.Label(action)} is only for Windows devices.");
        var why = reason?.Trim();
        if (string.IsNullOrEmpty(why))
            return new(false, "Give a reason: the approver sees it and it's kept in the audit log.");
        if (why.Length > DeviceActionPolicy.MaxReasonLength)
            return new(false, $"Keep the reason under {DeviceActionPolicy.MaxReasonLength} characters.");

        var now = time.GetUtcNow();
        var (request, created) = await actions.AddAsync(new DeviceActionRequest
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            DeviceId = device.Id,
            DeviceName = device.DeviceName,
            Action = action,
            Reason = why,
            Status = DeviceActionStatus.PendingApproval,
            RequestedAt = now,
            RequestedByUserId = userId,
            RequestedByName = user.Name,
            ExpiresAt = now + DeviceActionPolicy.ApprovalWindow
        }, ct);
        if (!created)
            return new(false, $"{device.DeviceName} already has an open {DeviceActions.Label(request.Action).ToLowerInvariant()} request ({Label(request.Status)}). " +
                              "Wait for it to finish or cancel it first.", request);

        await audit.RecordAsync(AuditActions.DeviceActionRequested, AuditOutcome.Success,
            $"Requested {action} of {device.DeviceName}: {why}", tenantId, "DeviceAction", request.Id.ToString(), Details(request), user);
        return new(true, DeviceActionPolicy.IsDestructive(action)
            ? $"{DeviceActions.Label(action)} of {device.DeviceName} requested. An Owner other than you has to approve it."
            : $"{DeviceActions.Label(action)} of {device.DeviceName} requested. Another admin has to approve it.", request);
    }

    /// <summary>
    /// Approval authorises a write, so it is fail-closed: the audit entry is written first and the
    /// approval is only applied if that succeeded.
    /// </summary>
    public async Task<DeviceActionOutcome> ApproveAsync(Guid id, string? note, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(id, user, ct) is not { } a) return new(false, "Request not found.");
        if (a.Status != DeviceActionStatus.PendingApproval) return new(false, $"This request is {Label(a.Status).ToLowerInvariant()}, so it can't be approved.");
        if (DeviceActionPolicy.WhyCannotApprove(a, user.UserId, user.Role) is { } refusal) return new(false, refusal);
        if (await tenants.GetAsync(a.TenantId, ct) is not { CanRemediate: true }) return new(false, "Remediation access for this tenant was turned off.");
        if (Note(note) is { Error: { } bad }) return new(false, bad);

        try
        {
            await audit.RecordOrThrowAsync(AuditActions.DeviceActionApproved, AuditOutcome.Success,
                $"Approved {a.Action} of {a.DeviceName} requested by {a.RequestedByName}", a.TenantId, "DeviceAction", a.Id.ToString(),
                WithNote(Details(a), Note(note).Text), user);
        }
        catch (AuditUnavailableException ex)
        {
            return new(false, ex.Message);
        }

        var decided = await actions.DecideAsync(a.Id, approve: true, user.UserId!.Value, user.Name, user.Role!.Value, Note(note).Text, time.GetUtcNow(), ct);
        if (decided is null)
        {
            // Lost a race (someone else decided, it was cancelled, or it just expired): the approval didn't apply.
            await audit.RecordAsync(AuditActions.DeviceActionApproved, AuditOutcome.Failure,
                $"Approval of {a.Action} of {a.DeviceName} wasn't applied: the request was no longer pending", a.TenantId, "DeviceAction", a.Id.ToString(),
                Details(a), user);
            return new(false, "The request changed before your approval applied (someone else decided, it was cancelled, or it expired).");
        }
        return new(true, $"Approved. SecurePulse sends {DeviceActions.Label(a.Action).ToLowerInvariant()} to {a.DeviceName} within a minute.", decided);
    }

    public async Task<DeviceActionOutcome> RejectAsync(Guid id, string? note, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(id, user, ct) is not { } a) return new(false, "Request not found.");
        if (!user.IsOperator) return new(false, "Only Owners and MSP admins can reject device actions.");
        if (user.UserId == a.RequestedByUserId) return new(false, "Cancel your own request instead of rejecting it.");
        if (Note(note) is { Error: { } bad }) return new(false, bad);
        if (string.IsNullOrWhiteSpace(note)) return new(false, "Say why you're rejecting it; the requester sees this.");

        var decided = await actions.DecideAsync(a.Id, approve: false, user.UserId!.Value, user.Name, user.Role!.Value, Note(note).Text, time.GetUtcNow(), ct);
        if (decided is null) return new(false, "This request is no longer waiting for approval.");
        await audit.RecordAsync(AuditActions.DeviceActionRejected, AuditOutcome.Success,
            $"Rejected {a.Action} of {a.DeviceName} requested by {a.RequestedByName}", a.TenantId, "DeviceAction", a.Id.ToString(),
            WithNote(Details(a), Note(note).Text), user);
        return new(true, "Rejected.", decided);
    }

    /// <summary>The requester or any operator can cancel until the Worker starts sending.</summary>
    public async Task<DeviceActionOutcome> CancelAsync(Guid id, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(id, user, ct) is not { } a) return new(false, "Request not found.");
        if (!user.IsOperator) return new(false, "Only Owners and MSP admins can cancel device actions.");
        var cancelled = await actions.CancelAsync(a.Id, user.Name, $"Cancelled by {user.Name}.", time.GetUtcNow(), ct);
        if (cancelled is null) return new(false, "Too late to cancel: it's already being sent, or it's finished.");
        await audit.RecordAsync(AuditActions.DeviceActionCancelled, AuditOutcome.Success,
            $"Cancelled {a.Action} of {a.DeviceName}", a.TenantId, "DeviceAction", a.Id.ToString(), Details(a), user);
        return new(true, "Cancelled.", cancelled);
    }

    private async Task<DeviceActionRequest?> LoadAsync(Guid id, UserContext user, CancellationToken ct) =>
        await actions.GetAsync(id, ct) is { } a && user.CanSee(a.TenantId) ? a : null;

    private static DeviceActionView View(DeviceActionRequest a, string tenantName, UserContext user) => new(a, tenantName,
        a.Status == DeviceActionStatus.PendingApproval ? DeviceActionPolicy.WhyCannotApprove(a, user.UserId, user.Role) : "It isn't waiting for approval.",
        user.IsOperator && a.Status is DeviceActionStatus.PendingApproval or DeviceActionStatus.Approved);

    private static (string? Text, string? Error) Note(string? note)
    {
        var text = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        return text is { Length: > DeviceActionPolicy.MaxNoteLength }
            ? (null, $"Keep the note under {DeviceActionPolicy.MaxNoteLength} characters.")
            : (text, null);
    }

    private static Dictionary<string, string> Details(DeviceActionRequest a) => new()
    {
        ["action"] = a.Action.ToString(),
        ["deviceId"] = a.DeviceId,
        ["deviceName"] = a.DeviceName,
        ["reason"] = a.Reason,
        ["requestedBy"] = a.RequestedByName
    };

    private static Dictionary<string, string> WithNote(Dictionary<string, string> details, string? note)
    {
        if (note is not null) details["note"] = note;
        return details;
    }

    public static string Label(DeviceActionStatus status) => status switch
    {
        DeviceActionStatus.PendingApproval => "Waiting for approval",
        DeviceActionStatus.Approved => "Approved, sending shortly",
        DeviceActionStatus.Sending => "Sending",
        DeviceActionStatus.Sent => "Sent to Intune",
        _ => status.ToString()
    };
}

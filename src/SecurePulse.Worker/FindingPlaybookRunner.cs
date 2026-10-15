using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Worker;

/// <summary>
/// After a successful scan, proposes catalog fixes for checks that failed in a tenant with configuration access.
/// Proposals always wait for another Owner's approval; nothing here changes a tenant.
/// </summary>
public sealed class FindingPlaybookRunner(
    IFindingPlaybookRepository playbooks,
    IFindingRepository findings,
    IConfigurationChangeRepository changes,
    IAuditLog audit,
    TimeProvider time,
    ILogger<FindingPlaybookRunner> logger)
{
    public async Task<int> RunForTenantAsync(Tenant tenant, CancellationToken ct = default)
    {
        if (!tenant.CanConfigure) return 0;
        var applicable = (await playbooks.GetAllAsync(ct)).Where(p => p.Enabled && (p.TenantId is null || p.TenantId == tenant.Id)).ToList();
        if (applicable.Count == 0) return 0;

        var current = await findings.GetForTenantAsync(tenant.Id, ct);
        var proposed = 0;
        foreach (var playbook in applicable)
        {
            var now = time.GetUtcNow();
            if (ConfigurationFixes.Find(playbook.FixId) is not { } fix)
            {
                logger.LogWarning("Finding playbook {PlaybookId} refers to unknown fix {Fix}; skipped", playbook.Id, playbook.FixId);
                continue;
            }
            await playbooks.RecordRunAsync(playbook.Id, now, ct);
            if (FindingPlaybookRules.Proposal(playbook, fix, tenant, current) is not { } reason) continue;
            if (await changes.HasPlaybookProposalSinceAsync(playbook.Id, tenant.Id, now - FindingPlaybookRules.Cooldown, ct)) continue;

            var checkId = current.First(f => f.Status == FindingStatus.Failed && fix.CheckIds.Contains(f.SourceCheckId ?? "", StringComparer.OrdinalIgnoreCase)).SourceCheckId;
            var (request, created) = await changes.AddAsync(new ConfigurationChangeRequest
            {
                Id = Guid.NewGuid(),
                TenantId = tenant.Id,
                FixId = fix.Id,
                CheckId = checkId,
                Reason = reason,
                Status = DeviceActionStatus.PendingApproval,
                RequestedAt = now,
                // In the name of the playbook's last editor, so they can't approve it: another Owner has to.
                RequestedByUserId = playbook.UpdatedByUserId,
                RequestedByName = Clip($"{playbook.UpdatedByName} (finding playbook \"{fix.Title}\")", 512),
                ExpiresAt = now + ConfigurationChangePolicy.ApprovalWindow,
                PlaybookId = playbook.Id
            }, ct);
            if (!created) continue; // already waiting or being applied

            proposed++;
            try
            {
                await audit.RecordAsync(new AuditEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = now,
                    Action = AuditActions.ConfigChangeRequested,
                    Outcome = AuditOutcome.Success,
                    ActorName = $"Finding playbook \"{fix.Title}\"",
                    TenantId = tenant.Id,
                    TargetType = "ConfigurationChange",
                    TargetId = request.Id.ToString(),
                    Summary = $"Proposed \"{fix.PolicyDisplayName}\" for {tenant.DisplayName}: {reason}",
                    Details = new Dictionary<string, string>
                    {
                        ["fix"] = fix.Id, ["checkId"] = checkId ?? "", ["reason"] = reason, ["requestedBy"] = request.RequestedByName,
                        ["playbookId"] = playbook.Id.ToString()
                    }
                }, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                // A proposal changes nothing in the tenant; the approval and the send are the fail-closed steps.
                logger.LogCritical(ex, "Audit write failed for configuration proposal {ChangeId}", request.Id);
            }
        }
        if (proposed > 0)
            logger.LogInformation("Finding playbooks proposed {Count} configuration changes for {Tenant}; each needs another Owner's approval",
                proposed, tenant.DisplayName);
        return proposed;
    }

    private static string Clip(string s, int max) => s.Length > max ? s[..(max - 1)] + "…" : s;
}

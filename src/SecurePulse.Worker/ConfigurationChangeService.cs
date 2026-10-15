using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;

namespace SecurePulse.Worker;

public sealed class ConfigurationChangeOptions
{
    public bool Enabled { get; set; } = true;
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>A change still Sending after this long is failed as "outcome unknown".</summary>
    public TimeSpan StuckSendingAfter { get; set; } = TimeSpan.FromMinutes(10);
}

/// <summary>
/// Applies approved configuration fixes through the separate configuration app. Like device actions: before each
/// one it re-checks configuration access, the approval policy (another Owner) and the token's roles, writes the
/// audit entry first, and only then makes one Graph call. Never retried.
/// </summary>
public sealed class ConfigurationChangeService(
    IConfigurationChangeRepository changes,
    ITenantRepository tenants,
    IConfigurationTokenProvider tokens,
    IConditionalAccessWriter writer,
    IAuditLog audit,
    IOptions<ConfigurationChangeOptions> options,
    TimeProvider time,
    ILogger<ConfigurationChangeService> logger)
{
    private const string WorkerActor = "SecurePulse Worker";

    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        foreach (var c in await changes.ExpireAsync(now, ConfigurationChangePolicy.SendWindow, now - options.Value.StuckSendingAfter, ct))
            await TryAuditAsync(c.Status == DeviceActionStatus.Failed ? AuditActions.ConfigChangeResult : AuditActions.ConfigChangeExpired,
                AuditOutcome.Failure, $"{Title(c)}: {c.Error}", c, ct);

        var processed = 0;
        while (!ct.IsCancellationRequested && await changes.ClaimNextApprovedAsync(time.GetUtcNow(), ct) is { } claimed)
        {
            processed++;
            await ProcessAsync(claimed, ct);
        }
        return processed;
    }

    private async Task ProcessAsync(ConfigurationChangeRequest c, CancellationToken ct)
    {
        if (await RefusalAsync(c, ct) is { } refusal)
        {
            await FinishAsync(c, new ConditionalAccessResult(false, null, $"Not sent: {refusal}"), ct);
            return;
        }
        var tenant = (await tenants.GetAsync(c.TenantId, ct))!;
        var fix = ConfigurationFixes.Find(c.FixId)!;

        string token;
        try
        {
            token = await tokens.GetTokenAsync(tenant.EntraTenantId, tenant.ConfigurationCredentialReference!, ct);
        }
        catch (GraphAuthException ex)
        {
            await FinishAsync(c, new ConditionalAccessResult(false, null, $"Not sent: {ex.Message}"), ct);
            return;
        }
        if (TokenProblem(token, tenant) is { } problem)
        {
            await FinishAsync(c, new ConditionalAccessResult(false, null, $"Not sent: {problem}"), ct);
            return;
        }

        // Fail-closed: the audit entry is written before anything reaches Graph.
        try
        {
            await audit.RecordAsync(Event(AuditActions.ConfigChangeSending, AuditOutcome.Success,
                $"Creating \"{fix.PolicyDisplayName}\" in {tenant.DisplayName} (approved by {c.DecidedByName})", c), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed before configuration change {ChangeId}; not sending", c.Id);
            await changes.CompleteAsync(c.Id, false, "Not sent: the audit log couldn't be written, and changes are never made unaudited.", null,
                time.GetUtcNow(), CancellationToken.None);
            return;
        }

        // Once sent, shutdown mustn't cancel it: the outcome would be unknown.
        var result = await writer.ApplyAsync(fix, token, CancellationToken.None);
        await FinishAsync(c, result, ct);
    }

    private async Task<string?> RefusalAsync(ConfigurationChangeRequest c, CancellationToken ct)
    {
        if (await tenants.GetAsync(c.TenantId, ct) is not { } tenant) return "the tenant no longer exists.";
        if (!tenant.CanConfigure) return "configuration access for this tenant was turned off.";
        if (ConfigurationFixes.Find(c.FixId) is null) return "it isn't a fix SecurePulse knows.";
        if (c.DecidedByUserId is null || c.DecidedAt is null || c.DecidedByRole is null) return "it has no recorded approval.";
        if (ConfigurationChangePolicy.WhyCannotApprove(c, c.DecidedByUserId, c.DecidedByRole) is { } policy)
            return $"the approval doesn't meet the policy ({policy})";
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
            return $"couldn't read the configuration token ({ex.Message}).";
        }
        if (claims.TenantId != tenant.EntraTenantId) return $"the token was issued for tenant {claims.TenantId}, not {tenant.EntraTenantId}.";
        if (ConfigurationPermissions.Unexpected(claims.Roles) is { Count: > 0 } extra)
            return $"the configuration app holds permissions it shouldn't ({string.Join(", ", extra)}). Remove them and have the tenant consent again.";
        if (ConfigurationPermissions.MissingFrom(claims.Roles) is { Count: > 0 } missing)
            return $"the tenant hasn't granted {string.Join(", ", missing)} to the configuration app any more.";
        return null;
    }

    private async Task FinishAsync(ConfigurationChangeRequest c, ConditionalAccessResult result, CancellationToken ct)
    {
        var note = result.AlreadyPresent ? "A policy with this name already existed; nothing new was created." : result.Error;
        await changes.CompleteAsync(c.Id, result.Succeeded, note, result.PolicyId, time.GetUtcNow(), CancellationToken.None);
        if (result.Succeeded)
            logger.LogInformation("Configuration change {ChangeId} ({Fix}) applied: policy {PolicyId}", c.Id, c.FixId, result.PolicyId);
        else
            logger.LogWarning("Configuration change {ChangeId} ({Fix}) failed: {Error}", c.Id, c.FixId, result.Error);

        var fix = ConfigurationFixes.Find(c.FixId);
        await TryAuditAsync(AuditActions.ConfigChangeResult, result.Succeeded ? AuditOutcome.Success : AuditOutcome.Failure,
            result.Succeeded
                ? result.AlreadyPresent
                    ? $"\"{fix?.PolicyDisplayName}\" already existed (policy {result.PolicyId}); nothing new was created"
                    : $"Created \"{fix?.PolicyDisplayName}\" in report-only mode (policy {result.PolicyId}). A tenant admin switches it on in Entra after reviewing its impact"
                : $"{Title(c)} failed: {result.Error}", c, ct);
    }

    private async Task TryAuditAsync(string action, AuditOutcome outcome, string summary, ConfigurationChangeRequest c, CancellationToken ct)
    {
        try
        {
            await audit.RecordAsync(Event(action, outcome, summary, c), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogCritical(ex, "Audit write failed for {AuditAction} ({Outcome}): {Summary}", action, outcome, summary);
        }
    }

    private static string Title(ConfigurationChangeRequest c) => ConfigurationFixes.Find(c.FixId)?.Title ?? c.FixId;

    private AuditEvent Event(string action, AuditOutcome outcome, string summary, ConfigurationChangeRequest c) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow(),
        Action = action,
        Outcome = outcome,
        ActorName = WorkerActor,
        TenantId = c.TenantId,
        TargetType = "ConfigurationChange",
        TargetId = c.Id.ToString(),
        Summary = summary.Length > 1000 ? summary[..1000] + "…" : summary,
        Details = new Dictionary<string, string>
        {
            ["fix"] = c.FixId,
            ["checkId"] = c.CheckId ?? "",
            ["requestedBy"] = c.RequestedByName,
            ["approvedBy"] = c.DecidedByName ?? ""
        }
    };
}

public sealed class ConfigurationChangeWorker(ConfigurationChangeService service, IOptions<ConfigurationChangeOptions> options,
    ILogger<ConfigurationChangeWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Configuration changes are disabled (ConfigurationChanges:Enabled = false)");
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
                logger.LogError(ex, "Configuration change pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Engines.Maester;
using SecurePulse.Engines.ScubaGear;
using SecurePulse.Intune;
using SecurePulse.Worker;
using SecurePulse.Worker.Siem;

var builder = Host.CreateApplicationBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("SecurePulse");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        "ConnectionStrings:SecurePulse is not set. Provide it with user-secrets or the ConnectionStrings__SecurePulse environment variable.");
}

builder.Services.AddSecurePulseData(connectionString);
var intune = builder.Configuration.GetSection("Intune").Get<IntuneOptions>() ?? new IntuneOptions();
builder.Services.AddIntuneDeviceSource(intune);

// Engines run out of process and use the same multi-tenant app as the Intune sync unless their
// AppClientId says otherwise. Scans:Engines picks the ones this Worker runs: ScubaGear needs Windows
// PowerShell 5.1, so it can run on a Windows Worker sharing the queue with a Linux one.
var scanEngines = builder.Configuration.GetSection("Scans:Engines").Get<string[]>() is { Length: > 0 } configured
    ? configured
    : [ScanEngines.Maester];
if (scanEngines.FirstOrDefault(e => !ScanEngines.All.Contains(e, StringComparer.Ordinal)) is { } unknown)
    throw new InvalidOperationException($"Scans:Engines lists '{unknown}'. Known engines: {string.Join(", ", ScanEngines.All)}.");

var engineTimeouts = new List<(string Name, TimeSpan Timeout)>();
if (scanEngines.Contains(ScanEngines.Maester))
{
    var maester = builder.Configuration.GetSection("Maester").Get<MaesterOptions>() ?? new MaesterOptions();
    if (string.IsNullOrWhiteSpace(maester.AppClientId)) maester.AppClientId = intune.AppClientId;
    builder.Services.AddSingleton(maester);
    builder.Services.AddSingleton<IScanEngine, MaesterEngine>();
    engineTimeouts.Add(("Maester", maester.Timeout));
}
if (scanEngines.Contains(ScanEngines.ScubaGear))
{
    var scubaGear = builder.Configuration.GetSection("ScubaGear").Get<ScubaGearOptions>() ?? new ScubaGearOptions();
    if (string.IsNullOrWhiteSpace(scubaGear.AppClientId)) scubaGear.AppClientId = intune.AppClientId;
    builder.Services.AddSingleton(scubaGear);
    builder.Services.AddSingleton<IScanEngine, ScubaGearEngine>();
    engineTimeouts.Add(("ScubaGear", scubaGear.Timeout));
}

if (scanEngines.Contains(ScanEngines.Wazuh))
{
    // Wazuh reads the shared Wazuh manager's API, not Graph; its password comes from Key Vault.
    var wazuh = builder.Services.AddWazuhEngine(builder.Configuration);
    engineTimeouts.Add(("Wazuh", wazuh.Timeout));
}
if (scanEngines.Contains(ScanEngines.GoPhish))
{
    // GoPhish: read-only import of each tenant's campaign counts; each tenant's API key comes from Key Vault.
    var goPhish = builder.Services.AddGoPhishEngine(builder.Configuration);
    engineTimeouts.Add(("GoPhish", goPhish.Timeout));
}

builder.Services.AddOptions<ScanOptions>()
    .Bind(builder.Configuration.GetSection("Scans"))
    .Validate(o => o.Interval >= TimeSpan.FromHours(1), "Scans:Interval must be at least one hour.")
    .Validate(o => o.PollInterval >= TimeSpan.FromSeconds(10), "Scans:PollInterval must be at least 10 seconds.")
    .Validate(o => o.MaxParallelScans >= 1, "Scans:MaxParallelScans must be at least 1.")
    .Validate(o => engineTimeouts.All(e => o.StaleAfter > e.Timeout),
        $"Scans:StaleAfter must be longer than every engine's Timeout ({string.Join(", ", engineTimeouts.Select(e => $"{e.Name}: {e.Timeout}"))}).")
    .ValidateOnStart();
builder.Services.AddSingleton<ScanService>();
builder.Services.AddHostedService<ScanWorker>();

builder.Services.AddOptions<DeviceSyncOptions>()
    .Bind(builder.Configuration.GetSection("DeviceSync"))
    .Validate(o => o.Interval >= TimeSpan.FromMinutes(1), "DeviceSync:Interval must be at least one minute.")
    .Validate(o => o.MaxParallelTenants >= 1, "DeviceSync:MaxParallelTenants must be at least 1.")
    .ValidateOnStart();
// Remediation playbooks: after each sync, propose device actions for matching devices (each still needs approval).
var playbookOptions = builder.Configuration.GetSection("Playbooks").Get<PlaybookOptions>() ?? new PlaybookOptions();
if (playbookOptions.Enabled) builder.Services.AddSingleton<PlaybookRunner>();
builder.Services.AddSingleton<DeviceSyncService>();
builder.Services.AddHostedService<DeviceSyncWorker>();

// Remote device actions go through a separate remediation app with its own certificate.
var remediation = builder.Configuration.GetSection("Remediation").Get<RemediationOptions>() ?? new RemediationOptions();
builder.Services.AddIntuneRemoteActions(remediation);
builder.Services.AddOptions<DeviceActionOptions>()
    .Bind(builder.Configuration.GetSection("DeviceActions"))
    .Validate(o => o.PollInterval >= TimeSpan.FromSeconds(5), "DeviceActions:PollInterval must be at least 5 seconds.")
    .Validate(o => o.StuckSendingAfter > remediation.SendTimeout, "DeviceActions:StuckSendingAfter must be longer than Remediation:SendTimeout.")
    .ValidateOnStart();
builder.Services.AddSingleton<DeviceActionService>();
builder.Services.AddHostedService<DeviceActionWorker>();

builder.Services.AddOptions<OnboardingVerificationOptions>()
    .Bind(builder.Configuration.GetSection("Onboarding"))
    .Validate(o => o.PollInterval >= TimeSpan.FromSeconds(5), "Onboarding:PollInterval must be at least 5 seconds.")
    .ValidateOnStart();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<OnboardingVerificationService>();
builder.Services.AddHostedService<OnboardingVerificationWorker>();

// Audit retention: off until AuditRetention:RetainFor is set. Deleting needs a separate maintenance
// login (a member of the purge role); the application's login must never be able to delete audit events.
builder.Services.AddOptions<AuditRetentionOptions>()
    .Bind(builder.Configuration.GetSection("AuditRetention"))
    .Validate(o => o.RetainFor is not { } r || AuditRetention.Problem(r) is null,
        $"AuditRetention:RetainFor must be at least {AuditRetention.Minimum.TotalDays:0} days.")
    .Validate(o => o.Interval >= TimeSpan.FromHours(1), "AuditRetention:Interval must be at least one hour.")
    .Validate(o => o.BatchSize is >= 100 and <= 100_000, "AuditRetention:BatchSize must be between 100 and 100000.")
    .ValidateOnStart();
if (builder.Configuration.GetSection("AuditRetention").Get<AuditRetentionOptions>() is { Enabled: true })
{
    var maintenance = builder.Configuration.GetConnectionString("AuditMaintenance");
    if (string.IsNullOrWhiteSpace(maintenance))
        throw new InvalidOperationException(
            "AuditRetention:RetainFor is set, but ConnectionStrings:AuditMaintenance isn't. Retention deletes with a separate maintenance login.");
    if (string.Equals(new Npgsql.NpgsqlConnectionStringBuilder(maintenance).Username, new Npgsql.NpgsqlConnectionStringBuilder(connectionString).Username,
            StringComparison.Ordinal))
        throw new InvalidOperationException(
            "ConnectionStrings:AuditMaintenance uses the application's login. Use a separate login that is a member of securepulse_audit_purge.");
    builder.Services.AddAuditPurger(maintenance);
    builder.Services.AddSingleton<AuditRetentionService>();
    builder.Services.AddHostedService<AuditRetentionWorker>();
}

// Audit export to Microsoft Sentinel (Logs Ingestion API). Off unless AuditExport:Sentinel:Enabled.
var sentinel = builder.Configuration.GetSection("AuditExport:Sentinel").Get<SentinelOptions>() ?? new SentinelOptions();
if (sentinel.Enabled)
{
    if (sentinel.Problems() is { Count: > 0 } problems)
        throw new InvalidOperationException(string.Join(" ", problems));
    builder.Services.AddSingleton(sentinel);
    builder.Services.AddSingleton<ISentinelTokenProvider, AzureSentinelTokenProvider>();
    // The sink applies SentinelOptions.Timeout itself; no redirects, so the token only goes to the configured host.
    builder.Services.AddHttpClient<ISentinelAuditSink, SentinelAuditSink>(c => c.Timeout = Timeout.InfiniteTimeSpan)
        .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
    builder.Services.AddSingleton<AuditExportService>();
    builder.Services.AddHostedService<AuditExportWorker>();
}

var host = builder.Build();

if (builder.Configuration.GetValue("Database:MigrateOnStartup", true))
    await host.Services.MigrateSecurePulseDatabaseAsync();

await host.RunAsync();

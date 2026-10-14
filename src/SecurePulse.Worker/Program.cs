using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Engines.Maester;
using SecurePulse.Engines.ScubaGear;
using SecurePulse.Intune;
using SecurePulse.Worker;

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
builder.Services.AddSingleton<DeviceSyncService>();
builder.Services.AddHostedService<DeviceSyncWorker>();

builder.Services.AddOptions<OnboardingVerificationOptions>()
    .Bind(builder.Configuration.GetSection("Onboarding"))
    .Validate(o => o.PollInterval >= TimeSpan.FromSeconds(5), "Onboarding:PollInterval must be at least 5 seconds.")
    .ValidateOnStart();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<OnboardingVerificationService>();
builder.Services.AddHostedService<OnboardingVerificationWorker>();

var host = builder.Build();

if (builder.Configuration.GetValue("Database:MigrateOnStartup", true))
    await host.Services.MigrateSecurePulseDatabaseAsync();

await host.RunAsync();

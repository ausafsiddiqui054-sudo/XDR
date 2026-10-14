using SecurePulse.Core.Abstractions;
using SecurePulse.Data;
using SecurePulse.Engines.Maester;
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

// Engines run out of process. Maester uses the same multi-tenant app as the Intune sync unless
// Maester:AppClientId says otherwise.
var maester = builder.Configuration.GetSection("Maester").Get<MaesterOptions>() ?? new MaesterOptions();
if (string.IsNullOrWhiteSpace(maester.AppClientId)) maester.AppClientId = intune.AppClientId;
builder.Services.AddSingleton(maester);
builder.Services.AddSingleton<IScanEngine, MaesterEngine>();

builder.Services.AddOptions<ScanOptions>()
    .Bind(builder.Configuration.GetSection("Scans"))
    .Validate(o => o.Interval >= TimeSpan.FromHours(1), "Scans:Interval must be at least one hour.")
    .Validate(o => o.PollInterval >= TimeSpan.FromSeconds(10), "Scans:PollInterval must be at least 10 seconds.")
    .Validate(o => o.MaxParallelScans >= 1, "Scans:MaxParallelScans must be at least 1.")
    .Validate(o => o.StaleAfter > maester.Timeout, "Scans:StaleAfter must be longer than Maester:Timeout.")
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

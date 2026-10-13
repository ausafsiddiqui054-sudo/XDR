using SecurePulse.Data;
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
builder.Services.AddIntuneDeviceSource(builder.Configuration.GetSection("Intune").Get<IntuneOptions>() ?? new IntuneOptions());

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

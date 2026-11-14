using MudBlazor.Services;
using Hasinix.Core.Abstractions;
using Hasinix.Core.Models;
using Hasinix.Data;
using Hasinix.Playbooks;
using Hasinix.Web.Components;
using Hasinix.Web.Services;
using Hasinix.Web.Services.Onboarding;
using Hasinix.Web.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();

// Entra ID sign-in with Hasinix-managed roles (development sign-in when not configured).
var useEntra = builder.AddPortalAuthentication();

// With a connection string the portal reads PostgreSQL (written by the Worker). Without one it
// runs on in-memory sample data, so the UI can be designed and demoed with no database.
var connectionString = builder.Configuration.GetConnectionString("Hasinix");
var useDatabase = !string.IsNullOrWhiteSpace(connectionString);
var demo = builder.Configuration.GetSection("Demo").Get<DemoOptions>() ?? new DemoOptions();
var simulated = !useDatabase && demo.Simulate;
if (useDatabase)
{
    builder.Services.AddHasinixData(connectionString!);
}
else
{
    builder.Services.AddSingleton(_ => new SampleDataStore(fullDemo: true));
    builder.Services.AddSingleton<ITenantRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IFindingRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IDeviceRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IOnboardingRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IPortalUserRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IAuditLog>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IScanRunRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IScoreHistory>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IFindingTrackingRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IDeviceActionRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IPlaybookRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IConfigurationChangeRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IFindingPlaybookRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IAuditExportStore>(sp => sp.GetRequiredService<SampleDataStore>());

    // Sample data only: a simulated Worker so a demo runs end to end. It changes the in-memory store and never calls Microsoft.
    if (simulated)
    {
        builder.Services.AddSingleton(demo);
        builder.Services.AddSingleton<PlaybookRunner>();
        builder.Services.AddSingleton<FindingPlaybookRunner>();
        builder.Services.AddHostedService<DemoSimulator>();
    }
}
builder.Services.AddSingleton(new PortalMode(useDatabase, simulated));
builder.Services.AddScoped<PostureService>();
builder.Services.AddScoped<ScoreTrendService>();
builder.Services.AddScoped<FindingTrackingService>();
builder.Services.AddScoped<EndpointService>();
builder.Services.AddScoped<DeviceActionRequestService>();
builder.Services.AddScoped<PlaybookService>();
builder.Services.AddScoped<ConfigurationChangeRequestService>();
builder.Services.AddScoped<PortalUserService>();
builder.Services.AddScoped<AuditTrail>();
// The simulated Worker runs every engine; a real portal lists the engines its Workers run.
builder.Services.AddSingleton(ScanEngineSelection.From(simulated ? [.. ScanEngines.All] : builder.Configuration.GetSection("Scans:Engines").Get<string[]>()));
builder.Services.AddScoped<ScanRequestService>();

// Branded PDF reports. Off until Reports:QuestPdfLicense names the QuestPDF license tier held.
builder.Services.AddSingleton(ReportSettings.Load(builder.Configuration.GetSection("Reports").Get<ReportOptions>() ?? new ReportOptions(),
    builder.Environment.ContentRootPath));
builder.Services.AddScoped<ReportService>();

// Data protection (sign-in cookie, antiforgery, consent-link state). With PostgreSQL the key ring is
// shared by every instance and encrypted with a certificate; a setup that can't do that stops here.
var keyRing = builder.Services.AddHasinixDataProtection(
    builder.Configuration.GetSection("DataProtection").Get<KeyRingOptions>() ?? new KeyRingOptions(),
    useDatabase, builder.Environment.IsDevelopment(), KeyRing.FindInStores);

// Tenant onboarding.
builder.Services.AddSingleton(builder.Configuration.GetSection("Onboarding").Get<OnboardingOptions>() ?? new OnboardingOptions());
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpClient<IEntraTenantResolver, EntraTenantResolver>(c => c.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddScoped<OnboardingService>();

var app = builder.Build();

app.Logger.LogInformation("Data-protection keys: {KeyRing}", keyRing.Description);
foreach (var warning in keyRing.Warnings)
    app.Logger.LogWarning("{KeyRingWarning}", warning);

if (useDatabase && app.Environment.IsDevelopment())
{
    // Production databases are migrated by the Worker (or a release step), not the portal.
    await app.Services.MigrateHasinixDatabaseAsync();
    if (app.Configuration.GetValue("Database:SeedSampleData", true))
    {
        var sample = new SampleDataStore();
        var (tenants, findings, devices) = sample.Snapshot();
        if (await app.Services.SeedIfEmptyAsync(tenants, findings, devices, sample.ScoreHistory()))
            app.Logger.LogInformation("Seeded an empty database with sample tenants, findings, devices and score history");
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
// Development usually runs on http only (hasinix.bat, the http launch profile), where there is no https
// port to redirect to and the middleware just logs a warning. Everywhere else the redirect stays on.
if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets().AllowAnonymous();

// Entra redirects here after the admin-consent prompt. Handle it once, then redirect to a
// result page so a refresh or a shared URL can't replay it.
app.MapGet("/" + OnboardingService.CallbackPath, async (HttpRequest request, OnboardingService onboarding, CancellationToken ct) =>
{
    var q = request.Query;
    var outcome = await onboarding.HandleCallbackAsync(q["state"], q["tenant"], q["admin_consent"], q["error"], q["error_description"], ct,
        request.HttpContext.Connection.RemoteIpAddress?.ToString());
    return Results.LocalRedirect($"~/onboarding/consent-result?outcome={outcome}");
}).AllowAnonymous(); // the client's admin isn't a portal user

app.MapPortalAuthEndpoints(useEntra);
app.MapAuditExport();
ReportService.MapReportDownload(app);
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

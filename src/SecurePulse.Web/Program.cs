using MudBlazor.Services;
using SecurePulse.Core.Abstractions;
using SecurePulse.Data;
using SecurePulse.Web.Components;
using SecurePulse.Web.Services;
using SecurePulse.Web.Services.Onboarding;
using SecurePulse.Web.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();

// Entra ID sign-in with SecurePulse-managed roles (development sign-in when not configured).
var useEntra = builder.AddPortalAuthentication();

// With a connection string the portal reads PostgreSQL (written by the Worker). Without one it
// runs on in-memory sample data, so the UI can be designed and demoed with no database.
var connectionString = builder.Configuration.GetConnectionString("SecurePulse");
var useDatabase = !string.IsNullOrWhiteSpace(connectionString);
if (useDatabase)
{
    builder.Services.AddSecurePulseData(connectionString!);
}
else
{
    builder.Services.AddSingleton<SampleDataStore>();
    builder.Services.AddSingleton<ITenantRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IFindingRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IDeviceRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IOnboardingRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IPortalUserRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IAuditLog>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IScanRunRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IDeviceActionRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IPlaybookRepository>(sp => sp.GetRequiredService<SampleDataStore>());
    builder.Services.AddSingleton<IAuditExportStore>(sp => sp.GetRequiredService<SampleDataStore>());
}
builder.Services.AddSingleton(new PortalMode(useDatabase));
builder.Services.AddScoped<PostureService>();
builder.Services.AddScoped<EndpointService>();
builder.Services.AddScoped<DeviceActionRequestService>();
builder.Services.AddScoped<PlaybookService>();
builder.Services.AddScoped<PortalUserService>();
builder.Services.AddScoped<AuditTrail>();
builder.Services.AddSingleton(ScanEngineSelection.From(builder.Configuration.GetSection("Scans:Engines").Get<string[]>()));
builder.Services.AddScoped<ScanRequestService>();

// Branded PDF reports. Off until Reports:QuestPdfLicense names the QuestPDF license tier held.
builder.Services.AddSingleton(ReportSettings.Load(builder.Configuration.GetSection("Reports").Get<ReportOptions>() ?? new ReportOptions(),
    builder.Environment.ContentRootPath));
builder.Services.AddScoped<ReportService>();

// Data protection (sign-in cookie, antiforgery, consent-link state). With PostgreSQL the key ring is
// shared by every instance and encrypted with a certificate; a setup that can't do that stops here.
var keyRing = builder.Services.AddSecurePulseDataProtection(
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
    await app.Services.MigrateSecurePulseDatabaseAsync();
    if (app.Configuration.GetValue("Database:SeedSampleData", true))
    {
        var (tenants, findings, devices) = new SampleDataStore().Snapshot();
        if (await app.Services.SeedIfEmptyAsync(tenants, findings, devices))
            app.Logger.LogInformation("Seeded an empty database with sample tenants, findings and devices");
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
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

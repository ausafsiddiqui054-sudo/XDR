using MudBlazor.Services;
using SecurePulse.Core.Abstractions;
using SecurePulse.Data;
using SecurePulse.Web.Components;
using SecurePulse.Web.Services;
using SecurePulse.Web.Services.Onboarding;
using Microsoft.AspNetCore.DataProtection;
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
}
builder.Services.AddSingleton(new PortalMode(useDatabase));
builder.Services.AddScoped<PostureService>();
builder.Services.AddScoped<EndpointService>();
builder.Services.AddScoped<PortalUserService>();
builder.Services.AddScoped<AuditTrail>();
builder.Services.AddScoped<ScanRequestService>();

// Tenant onboarding. Consent-link state is encrypted with data protection; in production,
// persist the key ring somewhere shared (PersistKeysTo...) so links survive restarts and scale-out.
builder.Services.AddDataProtection().SetApplicationName("SecurePulse");
builder.Services.AddSingleton(builder.Configuration.GetSection("Onboarding").Get<OnboardingOptions>() ?? new OnboardingOptions());
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpClient<IEntraTenantResolver, EntraTenantResolver>(c => c.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddScoped<OnboardingService>();

var app = builder.Build();

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
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

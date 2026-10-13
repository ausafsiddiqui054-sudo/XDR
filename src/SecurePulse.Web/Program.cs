using MudBlazor.Services;
using SecurePulse.Core.Abstractions;
using SecurePulse.Data;
using SecurePulse.Web.Components;
using SecurePulse.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();

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
}
builder.Services.AddScoped<PostureService>();
builder.Services.AddScoped<EndpointService>();

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

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

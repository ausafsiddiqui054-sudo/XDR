using MudBlazor.Services;
using SecurePulse.Core.Abstractions;
using SecurePulse.Web.Components;
using SecurePulse.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();

// Phase 1 uses seeded sample data so the UI can be designed and demoed before
// any real tenant is connected. Swap these for EF Core repositories later.
builder.Services.AddSingleton<SampleDataStore>();
builder.Services.AddSingleton<ITenantRepository>(sp => sp.GetRequiredService<SampleDataStore>());
builder.Services.AddSingleton<IFindingRepository>(sp => sp.GetRequiredService<SampleDataStore>());
builder.Services.AddSingleton<IDeviceRepository>(sp => sp.GetRequiredService<SampleDataStore>());
builder.Services.AddScoped<PostureService>();
builder.Services.AddScoped<EndpointService>();

var app = builder.Build();

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

using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Security;

public static class AuthEndpoints
{
    public static void MapPortalAuthEndpoints(this WebApplication app, bool useEntra)
    {
        var auth = app.MapGroup("/authentication");

        auth.MapGet("/login", (string? returnUrl) =>
            useEntra
                ? Results.Challenge(new AuthenticationProperties { RedirectUri = LocalOrRoot(returnUrl) }, [OpenIdConnectDefaults.AuthenticationScheme])
                : Results.LocalRedirect($"~/dev/sign-in?returnUrl={Uri.EscapeDataString(LocalOrRoot(returnUrl))}"))
            .AllowAnonymous();

        // POST with an antiforgery token, so another site can't sign people out.
        auth.MapPost("/logout", async (HttpContext http, IAntiforgery antiforgery) =>
        {
            if (!await antiforgery.IsRequestValidAsync(http)) return Results.BadRequest();
            var actor = UserContext.From(http.User);
            await http.RequestServices.GetRequiredService<Services.AuditTrail>().RecordAsync(AuditActions.SignOut, AuditOutcome.Success,
                $"{actor.Name} signed out", actor.ClientTenantId, actor: actor, ipAddress: http.Connection.RemoteIpAddress?.ToString());
            var props = new AuthenticationProperties { RedirectUri = "/" };
            return useEntra
                ? Results.SignOut(props, [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme])
                : Results.SignOut(props, [CookieAuthenticationDefaults.AuthenticationScheme]);
        }).RequireAuthorization(Policies.SignedIn);

        if (!useEntra && app.Environment.IsDevelopment())
            auth.MapPost("/dev-login", DevSignInAsync).AllowAnonymous();
    }

    /// <summary>
    /// Development only: signs in as a chosen persona with the same claim shape Entra produces, then
    /// goes through the normal invitation binding, so roles and scoping behave as in production.
    /// </summary>
    private static async Task<IResult> DevSignInAsync(HttpContext http, IAntiforgery antiforgery, IPortalUserRepository users,
        ITenantRepository tenants, AuthOptions options)
    {
        if (!await antiforgery.IsRequestValidAsync(http)) return Results.BadRequest();
        var form = await http.Request.ReadFormAsync();
        var persona = form["persona"].ToString();
        var returnUrl = LocalOrRoot(form["returnUrl"]);
        var operatorTenant = options.OperatorTenantId;

        (Guid Tid, Guid Oid, string Upn, string Name, PortalRole? Role, Guid? ClientTenant) who;
        switch (persona)
        {
            case "owner":
                who = (operatorTenant, DevGuid(1), "owner@securepulse.dev", "Dev Owner", PortalRole.Owner, null);
                break;
            case "msp-admin":
                who = (operatorTenant, DevGuid(2), "admin@securepulse.dev", "Dev MSP Admin", PortalRole.MspAdmin, null);
                break;
            case not null when persona.StartsWith("viewer:", StringComparison.Ordinal)
                               && Guid.TryParse(persona["viewer:".Length..], out var tenantId)
                               && await tenants.GetAsync(tenantId) is { } tenant:
                who = (tenant.EntraTenantId, DevGuid(3), $"viewer@{tenant.PrimaryDomain}", $"Dev Viewer ({tenant.DisplayName})", PortalRole.ClientViewer, tenant.Id);
                break;
            case "unassigned":
                who = (Guid.NewGuid(), Guid.NewGuid(), "nobody@elsewhere.dev", "Dev Unassigned", null, null);
                break;
            default:
                return Results.BadRequest();
        }

        if (who.Role is { } role)
        {
            try
            {
                await users.AddAsync(new PortalUser
                {
                    Id = Guid.NewGuid(), Role = role, EntraTenantId = who.Tid, UserPrincipalName = who.Upn,
                    ClientTenantId = who.ClientTenant, CreatedAt = DateTimeOffset.UtcNow, CreatedBy = "Development sign-in"
                });
            }
            catch (DuplicatePortalUserException) { /* reuse the existing dev user and its current role */ }
        }

        var identity = new ClaimsIdentity(
        [
            new Claim("tid", who.Tid.ToString()),
            new Claim("oid", who.Oid.ToString()),
            new Claim("preferred_username", who.Upn),
            new Claim("name", who.Name)
        ], CookieAuthenticationDefaults.AuthenticationScheme, "name", "securepulse:unused-role");
        var principal = new ClaimsPrincipal(identity);

        await AuthSetup.OnSignedInAsync(http, principal);
        await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        return Results.LocalRedirect("~" + returnUrl);
    }

    private static Guid DevGuid(int n) => Guid.Parse($"5ec0be15-0000-4000-8000-{n:D12}");

    /// <summary>Only same-site paths, so a crafted link can't bounce a signed-in user elsewhere.</summary>
    internal static string LocalOrRoot(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl[0] == '/' && (returnUrl.Length == 1 || returnUrl[1] is not ('/' or '\\'))
            ? returnUrl
            : "/";
}

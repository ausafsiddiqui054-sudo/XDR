using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Identity.Web;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Security;

public static class AuthSetup
{
    /// <summary>
    /// Entra ID sign-in (Microsoft.Identity.Web) when AzureAd:ClientId is set. Without it, a
    /// development-only sign-in page stands in; outside Development that's a startup error.
    /// </summary>
    /// <returns>True when Entra sign-in is configured; false for development sign-in.</returns>
    public static bool AddPortalAuthentication(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var useEntra = !string.IsNullOrWhiteSpace(builder.Configuration["AzureAd:ClientId"]);

        if (useEntra)
        {
            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));

            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, o =>
            {
                // Don't let a token's role claims become ASP.NET roles anywhere.
                o.TokenValidationParameters.RoleClaimType = "securepulse:unused-role";
                var inner = o.Events.OnTokenValidated;
                o.Events.OnTokenValidated = async ctx =>
                {
                    if (inner is not null) await inner(ctx);
                    await OnSignedInAsync(ctx.HttpContext, ctx.Principal);
                };
            });
        }
        else if (builder.Environment.IsDevelopment())
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o => o.LoginPath = "/dev/sign-in");
        }
        else
        {
            throw new InvalidOperationException(
                "AzureAd:ClientId is not configured. Portal sign-in requires Microsoft Entra ID outside Development.");
        }

        services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, o =>
        {
            o.AccessDeniedPath = "/access-pending";
            o.ExpireTimeSpan = TimeSpan.FromHours(8);
            o.SlidingExpiration = true;
            o.Cookie.Name = "SecurePulse.Auth";
            o.Cookie.HttpOnly = true;
            o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });

        services.AddAuthorization(o =>
        {
            o.AddPolicy(Policies.SignedIn, p => p.RequireAuthenticatedUser());
            o.AddPolicy(Policies.Member, p => p.RequireAuthenticatedUser()
                .RequireAssertion(c => c.User.HasPortalRole(PortalRole.Owner, PortalRole.MspAdmin, PortalRole.ClientViewer)));
            o.AddPolicy(Policies.Operator, p => p.RequireAuthenticatedUser()
                .RequireAssertion(c => c.User.HasPortalRole(PortalRole.Owner, PortalRole.MspAdmin)));
            o.AddPolicy(Policies.Owner, p => p.RequireAuthenticatedUser()
                .RequireAssertion(c => c.User.HasPortalRole(PortalRole.Owner)));

            // Every endpoint and page needs a portal role unless it says otherwise.
            o.FallbackPolicy = o.GetPolicy(Policies.Member);
        });

        services.AddMemoryCache();
        services.AddTransient<IClaimsTransformation, PortalClaimsTransformation>();
        services.AddCascadingAuthenticationState();
        services.AddScoped<AuthenticationStateProvider, PortalAuthenticationStateProvider>();
        services.AddScoped<IUserContextAccessor, AuthStateUserContextAccessor>();
        var authOptions = builder.Configuration.GetSection("Auth").Get<AuthOptions>() ?? new AuthOptions();
        if (!useEntra && authOptions.OperatorTenantId == Guid.Empty)
            authOptions.OperatorTenantId = AuthOptions.DevelopmentOperatorTenantId;
        services.AddSingleton(authOptions);
        services.AddSingleton(new SignInMode(useEntra));
        services.AddHostedService<BootstrapOwners>();
        return useEntra;
    }

    /// <summary>Strips inbound role claims and binds a pending invitation on first sign-in.</summary>
    internal static async Task OnSignedInAsync(HttpContext http, ClaimsPrincipal? principal)
    {
        if (principal is null) return;
        foreach (var identity in principal.Identities)
            foreach (var claim in identity.Claims.Where(PortalClaims.IsInboundRoleClaim).ToList())
                identity.RemoveClaim(claim);

        if (principal.EntraIdentity() is not { } id) return;
        var users = http.RequestServices.GetRequiredService<IPortalUserRepository>();
        var user = await users.SignInAsync(id.TenantId, id.ObjectId, principal.SignInName(), principal.DisplayName(), DateTimeOffset.UtcNow);

        var log = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SecurePulse.SignIn");
        if (user is null)
            log.LogWarning("Sign-in by {SignInName} ({TenantId}/{ObjectId}) has no portal access", principal.SignInName(), id.TenantId, id.ObjectId);
        else
            log.LogInformation("{SignInName} signed in as {Role}", principal.SignInName(), user.Role);
    }
}

/// <summary>Whether sign-in goes through Microsoft Entra ID or the development persona page.</summary>
public sealed record SignInMode(bool UsesEntra);

/// <summary>Invites Auth:BootstrapOwners as Owners at startup, so a fresh install can be reached.</summary>
internal sealed class BootstrapOwners(AuthOptions options, IPortalUserRepository users, IHostEnvironment env, ILogger<BootstrapOwners> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        if (options.OperatorTenantId == Guid.Empty || options.BootstrapOwners.Length == 0)
        {
            if (!env.IsDevelopment() && !(await users.GetAllAsync(ct)).Any(u => u.Role == PortalRole.Owner))
                logger.LogWarning("No Owner exists and Auth:OperatorTenantId / Auth:BootstrapOwners aren't set, so nobody can manage the portal.");
            return;
        }

        foreach (var upn in options.BootstrapOwners.Where(u => !string.IsNullOrWhiteSpace(u)))
        {
            try
            {
                await users.AddAsync(new PortalUser
                {
                    Id = Guid.NewGuid(),
                    Role = PortalRole.Owner,
                    EntraTenantId = options.OperatorTenantId,
                    UserPrincipalName = upn,
                    CreatedAt = DateTimeOffset.UtcNow,
                    CreatedBy = "Auth:BootstrapOwners"
                }, ct);
                logger.LogInformation("Invited bootstrap Owner {SignInName}", upn);
            }
            catch (DuplicatePortalUserException)
            {
                // Already invited or signed in; leave their current role alone.
            }
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}

namespace SecurePulse.Web.Security;

public sealed class AuthOptions
{
    /// <summary>Stand-in operator tenant for development sign-in.</summary>
    public static readonly Guid DevelopmentOperatorTenantId = Guid.Parse("5ec0be15-0000-4000-8000-00000000d000");

    /// <summary>The MSP's own Entra tenant. Owners and MSP admins sign in from here.</summary>
    public Guid OperatorTenantId { get; set; }

    /// <summary>
    /// Sign-in names in the operator tenant invited as Owner at startup (if not already present),
    /// so the first person can get in and invite everyone else.
    /// </summary>
    public string[] BootstrapOwners { get; set; } = [];
}

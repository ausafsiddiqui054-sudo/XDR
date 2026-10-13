using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;

namespace SecurePulse.Intune;

public static class IntuneServiceCollectionExtensions
{
    public static IServiceCollection AddIntuneDeviceSource(this IServiceCollection services, IntuneOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<ICertificateLoader, StoreCertificateLoader>();
        services.AddSingleton<IGraphTokenProvider, CertificateGraphTokenProvider>();
        // Per-request timeouts are handled by IntuneOptions.Timeout across the whole tenant sync.
        services.AddHttpClient<IDeviceInventorySource, IntuneDeviceSource>(c => c.Timeout = Timeout.InfiniteTimeSpan);
        return services;
    }
}

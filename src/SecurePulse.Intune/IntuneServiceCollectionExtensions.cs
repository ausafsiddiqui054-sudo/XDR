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

    /// <summary>Remote device actions through the separate remediation app. Call after <see cref="AddIntuneDeviceSource"/>.</summary>
    public static IServiceCollection AddIntuneRemoteActions(this IServiceCollection services, RemediationOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<IRemediationTokenProvider, CertificateRemediationTokenProvider>();
        // The sender applies RemediationOptions.SendTimeout itself; no retries, no automatic redirects to other hosts.
        services.AddHttpClient<IDeviceActionSender, IntuneDeviceActionSender>(c => c.Timeout = Timeout.InfiniteTimeSpan)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        return services;
    }
}

using Microsoft.Extensions.Options;

namespace SecurePulse.Worker;

/// <summary>Checks for reported consents every <see cref="OnboardingVerificationOptions.PollInterval"/>.</summary>
public sealed class OnboardingVerificationWorker(
    OnboardingVerificationService verifier,
    IOptions<OnboardingVerificationOptions> options,
    ILogger<OnboardingVerificationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Onboarding verification is disabled (Onboarding:Enabled = false)");
            return;
        }

        using var timer = new PeriodicTimer(options.Value.PollInterval);
        do
        {
            try
            {
                await verifier.VerifyPendingAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Onboarding verification pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

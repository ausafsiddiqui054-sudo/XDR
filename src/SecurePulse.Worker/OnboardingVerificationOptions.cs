namespace SecurePulse.Worker;

public sealed class OnboardingVerificationOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>How often to look for consents waiting to be verified.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// How long after consent to keep retrying. New service principals and permission grants
    /// can take a few minutes to reach every Entra region.
    /// </summary>
    public TimeSpan VerificationWindow { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Thumbprint of the SecurePulse app's certificate in this Worker's certificate store. Becomes
    /// the CredentialReference of every tenant onboarded through admin consent.
    /// </summary>
    public string CertificateThumbprint { get; set; } = string.Empty;
}

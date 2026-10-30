namespace SecurePulse.Worker;

public sealed class PlaybookOptions
{
    /// <summary>Check playbooks after each successful device sync. Off: playbooks propose nothing.</summary>
    public bool Enabled { get; set; } = true;
}

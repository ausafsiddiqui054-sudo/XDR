namespace SecurePulse.Worker;

public sealed class ScanOptions
{
    public bool Enabled { get; set; } = true;

    // Scans:Engines (which engines this Worker runs, default Maester) is read in Program.cs,
    // because it decides which engines are registered.

    /// <summary>How often each onboarded tenant is scanned.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(24);

    /// <summary>How soon a failed scan is tried again (instead of waiting a full interval).</summary>
    public TimeSpan RetryFailedAfter { get; set; } = TimeSpan.FromHours(2);

    /// <summary>How often the Worker looks for due tenants and queued runs.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Scans running at the same time (each is a PowerShell process).</summary>
    public int MaxParallelScans { get; set; } = 2;

    /// <summary>A run still Running after this long is marked failed (its Worker stopped). Keep above every engine's timeout.</summary>
    public TimeSpan StaleAfter { get; set; } = TimeSpan.FromMinutes(45);

    /// <summary>Check the tenant granted every required permission before starting a scan.</summary>
    public bool CheckPermissions { get; set; } = true;
}

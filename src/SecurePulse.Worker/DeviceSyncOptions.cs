namespace SecurePulse.Worker;

public sealed class DeviceSyncOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>Time between sync passes over all tenants.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(4);

    /// <summary>Run a pass as soon as the Worker starts instead of waiting one interval.</summary>
    public bool RunOnStartup { get; set; } = true;

    /// <summary>Tenants synced at the same time.</summary>
    public int MaxParallelTenants { get; set; } = 2;
}

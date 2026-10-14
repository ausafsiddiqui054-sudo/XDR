using MudBlazor;
using SecurePulse.Core.Models;

namespace SecurePulse.Web.Services;

/// <summary>How <see cref="DeviceAction"/>s are shown in the portal.</summary>
public static class DeviceActions
{
    public static string Label(DeviceAction action) => action switch
    {
        DeviceAction.Sync => "Sync",
        DeviceAction.Restart => "Restart",
        DeviceAction.Retire => "Retire",
        _ => "Wipe"
    };

    public static string Icon(DeviceAction action) => action switch
    {
        DeviceAction.Sync => Icons.Material.Rounded.Sync,
        DeviceAction.Restart => Icons.Material.Rounded.RestartAlt,
        DeviceAction.Retire => Icons.Material.Rounded.PersonRemove,
        _ => Icons.Material.Rounded.DeleteForever
    };

    public static string Description(DeviceAction action) => action switch
    {
        DeviceAction.Sync => "Asks the device to check in with Intune now and re-evaluate its compliance policies.",
        DeviceAction.Restart => "Restarts the device. Unsaved work on it is lost.",
        DeviceAction.Retire => "Removes company data, apps and settings, and unenrolls the device. Personal data stays.",
        _ => "Resets the device to factory settings. All data on it is erased."
    };

    /// <summary>Destructive actions need the device name typed to confirm, and an Owner's approval.</summary>
    public static bool IsDestructive(DeviceAction action) => DeviceActionPolicy.IsDestructive(action);
}

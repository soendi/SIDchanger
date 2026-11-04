using Microsoft.Win32;
using SidChanger.Sid;

namespace SidChanger.Core.Registry;

/// <summary>Ein Benutzerprofil laut ProfileList.</summary>
public sealed record ProfileEntry(string Sid, string ImagePath)
{
    public bool Exists => !string.IsNullOrWhiteSpace(ImagePath) && Directory.Exists(ImagePath);
}

/// <summary>Liest die Benutzerprofile aus der ProfileList.</summary>
public static class ProfileLocator
{
    public const string ProfileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>Alle Profile, deren SID zur angegebenen Maschinen-SID gehören.</summary>
    public static IReadOnlyList<ProfileEntry> ReadForMachine(MachineSid machineSid, Action<string>? warn = null)
    {
        var profiles = new List<ProfileEntry>();

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ProfileListPath);
            if (key is null)
            {
                return profiles;
            }

            foreach (var name in key.GetSubKeyNames())
            {
                if (!SidMapping.BelongsToMachine(name, machineSid))
                {
                    continue;
                }

                using var sub = key.OpenSubKey(name);
                if (sub?.GetValue("ProfileImagePath") is not string path || string.IsNullOrWhiteSpace(path))
                {
                    continue;
                }

                profiles.Add(new ProfileEntry(name, path));
            }
        }
        catch (Exception ex)
        {
            warn?.Invoke($"ProfileList nicht lesbar: {ex.Message}");
        }

        return profiles;
    }
}

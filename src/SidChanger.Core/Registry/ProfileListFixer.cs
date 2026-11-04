using System.Security.AccessControl;
using Microsoft.Win32;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;
using SidChanger.Sid;

namespace SidChanger.Core.Registry;

/// <summary>Eine geplante Umbennung eines ProfileList-Schlüssels.</summary>
public sealed record ProfileRename(string OldSid, string NewSid, string ImagePath);

/// <summary>
/// Schlüsselt die ProfileList-Einträge (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-...)
/// von der alten auf die neue Maschinen-SID um, damit Windows die vorhandenen Profile weiter nutzt.
/// </summary>
public static class ProfileListFixer
{
    private const string ProfileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>Ermittelt, welche Einträge umbenannt werden müssten.</summary>
    public static IReadOnlyList<ProfileRename> Plan(MachineSid oldSid, MachineSid newSid, Action<string>? warn = null)
    {
        var plan = new List<ProfileRename>();

        foreach (var entry in ProfileLocator.ReadForMachine(oldSid, warn))
        {
            if (SidMapping.TryMap(entry.Sid, oldSid, newSid, out var newKey))
            {
                plan.Add(new ProfileRename(entry.Sid, newKey, entry.ImagePath));
            }
        }

        return plan;
    }

    /// <summary>Führt die Umbenennung aus. Liefert die Anzahl geänderter Einträge.</summary>
    public static int Apply(
        MachineSid oldSid,
        MachineSid newSid,
        BackupStore backup,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var plan = Plan(oldSid, newSid, warn);
        if (plan.Count == 0)
        {
            log("Keine ProfileList-Einträge mit der alten SID gefunden.");
            return 0;
        }

        using var key = RegistryKeyAccess.OpenWritable(RegistryHive.LocalMachine, ProfileListPath, log, warn);
        if (key is null)
        {
            warn?.Invoke("ProfileList ist nicht schreibbar.");
            return 0;
        }

        var changed = 0;

        foreach (var rename in plan)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var source = key.OpenSubKey(rename.OldSid, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey);
                if (source is null)
                {
                    warn?.Invoke($"ProfileList\\{rename.OldSid} nicht lesbar.");
                    continue;
                }

                BackupKey(source, ProfileListPath + "\\" + rename.OldSid, backup, warn);

                using var target = key.CreateSubKey(rename.NewSid, writable: true);
                if (target is null)
                {
                    warn?.Invoke($"ProfileList\\{rename.NewSid} konnte nicht erstellt werden.");
                    continue;
                }

                CopyValues(source, target);
                CopySubKeys(source, target);

                key.DeleteSubKeyTree(rename.OldSid, throwOnMissingSubKey: false);
                changed++;
                log($"Profil {rename.OldSid} → {rename.NewSid} ({rename.ImagePath})");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"Profil {rename.OldSid} konnte nicht umgeschlüsselt werden: {ex.Message}");
            }
        }

        return changed;
    }

    /// <summary>Sichert alle Werte eines Profilschlüssels (rekursiv), bevor er geändert wird.</summary>
    private static void BackupKey(RegistryKey key, string path, BackupStore backup, Action<string>? warn, int depth = 0)
    {
        if (depth > 8)
        {
            return;
        }

        foreach (var name in key.GetValueNames())
        {
            try
            {
                backup.RecordRegistry(RegistryHive.LocalMachine, path, name,
                    key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames), key.GetValueKind(name));
            }
            catch
            {
                warn?.Invoke($"{path}\\{name} konnte nicht gesichert werden.");
            }
        }

        foreach (var childName in key.GetSubKeyNames())
        {
            try
            {
                using var child = key.OpenSubKey(childName);
                if (child is not null)
                {
                    BackupKey(child, path + "\\" + childName, backup, warn, depth + 1);
                }
            }
            catch
            {
                // ignorieren
            }
        }
    }

    private static void CopyValues(RegistryKey source, RegistryKey target)
    {
        foreach (var name in source.GetValueNames())
        {
            try
            {
                var kind = source.GetValueKind(name);
                var value = source.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (value is not null)
                {
                    target.SetValue(name, value, kind);
                }
            }
            catch
            {
                // einzelne Werte überspringen
            }
        }
    }

    private static void CopySubKeys(RegistryKey source, RegistryKey target, int depth = 0)
    {
        if (depth > 8)
        {
            return;
        }

        foreach (var name in source.GetSubKeyNames())
        {
            try
            {
                using var sourceChild = source.OpenSubKey(name);
                if (sourceChild is null)
                {
                    continue;
                }

                using var targetChild = target.CreateSubKey(name, writable: true);
                if (targetChild is null)
                {
                    continue;
                }

                CopyValues(sourceChild, targetChild);
                CopySubKeys(sourceChild, targetChild, depth + 1);
            }
            catch
            {
                // einzelne Unterschlüssel überspringen
            }
        }
    }
}

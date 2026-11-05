using System.Security.AccessControl;
using Microsoft.Win32;
using SidChanger.Core.Native;
using SidChanger.Sid;

namespace SidChanger.Core.Registry;

/// <summary>Liest die aktuelle lokale Computer-SID aus der SAM-Datenbank.</summary>
public static class MachineSidReader
{
    private const string SamAccountPath = @"SAM\SAM\Domains\Account";
    private const string ProfileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>
    /// Versucht die Maschinen-SID zu ermitteln. Reihenfolge:
    /// 1) SAM-Wert "V" (autoritativ, aber nur als SYSTEM lesbar),
    /// 2) LSA-Richtlinie (funktioniert mit Administratorrechten),
    /// 3) ProfileList (S-1-5-21-Schlüssel), 4) HKU.
    /// </summary>
    public static MachineSid? TryRead(Action<string>? log, Action<string>? warn, out string source)
    {
        source = string.Empty;

        if (TryFromSam(log, out var sid))
        {
            source = @"HKLM\SAM\SAM\Domains\Account\V";
            return sid;
        }

        if (TryFromLsa(log, out sid))
        {
            source = "LSA-Richtlinie (Kontodomäne)";
            return sid;
        }

        if (TryFromProfileList(out sid))
        {
            source = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            log?.Invoke("SID konnte nicht aus der SAM gelesen werden – ermittelt aus ProfileList.");
            return sid;
        }

        if (TryFromLoadedUsers(out sid))
        {
            source = "HKEY_USERS";
            log?.Invoke("SID konnte nicht aus der SAM gelesen werden – ermittelt aus HKEY_USERS.");
            return sid;
        }

        warn?.Invoke("Die lokale Computer-SID konnte nicht ermittelt werden.");
        return null;
    }

    private static bool TryFromSam(Action<string>? log, out MachineSid? sid)
    {
        sid = null;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var key = baseKey.OpenSubKey(SamAccountPath, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey);
            if (key?.GetValue("V") is not byte[] v || v.Length < MachineSid.BinaryLength)
            {
                return false;
            }

            return SidBinary.TryFindDomainSid(v, out sid);
        }
        catch (Exception ex)
        {
            // Normal: die SAM darf nur SYSTEM lesen – auch Administratoren erhalten keinen Zugriff.
            log?.Invoke($"SAM nicht lesbar (Zugriff hat nur SYSTEM): {ex.Message}");
            return false;
        }
    }

    private static bool TryFromLsa(Action<string>? log, out MachineSid? sid)
    {
        sid = null;

        if (!LsaPolicy.TryReadAccountDomainSid(out var value, out var error) || value is null)
        {
            log?.Invoke("SID nicht über die LSA-Richtlinie lesbar: " + error);
            return false;
        }

        if (!MachineSid.TryParse(value, out sid, out _))
        {
            log?.Invoke($"Die LSA-Richtlinie lieferte keine gültige Computer-SID ({value}).");
            return false;
        }

        log?.Invoke("SID über die LSA-Richtlinie gelesen (die SAM ist nur für SYSTEM lesbar).");
        return true;
    }

    private static bool TryFromProfileList(out MachineSid? sid)
    {
        sid = null;

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ProfileListPath);
            if (key is null)
            {
                return false;
            }

            foreach (var name in key.GetSubKeyNames())
            {
                if (!MachineSid.LooksLikeLocalSid(name))
                {
                    continue;
                }

                var parts = name.Split('-');
                if (parts.Length >= 7 &&
                    MachineSid.TryParse(string.Join('-', parts.Take(7)), out var candidate, out _))
                {
                    sid = candidate;
                    return true;
                }
            }
        }
        catch
        {
            // ignorieren – Fallback folgt
        }

        return false;
    }

    private static bool TryFromLoadedUsers(out MachineSid? sid)
    {
        sid = null;

        try
        {
            using var users = Microsoft.Win32.Registry.Users;
            foreach (var name in users.GetSubKeyNames())
            {
                if (!MachineSid.LooksLikeLocalSid(name))
                {
                    continue;
                }

                var parts = name.Split('-');
                if (parts.Length >= 7 &&
                    MachineSid.TryParse(string.Join('-', parts.Take(7)), out var candidate, out _))
                {
                    sid = candidate;
                    return true;
                }
            }
        }
        catch
        {
            // ignorieren
        }

        return false;
    }

    /// <summary>Zählt lokale Konten (RIDs) der Maschinen-SID in der SAM.</summary>
    public static int CountLocalAccounts(MachineSid machineSid, Action<string>? warn)
    {
        var count = 0;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var users = baseKey.OpenSubKey(@"SAM\SAM\Domains\Account\Users", RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey);
            if (users is null)
            {
                return 0;
            }

            foreach (var name in users.GetSubKeyNames())
            {
                if (name.Length == 8 && name.All(Uri.IsHexDigit))
                {
                    count++;
                }
            }
        }
        catch (Exception ex)
        {
            warn?.Invoke($"Konten konnten nicht gezählt werden: {ex.Message}");
        }

        return count;
    }
}

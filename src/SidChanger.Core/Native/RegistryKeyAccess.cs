using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using SidChanger.Core.Native;

namespace SidChanger.Core.Native;

/// <summary>
/// Übernimmt den Besitz geschützter Registrierungsschlüssel (SAM, SECURITY) und
/// erteilt Administratoren sowie SYSTEM Vollzugriff, damit die SID-Werte schreibbar sind.
/// </summary>
public static class RegistryKeyAccess
{
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>Rechte, die zum Schreiben von Werten und Anlegen von Unterschlüsseln nötig sind.</summary>
    internal const RegistryRights WritableRights =
        RegistryRights.ReadKey | RegistryRights.SetValue | RegistryRights.CreateSubKey |
        RegistryRights.EnumerateSubKeys;

    /// <summary>
    /// Öffnet den Schlüssel mit Schreibrechten. Schlägt das fehl, wird zuerst der Besitz
    /// übernommen und die Berechtigung gesetzt. Danach wird erneut geöffnet.
    /// </summary>
    public static RegistryKey? OpenWritable(RegistryHive hive, string subKey, Action<string> log, Action<string>? warn = null)
    {
        var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);

        try
        {
            return baseKey.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, WritableRights);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            warn?.Invoke($"Zugriff auf {hive}\\{subKey} verweigert – Besitz wird übernommen.");
        }

        if (!TakeOwnershipAndGrant(hive, subKey, log, warn))
        {
            baseKey.Dispose();
            return null;
        }

        try
        {
            return baseKey.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, WritableRights);
        }
        catch (Exception ex)
        {
            warn?.Invoke($"Schlüssel {hive}\\{subKey} bleibt nicht schreibbar: {ex.Message}");
            baseKey.Dispose();
            return null;
        }
    }

    /// <summary>Übernimmt Besitz und erteilt Administratoren + SYSTEM Vollzugriff auf einen Schlüssel.</summary>
    public static bool TakeOwnershipAndGrant(RegistryHive hive, string subKey, Action<string> log, Action<string>? warn = null)
    {
        var privilegeErrors = TokenPrivileges.Enable(
            TokenPrivileges.TakeOwnership,
            TokenPrivileges.Restore,
            TokenPrivileges.Backup,
            TokenPrivileges.Security);

        foreach (var error in privilegeErrors)
        {
            warn?.Invoke(error);
        }

        var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);

        try
        {
            // 1) Besitz übernehmen (SeTakeOwnershipPrivilege erlaubt WRITE_OWNER unabhängig von der DACL).
            using (var key = baseKey.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership | RegistryRights.ReadPermissions))
            {
                if (key is null)
                {
                    warn?.Invoke($"Schlüssel {hive}\\{subKey} nicht gefunden.");
                    return false;
                }

                var security = key.GetAccessControl(AccessControlSections.Owner);
                security.SetOwner(Administrators);
                key.SetAccessControl(security);
                log($"Besitz von {hive}\\{subKey} übernommen.");
            }

            // 2) DACL um Vollzugriff für Administratoren und SYSTEM erweitern.
            using (var key = baseKey.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions | RegistryRights.ReadPermissions))
            {
                if (key is null)
                {
                    return false;
                }

                var security = key.GetAccessControl(AccessControlSections.Access);

                foreach (var sid in new[] { Administrators, SystemSid })
                {
                    security.AddAccessRule(new RegistryAccessRule(
                        sid,
                        RegistryRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AccessControlType.Allow));
                }

                key.SetAccessControl(security);
                log($"Vollzugriff für Administratoren/SYSTEM auf {hive}\\{subKey} gesetzt.");
            }

            return true;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"Besitzübernahme für {hive}\\{subKey} fehlgeschlagen: {ex.Message}");
            return false;
        }
        finally
        {
            baseKey.Dispose();
        }
    }

    /// <summary>Übernimmt Besitz und Vollzugriff rekursiv für einen Schlüsselbaum.</summary>
    public static int GrantRecursive(RegistryHive hive, string subKey, Action<string> log, Action<string>? warn, CancellationToken cancellationToken)
    {
        var count = 0;

        if (!TakeOwnershipAndGrant(hive, subKey, log, warn))
        {
            return 0;
        }

        count++;

        string[] children;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions | RegistryRights.EnumerateSubKeys);
            children = key?.GetSubKeyNames() ?? Array.Empty<string>();
        }
        catch (Exception ex)
        {
            warn?.Invoke($"Unterschlüssel von {hive}\\{subKey} nicht lesbar: {ex.Message}");
            return count;
        }

        foreach (var child in children)
        {
            cancellationToken.ThrowIfCancellationRequested();
            count += GrantRecursive(hive, subKey + "\\" + child, log, warn, cancellationToken);
        }

        return count;
    }
}

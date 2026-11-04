using System.ComponentModel;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SidChanger.Core.Native;

namespace SidChanger.Core.Native;

/// <summary>Aktiviert Windows-Privilegien im Token des laufenden Prozesses.</summary>
public static class TokenPrivileges
{
    private static readonly HashSet<string> Enabled = new(StringComparer.OrdinalIgnoreCase);

    public const string Backup = "SeBackupPrivilege";
    public const string Restore = "SeRestorePrivilege";
    public const string TakeOwnership = "SeTakeOwnershipPrivilege";
    public const string Security = "SeSecurityPrivilege";
    public const string Debug = "SeDebugPrivilege";
    public const string Shutdown = "SeShutdownPrivilege";

    /// <summary>
    /// Aktiviert die für die SID-Änderung benötigten Privilegien.
    /// Fehler werden gesammelt zurückgegeben (nicht geworfene Ausnahmen).
    /// </summary>
    public static IReadOnlyList<string> EnableAllRequired()
    {
        return Enable(Backup, Restore, TakeOwnership, Security, Debug, Shutdown);
    }

    /// <summary>Aktiviert die angegebenen Privilegien. Liefert Fehlermeldungen.</summary>
    public static IReadOnlyList<string> Enable(params string[] names)
    {
        var errors = new List<string>();

        foreach (var name in names)
        {
            if (Enabled.Contains(name))
            {
                continue;
            }

            if (EnablePrivilege(name, out var error))
            {
                Enabled.Add(name);
            }
            else
            {
                errors.Add(error);
            }
        }

        return errors;
    }

    private static bool EnablePrivilege(string name, out string error)
    {
        error = string.Empty;

        if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), NativeMethods.TokenAdjustPrivileges | NativeMethods.TokenQuery, out SafeAccessTokenHandle token))
        {
            error = $"OpenProcessToken fehlgeschlagen: {new Win32Exception().Message}";
            return false;
        }

        using (token)
        {
            if (!NativeMethods.LookupPrivilegeValue(null, name, out var luid))
            {
                error = $"Privileg \"{name}\" ist auf diesem System nicht vorhanden.";
                return false;
            }

            var state = new NativeMethods.TokenPrivileges
            {
                PrivilegeCount = 1,
                Privileges = new NativeMethods.LuidAndAttributes
                {
                    Luid = luid,
                    Attributes = NativeMethods.SePrivilegeEnabled,
                },
            };

            if (!NativeMethods.AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero))
            {
                error = $"AdjustTokenPrivileges für \"{name}\" fehlgeschlagen: {new Win32Exception().Message}";
                return false;
            }

            var last = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            if (last != 0)
            {
                error = $"Privileg \"{name}\" konnte nicht aktiviert werden (Fehler {last}).";
                return false;
            }

            return true;
        }
    }

    /// <summary>Prüft, ob der Prozess mit Administratorrechten läuft.</summary>
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

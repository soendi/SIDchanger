using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SidChanger.Core.Native;

/// <summary>
/// Startet den Rechner direkt über die Win32-API neu – ohne externen Prozess und ohne
/// Abhängigkeit von Diensten. Nötig, wenn <c>shutdown.exe</c> den Neustart nicht annimmt.
/// </summary>
public static class NativeReboot
{
    private const uint EwxForce = 0x0004;
    private const uint EwxForceIfHung = 0x0010;
    private const uint EwxReboot = 0x0002;
    private const uint ShutdownReasonUserDefined = 0x80000000;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

    /// <summary>Löst einen sofortigen Neustart aus. Liefert bei Misserfolg die Windows-Fehlermeldung.</summary>
    public static bool TryRestartNow(out string error)
    {
        error = string.Empty;
        TokenPrivileges.Enable(TokenPrivileges.Shutdown);

        if (ExitWindowsEx(EwxReboot | EwxForce | EwxForceIfHung, ShutdownReasonUserDefined))
        {
            return true;
        }

        error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
        return false;
    }
}

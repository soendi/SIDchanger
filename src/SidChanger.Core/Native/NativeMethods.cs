using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SidChanger.Core.Native;

/// <summary>Direkte Windows-API-Aufrufe (P/Invoke), die .NET nicht verwaltet anbietet.</summary>
internal static class NativeMethods
{
    // --- Token / Privilegien -------------------------------------------------
    public const uint TokenAdjustPrivileges = 0x0020;
    public const uint TokenQuery = 0x0008;
    public const uint SePrivilegeEnabled = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        SafeAccessTokenHandle tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    // --- Terminalsitzungen (Abmelden anderer Benutzer) -----------------------
    [StructLayout(LayoutKind.Sequential)]
    public struct WtsSessionInfo
    {
        public uint SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    public const int WtsCurrentSession = 0;
    public const int WtsActive = 0;
    public const int WtsDisconnected = 4;
    public const int WtsUserName = 5;
    public const int WtsDomainName = 7;

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSEnumerateSessions(IntPtr server, uint reserved, uint version, out IntPtr sessions, out uint count);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSLogoffSession(IntPtr server, uint sessionId, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr memory);

    // --- Domänenbeitritt ----------------------------------------------------
    private const int NetSetupUnknownStatus = 0;
    private const int NetSetupUnjoined = 1;
    private const int NetSetupWorkgroup = 2;
    private const int NetSetupDomain = 3;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int NetGetJoinInformation(string? server, out IntPtr nameBuffer, out int bufferType);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);

    /// <summary>Ermittelt Domänenbeitritt und Arbeitsgruppen-/Domänennamen.</summary>
    public static (bool IsDomainJoined, string Name) GetJoinInformation()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            var result = NetGetJoinInformation(null, out buffer, out var type);
            if (result != 0)
            {
                return (false, string.Empty);
            }

            var name = buffer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUni(buffer) ?? string.Empty;
            return (type == NetSetupDomain, name);
        }
        catch
        {
            return (false, string.Empty);
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NetApiBufferFree(buffer);
            }
        }
    }
}

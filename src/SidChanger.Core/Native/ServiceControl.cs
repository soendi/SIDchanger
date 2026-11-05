using System.Runtime.InteropServices;

namespace SidChanger.Core.Native;

/// <summary>Laufzeitzustand eines Dienstes oder Treibers.</summary>
public enum ServiceRunState
{
    Unknown = 0,
    NotInstalled = 1,
    Stopped = 2,
    StartPending = 3,
    StopPending = 4,
    Running = 5,
    ContinuePending = 6,
    PausePending = 7,
    Paused = 8,
}

/// <summary>
/// Steuerung von Diensten und Treibern über den Windows-Dienst-Manager (SCM).
/// Damit kann das Programm einen Treiber selbst anhalten und deaktivieren, statt den
/// Benutzer in die Dienste-Verwaltung zu schicken.
/// </summary>
public static class ServiceControl
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceCannotAcceptCtrl = 1052;
    private const int ErrorServiceDisabled = 1058;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorAccessDenied = 5;

    /// <summary>Starttyp "deaktiviert" (HKLM\SYSTEM\CurrentControlSet\Services\&lt;Dienst&gt;\Start).</summary>
    public const int StartTypeDisabled = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")]
    private static extern IntPtr OpenScManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr service, uint control, out ServiceStatusProcess status);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "StartServiceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(IntPtr service, int argumentCount, IntPtr[]? arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service,
        int infoLevel,
        out ServiceStatusProcess buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ChangeServiceConfigW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(
        IntPtr service,
        uint serviceType,
        uint startType,
        uint errorControl,
        string? binaryPathName,
        string? loadOrderGroup,
        IntPtr tagId,
        string? dependencies,
        string? serviceStartName,
        string? password,
        string? displayName);

    /// <summary>Liest den Laufzeitzustand eines Dienstes bzw. Treibers.</summary>
    public static ServiceRunState GetState(string serviceName, out string detail)
    {
        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            detail = $"Dienst-Manager konnte nicht geöffnet werden: {LastError()}";
            return ServiceRunState.Unknown;
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                detail = error == ErrorServiceDoesNotExist
                    ? $"Der Dienst \"{serviceName}\" ist nicht vorhanden."
                    : $"Der Dienst \"{serviceName}\" konnte nicht geöffnet werden: {DescribeError(error)}";

                return error == ErrorServiceDoesNotExist ? ServiceRunState.NotInstalled : ServiceRunState.Unknown;
            }

            try
            {
                var state = QueryState(service, out var statusDetail);
                detail = statusDetail;
                return state;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>Hält einen Dienst bzw. Treiber an und wartet, bis er gestoppt ist.</summary>
    public static bool TryStop(string serviceName, TimeSpan timeout, out string detail)
    {
        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            detail = $"Dienst-Manager konnte nicht geöffnet werden: {LastError()}";
            return false;
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceStop | ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                detail = $"Der Dienst \"{serviceName}\" konnte nicht zum Anhalten geöffnet werden: {LastError()}";
                return false;
            }

            try
            {
                var before = QueryState(service, out _);
                if (before == ServiceRunState.Stopped)
                {
                    detail = "Der Dienst war bereits gestoppt.";
                    return true;
                }

                if (!ControlService(service, ServiceControlStop, out var status))
                {
                    var error = Marshal.GetLastWin32Error();
                    detail = error == ErrorServiceCannotAcceptCtrl
                        ? $"Der Dienst nimmt keinen Anhalten-Befehl an (Zustand {status.CurrentState})."
                        : $"Anhalten abgelehnt: {DescribeError(error)}";
                    return false;
                }

                var deadline = DateTime.UtcNow + timeout;
                while (DateTime.UtcNow < deadline)
                {
                    if (QueryState(service, out _) == ServiceRunState.Stopped)
                    {
                        detail = "Der Dienst ist gestoppt.";
                        return true;
                    }

                    Thread.Sleep(200);
                }

                detail = $"Der Dienst wurde nach {timeout.TotalSeconds:0} Sekunden nicht gestoppt.";
                return false;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>Startet einen Dienst bzw. Treiber und wartet, bis er läuft.</summary>
    public static bool TryStart(string serviceName, TimeSpan timeout, out string detail)
    {
        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            detail = $"Dienst-Manager konnte nicht geöffnet werden: {LastError()}";
            return false;
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceStart | ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                detail = error == ErrorServiceDoesNotExist
                    ? $"Der Dienst \"{serviceName}\" ist nicht vorhanden."
                    : $"Der Dienst \"{serviceName}\" konnte nicht zum Starten geöffnet werden: {DescribeError(error)}";
                return false;
            }

            try
            {
                if (QueryState(service, out _) == ServiceRunState.Running)
                {
                    detail = "Der Dienst lief bereits.";
                    return true;
                }

                if (!StartService(service, 0, null))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ErrorServiceAlreadyRunning)
                    {
                        detail = "Der Dienst lief bereits.";
                        return true;
                    }

                    detail = error == ErrorServiceDisabled
                        ? "Der Dienst ist auf \"deaktiviert\" gesetzt und kann nicht gestartet werden."
                        : $"Starten abgelehnt: {DescribeError(error)}";
                    return false;
                }

                var deadline = DateTime.UtcNow + timeout;
                while (DateTime.UtcNow < deadline)
                {
                    var state = QueryState(service, out _);
                    if (state == ServiceRunState.Running)
                    {
                        detail = "Der Dienst läuft.";
                        return true;
                    }

                    Thread.Sleep(200);
                }

                detail = $"Der Dienst lief nach {timeout.TotalSeconds:0} Sekunden nicht an.";
                return false;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>Setzt den Starttyp eines Dienstes (z. B. 4 = deaktiviert).</summary>
    public static bool TrySetStartType(string serviceName, uint startType, out string detail)
    {
        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            detail = $"Dienst-Manager konnte nicht geöffnet werden: {LastError()}";
            return false;
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceChangeConfig);
            if (service == IntPtr.Zero)
            {
                detail = $"Der Dienst \"{serviceName}\" konnte nicht zum Konfigurieren geöffnet werden: {LastError()}";
                return false;
            }

            try
            {
                if (!ChangeServiceConfig(service, ServiceNoChange, startType, ServiceNoChange,
                        null, null, IntPtr.Zero, null, null, null, null))
                {
                    detail = $"Starttyp konnte nicht gesetzt werden: {LastError()}";
                    return false;
                }

                detail = $"Starttyp auf {startType} gesetzt.";
                return true;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>Liest den gespeicherten Starttyp aus der Registrierung (4 = deaktiviert).</summary>
    public static int? ReadStartType(string serviceName)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");

            return key?.GetValue("Start") is { } value ? Convert.ToInt32(value) : null;
        }
        catch
        {
            return null;
        }
    }

    private static ServiceRunState QueryState(IntPtr service, out string detail)
    {
        var size = (uint)Marshal.SizeOf<ServiceStatusProcess>();

        if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out var status, size, out _))
        {
            detail = "Zustand konnte nicht gelesen werden: " + LastError();
            return ServiceRunState.Unknown;
        }

        var state = status.CurrentState switch
        {
            1 => ServiceRunState.Stopped,
            2 => ServiceRunState.StartPending,
            3 => ServiceRunState.StopPending,
            4 => ServiceRunState.Running,
            5 => ServiceRunState.ContinuePending,
            6 => ServiceRunState.PausePending,
            7 => ServiceRunState.Paused,
            _ => ServiceRunState.Unknown,
        };

        detail = $"Zustand {status.CurrentState}";
        return state;
    }

    private static string LastError() => DescribeError(Marshal.GetLastWin32Error());

    private static string DescribeError(int error) => error switch
    {
        ErrorAccessDenied => "Zugriff verweigert (Administratorrechte erforderlich).",
        ErrorServiceCannotAcceptCtrl => "Der Dienst nimmt diesen Befehl im laufenden Betrieb nicht an.",
        ErrorServiceDoesNotExist => "Der Dienst ist nicht vorhanden.",
        ErrorServiceDisabled => "Der Dienst ist deaktiviert.",
        _ => $"Windows-Fehler {error}.",
    };
}

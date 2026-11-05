using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SidChanger.Core.Native;

/// <summary>Ergebnis eines Wiederherstellungspunkts.</summary>
public sealed record RestorePointOutcome(bool Created, long SequenceNumber, string Message);

/// <summary>
/// Legt über die Windows-Systemwiederherstellung (<c>srclient.dll</c>) einen
/// Wiederherstellungspunkt an. Ist sie abgeschaltet oder nicht vorhanden, meldet das
/// Programm das ehrlich, statt einen Punkt vorzutäuschen.
/// </summary>
public static class SystemRestore
{
    private const int BeginSystemChange = 100;
    private const int EndSystemChange = 101;
    private const int ModifySettings = 12;
    private const int MaxDescriptionLength = 256;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RestorePointInfo
    {
        public int EventType;
        public int RestorePointType;
        public long SequenceNumber;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxDescriptionLength)]
        public string Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StateManagerStatus
    {
        public int Status;
        public long SequenceNumber;
    }

    [DllImport("srclient.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SRSetRestorePointW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SrSetRestorePoint(ref RestorePointInfo info, ref StateManagerStatus status);

    /// <summary>Ist die Systemwiederherstellung abgeschaltet (Richtlinie oder Systemeinstellung)?</summary>
    public static bool IsDisabled()
    {
        try
        {
            using (var policy = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                       @"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"))
            {
                if (policy?.GetValue("DisableSR") is { } policyValue && Convert.ToInt32(policyValue) == 1)
                {
                    return true;
                }
            }

            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore");
            return key?.GetValue("DisableSR") is { } value && Convert.ToInt32(value) == 1;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Beginnt einen Wiederherstellungspunkt. Der Rückgabewert enthält die Sequenznummer.</summary>
    public static RestorePointOutcome Create(string description, Action<string>? info, Action<string>? warn)
    {
        if (IsDisabled())
        {
            const string message =
                "Die Systemwiederherstellung ist auf diesem Rechner abgeschaltet – es wurde kein " +
                "Wiederherstellungspunkt angelegt. Bitte vorher einen Wiederherstellungspunkt von Hand anlegen.";
            warn?.Invoke(message);
            return new RestorePointOutcome(false, 0, message);
        }

        return SetPoint(BeginSystemChange, description, info, warn);
    }

    /// <summary>Schließt einen begonnenen Wiederherstellungspunkt ab.</summary>
    public static RestorePointOutcome Finish(long sequenceNumber, Action<string>? info, Action<string>? warn)
    {
        if (sequenceNumber <= 0)
        {
            return new RestorePointOutcome(true, 0, "Kein offener Wiederherstellungspunkt.");
        }

        return SetPoint(EndSystemChange, string.Empty, info, warn, sequenceNumber);
    }

    private static RestorePointOutcome SetPoint(
        int eventType,
        string description,
        Action<string>? info,
        Action<string>? warn,
        long sequenceNumber = 0)
    {
        var text = description.Length > MaxDescriptionLength - 1
            ? description[..(MaxDescriptionLength - 1)]
            : description;

        var request = new RestorePointInfo
        {
            EventType = eventType,
            RestorePointType = ModifySettings,
            SequenceNumber = sequenceNumber,
            Description = text,
        };

        var status = default(StateManagerStatus);

        try
        {
            if (!SrSetRestorePoint(ref request, ref status))
            {
                var message = DescribeError(Marshal.GetLastWin32Error());
                warn?.Invoke(message);
                return new RestorePointOutcome(false, 0, message);
            }
        }
        catch (DllNotFoundException)
        {
            const string message =
                "Die Systemwiederherstellung (srclient.dll) ist auf diesem System nicht vorhanden – " +
                "es wurde kein Wiederherstellungspunkt angelegt.";
            warn?.Invoke(message);
            return new RestorePointOutcome(false, 0, message);
        }
        catch (EntryPointNotFoundException)
        {
            const string message =
                "Dieses Windows stellt die Funktion für Wiederherstellungspunkte nicht bereit – " +
                "es wurde kein Wiederherstellungspunkt angelegt.";
            warn?.Invoke(message);
            return new RestorePointOutcome(false, 0, message);
        }
        catch (Exception ex)
        {
            var message = "Wiederherstellungspunkt konnte nicht angelegt werden: " + ex.Message;
            warn?.Invoke(message);
            return new RestorePointOutcome(false, 0, message);
        }

        if (status.Status != 0)
        {
            var message = $"Windows hat den Wiederherstellungspunkt abgelehnt (Status {status.Status}).";
            warn?.Invoke(message);
            return new RestorePointOutcome(false, 0, message);
        }

        if (eventType == EndSystemChange)
        {
            info?.Invoke("Wiederherstellungspunkt abgeschlossen.");
            return new RestorePointOutcome(true, sequenceNumber, "Wiederherstellungspunkt abgeschlossen.");
        }

        var created = $"Wiederherstellungspunkt angelegt (Sequenz {status.SequenceNumber}).";
        info?.Invoke(created);
        return new RestorePointOutcome(true, status.SequenceNumber, created);
    }

    private static string DescribeError(int error) => error switch
    {
        5 => "Zugriff verweigert – der Wiederherstellungspunkt braucht Administratorrechte.",
        50 => "Die Systemwiederherstellung wird von diesem Windows nicht unterstützt – " +
              "es wurde kein Wiederherstellungspunkt angelegt.",
        1058 => "Der Dienst der Systemwiederherstellung ist nicht gestartet – es wurde kein " +
                "Wiederherstellungspunkt angelegt.",
        _ => $"Windows hat keinen Wiederherstellungspunkt angelegt (Fehler {error}).",
    };
}

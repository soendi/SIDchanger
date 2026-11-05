using Microsoft.Win32;

namespace SidChanger.Core.Operations;

/// <summary>Was beim Vorbereiten der Maschine zurückgesetzt werden soll.</summary>
public sealed record PrepareOptions(
    bool SuspendBitLocker,
    bool DisableDefender,
    bool DisableUcpd,
    bool StopServices,
    bool RestartAfterLogin,
    int RebootCount = 3);

/// <summary>Ergebnis der Vorbereitung.</summary>
public sealed record PrepareResult(bool Success, bool RebootRequired, string Summary, IReadOnlyList<string> Steps);

/// <summary>
/// „Maschine vorbereiten": setzt die Elemente zurück, die eine SID-Änderung blockieren
/// (BitLocker, Defender-Echtzeitschutz, UCPD-Treiber, laufende Dienste) und sorgt dafür,
/// dass das Programm nach dem Neustart automatisch wieder offen ist.
/// </summary>
public static class SystemPreparation
{
    /// <summary>Führt alle gewählten Vorbereitungsschritte aus.</summary>
    public static PrepareResult Run(PrepareOptions options, Action<string> log, Action<string>? warn)
    {
        var steps = new List<string>();
        var problems = new List<string>();

        if (options.SuspendBitLocker)
        {
            var result = SystemFixes.SuspendBitLocker(options.RebootCount, log, warn);
            steps.Add(result.Summary);
            if (!result.Success)
            {
                problems.Add(result.Summary);
            }
        }

        if (options.DisableDefender)
        {
            var result = SystemFixes.DisableDefender(log, warn);
            steps.Add(result.Summary);
            if (!result.Success)
            {
                problems.Add(result.Summary);
            }
        }

        if (options.DisableUcpd)
        {
            var outcome = UcpdController.StopAndDisable(log, warn);
            steps.Add(outcome.Message);

            if (!outcome.Stopped && !outcome.Disabled)
            {
                problems.Add(outcome.Message);
            }
        }

        if (options.StopServices)
        {
            var result = SystemFixes.StopAllServices(log, warn);
            steps.Add(result.Summary);
            if (!result.Success)
            {
                problems.Add(result.Summary);
            }
        }

        if (options.RestartAfterLogin)
        {
            TryScheduleSelfRestart(log, warn);
        }

        var summary = problems.Count == 0
            ? "Die Maschine ist vorbereitet. Bitte jetzt neu starten – danach sind BitLocker, Defender und UCPD " +
              "nicht mehr im Weg und die SID-Änderung kann laufen."
            : "Vorbereitung mit Hinweisen beendet:\n\n• " + string.Join("\n• ", problems) +
              "\n\nBitte trotzdem neu starten und die Vorabprüfung danach erneut ansehen.";

        return new PrepareResult(problems.Count == 0, true, summary, steps);
    }

    /// <summary>Startet den Rechner in der angegebenen Zeit neu.</summary>
    public static void ScheduleReboot(int seconds, Action<string> log)
    {
        log($"Neustart in {seconds} Sekunden angefordert.");
        Shell.Run("shutdown.exe", $"/r /t {seconds} /f /c \"SID-Wechsler: Neustart nach der Vorbereitung\"", 20_000);
    }

    /// <summary>Trägt das Programm für die nächste Anmeldung ein (RunOnce).</summary>
    public static bool TryScheduleSelfRestart(Action<string> log, Action<string>? warn)
    {
        var path = Environment.ProcessPath;

        if (string.IsNullOrEmpty(path))
        {
            warn?.Invoke("Der Programmpfad ist unbekannt – Autostart nach dem Neustart nicht möglich.");
            return false;
        }

        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce");

            if (key is null)
            {
                warn?.Invoke("Autostart konnte nicht eingetragen werden (RunOnce nicht verfügbar).");
                return false;
            }

            key.SetValue("SidWechsler", "\"" + path + "\"");
            log("Das Programm startet nach der nächsten Anmeldung automatisch wieder.");
            return true;
        }
        catch (Exception ex)
        {
            warn?.Invoke("Autostart konnte nicht eingetragen werden: " + ex.Message);
            return false;
        }
    }
}

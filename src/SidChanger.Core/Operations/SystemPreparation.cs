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

/// <summary>Ein Punkt, den das Vorbereiten der Maschine ausführt.</summary>
public sealed record PrepareStepInfo(string Title, string Description);

/// <summary>
/// „Maschine vorbereiten": setzt die Elemente zurück, die eine SID-Änderung blockieren
/// (BitLocker, Defender-Echtzeitschutz, UCPD-Treiber, laufende Dienste) und sorgt dafür,
/// dass das Programm nach dem Neustart automatisch wieder offen ist.
/// </summary>
public static class SystemPreparation
{
    /// <summary>
    /// Beschreibt die Punkte, die <see cref="Run"/> ausführen wird – damit die Bestätigung
    /// im Programm genau das anzeigt, was danach wirklich passiert.
    /// </summary>
    public static IReadOnlyList<PrepareStepInfo> Describe(PrepareOptions options)
    {
        var steps = new List<PrepareStepInfo>();

        if (options.SuspendBitLocker)
        {
            steps.Add(new PrepareStepInfo("BitLocker für die nächsten Neustarts aussetzen",
                $"Der Schutz des Systemlaufwerks wird für die nächsten {Math.Clamp(options.RebootCount, 1, 15)} " +
                "Neustarts ausgesetzt. Entschlüsselt wird nichts; danach schaltet sich der Schutz automatisch wieder ein."));
        }

        if (options.DisableDefender)
        {
            steps.Add(new PrepareStepInfo("Defender-Echtzeitschutz abschalten",
                "Echtzeit-, Verhaltens-, Skript- und Archivprüfung werden abgeschaltet und per Richtlinie deaktiviert. " +
                "Blockiert der Manipulationsschutz von Windows, meldet das Programm das anschließend ehrlich."));
        }

        if (options.DisableUcpd)
        {
            steps.Add(new PrepareStepInfo("UCPD-Treiber anhalten und deaktivieren",
                "Der User Choice Protection Driver wird angehalten und auf „deaktiviert“ gesetzt, damit er keine " +
                "Registrierungsänderungen mehr blockiert."));
        }

        if (options.StopServices)
        {
            steps.Add(new PrepareStepInfo("Laufende Dienste beenden",
                "Alle laufenden Dienste außer den kritischen Systemdiensten werden beendet. Nach dem Neustart starten " +
                "sie je nach Starttyp wieder; die vom Programm beendeten Dienste werden am Ende der SID-Änderung erneut " +
                "gestartet. Startmenü und Taskleiste bleiben bedienbar: die Dienste dafür (u. a. StateRepository und " +
                "AppXSvc) werden nicht angehalten."));
        }

        if (options.RestartAfterLogin)
        {
            steps.Add(new PrepareStepInfo("Programm nach der Anmeldung wieder öffnen",
                "Das Programm wird per RunOnce für die nächste Anmeldung eingetragen, damit es nach dem Neustart " +
                "automatisch wieder offen ist."));
        }

        return steps;
    }

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

    /// <summary>
    /// Startet den Rechner in der angegebenen Zeit neu und meldet, ob Windows den Auftrag
    /// tatsächlich angenommen hat (inklusive Rückfallweg über die Windows-API).
    /// </summary>
    public static (bool Success, string Detail) ScheduleReboot(int seconds, Action<string> log, Action<string>? warn = null)
    {
        return RebootService.RequestRestart(seconds, "SID-Wechsler: Neustart nach der Vorbereitung", log, warn);
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

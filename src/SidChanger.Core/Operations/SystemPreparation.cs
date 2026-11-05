using Microsoft.Win32;
using SidChanger.Sid;

namespace SidChanger.Core.Operations;

/// <summary>Was beim Vorbereiten der Maschine zurückgesetzt werden soll.</summary>
public sealed record PrepareOptions(
    bool SuspendBitLocker,
    bool DisableDefender,
    bool DisableUcpd,
    bool StopServices,
    bool RestartAfterLogin,
    int RebootCount = 3);

/// <summary>Ergebnis eines einzelnen Vorbereitungsschritts – für das Fortschrittsfenster.</summary>
public sealed record PrepareStepResult(string Title, StepStatus Status, string Message);

/// <summary>Ergebnis der Vorbereitung.</summary>
public sealed record PrepareResult(
    bool Success,
    bool RebootRequired,
    string Summary,
    IReadOnlyList<string> Steps,
    IReadOnlyList<PrepareStepResult> StepResults);

/// <summary>Ein Punkt, den das Vorbereiten der Maschine ausführt.</summary>
public sealed record PrepareStepInfo(string Title, string Description, string? DurationHint = null);

/// <summary>
/// „Maschine vorbereiten": setzt die Elemente zurück, die eine SID-Änderung blockieren
/// (BitLocker, Defender-Echtzeitschutz, UCPD-Treiber, laufende Dienste) und sorgt dafür,
/// dass das Programm nach dem Neustart automatisch wieder offen ist.
/// </summary>
public static class SystemPreparation
{
    /// <summary>Titel der Vorbereitungsschritte – von <see cref="Describe"/> und <see cref="Run"/> gemeinsam genutzt.</summary>
    private static class StepTitles
    {
        public const string BitLocker = "BitLocker für die nächsten Neustarts aussetzen";
        public const string Defender = "Defender-Echtzeitschutz abschalten";
        public const string Ucpd = "UCPD-Treiber anhalten und deaktivieren";
        public const string Services = "Laufende Dienste beenden";
        public const string RunOnce = "Programm nach der Anmeldung wieder öffnen";
    }

    /// <summary>
    /// Beschreibt die Punkte, die <see cref="Run"/> ausführen wird – damit die Bestätigung
    /// im Programm genau das anzeigt, was danach wirklich passiert.
    /// </summary>
    public static IReadOnlyList<PrepareStepInfo> Describe(PrepareOptions options)
    {
        var steps = new List<PrepareStepInfo>();

        if (options.SuspendBitLocker)
        {
            steps.Add(new PrepareStepInfo(StepTitles.BitLocker,
                $"Der Schutz des Systemlaufwerks wird für die nächsten {Math.Clamp(options.RebootCount, 1, 15)} " +
                "Neustarts ausgesetzt. Entschlüsselt wird nichts; danach schaltet sich der Schutz automatisch wieder ein."));
        }

        if (options.DisableDefender)
        {
            steps.Add(new PrepareStepInfo(StepTitles.Defender,
                "Echtzeit-, Verhaltens-, Skript- und Archivprüfung werden abgeschaltet und per Richtlinie deaktiviert. " +
                "Blockiert der Manipulationsschutz von Windows, meldet das Programm das anschließend ehrlich.",
                "Kann einen Moment dauern, bis Windows die Richtlinie übernommen hat."));
        }

        if (options.DisableUcpd)
        {
            steps.Add(new PrepareStepInfo(StepTitles.Ucpd,
                "Der User Choice Protection Driver wird angehalten und auf „deaktiviert“ gesetzt, damit er keine " +
                "Registrierungsänderungen mehr blockiert.",
                "Kann einen Moment dauern, wenn der Treiber noch in Benutzung ist."));
        }

        if (options.StopServices)
        {
            steps.Add(new PrepareStepInfo(StepTitles.Services,
                "Alle laufenden Dienste außer den kritischen Systemdiensten werden beendet. Nach dem Neustart starten " +
                "sie je nach Starttyp wieder; die vom Programm beendeten Dienste werden am Ende der SID-Änderung erneut " +
                "gestartet. Startmenü und Taskleiste bleiben bedienbar: die Dienste dafür (u. a. StateRepository und " +
                "AppXSvc) werden nicht angehalten.",
                "Die Dienste werden nacheinander beendet – das kann ein bis zwei Minuten dauern."));
        }

        if (options.RestartAfterLogin)
        {
            steps.Add(new PrepareStepInfo(StepTitles.RunOnce,
                "Das Programm wird per RunOnce für die nächste Anmeldung eingetragen, damit es nach dem Neustart " +
                "automatisch wieder offen ist."));
        }

        return steps;
    }

    /// <summary>Führt alle gewählten Vorbereitungsschritte aus.</summary>
    /// <param name="stepStarted">Meldet den Titel des Schritts, der gerade beginnt.</param>
    public static PrepareResult Run(
        PrepareOptions options,
        Action<string> log,
        Action<string>? warn,
        Action<string>? stepStarted = null)
    {
        var steps = new List<string>();
        var stepResults = new List<PrepareStepResult>();
        var problems = new List<string>();

        // Jeder Schritt landet doppelt: als Protokollzeile und als Ergebnis für das
        // Fortschrittsfenster. Als „Problem“ zählen nur echte Fehler, keine Hinweise.
        void Add(string title, StepStatus status, string message)
        {
            steps.Add(message);
            stepResults.Add(new PrepareStepResult(title, status, message));

            if (status == StepStatus.Error)
            {
                problems.Add(message);
            }
        }

        if (options.SuspendBitLocker)
        {
            stepStarted?.Invoke(StepTitles.BitLocker);
            var result = SystemFixes.SuspendBitLocker(options.RebootCount, log, warn);
            Add(StepTitles.BitLocker, result.Success ? StepStatus.Ok : StepStatus.Error, result.Summary);
        }

        if (options.DisableDefender)
        {
            stepStarted?.Invoke(StepTitles.Defender);
            var result = SystemFixes.DisableDefender(log, warn);
            Add(StepTitles.Defender, result.Success ? StepStatus.Ok : StepStatus.Error, result.Summary);
        }

        if (options.DisableUcpd)
        {
            stepStarted?.Invoke(StepTitles.Ucpd);
            var outcome = UcpdController.StopAndDisable(log, warn);

            var status = outcome.Stopped && outcome.Disabled
                ? StepStatus.Ok
                : outcome.Stopped || outcome.Disabled
                    ? StepStatus.Warning
                    : StepStatus.Error;

            Add(StepTitles.Ucpd, status, outcome.Message);
        }

        if (options.StopServices)
        {
            stepStarted?.Invoke(StepTitles.Services);
            var result = SystemFixes.StopAllServices(log, warn);
            Add(StepTitles.Services, result.Success ? StepStatus.Ok : StepStatus.Error, result.Summary);
        }

        if (options.RestartAfterLogin)
        {
            stepStarted?.Invoke(StepTitles.RunOnce);

            var details = new List<string>();
            var scheduled = TryScheduleSelfRestart(log, message =>
            {
                details.Add(message);
                warn?.Invoke(message);
            });

            Add(StepTitles.RunOnce,
                scheduled ? StepStatus.Ok : StepStatus.Warning,
                scheduled
                    ? "Das Programm startet nach der nächsten Anmeldung automatisch wieder."
                    : string.Join(" ", details));
        }

        var summary = problems.Count == 0
            ? "Die Maschine ist vorbereitet. Bitte jetzt neu starten – danach sind BitLocker, Defender und UCPD " +
              "nicht mehr im Weg und die SID-Änderung kann laufen."
            : "Vorbereitung mit Hinweisen beendet:\n\n• " + string.Join("\n• ", problems) +
              "\n\nBitte trotzdem neu starten und die Vorabprüfung danach erneut ansehen.";

        return new PrepareResult(problems.Count == 0, true, summary, steps, stepResults);
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

using System.Diagnostics;
using SidChanger.Core.Native;

namespace SidChanger.Core.Operations;

/// <summary>
/// Fordert einen Neustart an und prüft, ob Windows ihn tatsächlich annimmt.
/// Bisher wurde das Ergebnis von <c>shutdown.exe</c> ignoriert – lehnte Windows den Neustart ab,
/// meldete das Programm trotzdem „Neustart angefordert“ und es passierte nichts.
/// </summary>
public static class RebootService
{
    /// <summary>Fordert einen Neustart mit Vorlauf an.</summary>
    /// <param name="seconds">Vorlauf in Sekunden (0 = sofort).</param>
    /// <param name="comment">Kommentar, den Windows im Hinweisdialog anzeigt.</param>
    /// <param name="log">Protokoll für den normalen Ablauf.</param>
    /// <param name="warn">Protokoll für Probleme (optional).</param>
    /// <param name="watchdogSeconds">Zusätzliche Frist, nach der der Neustart erzwungen wird.</param>
    public static (bool Success, string Detail) RequestRestart(
        int seconds,
        string comment,
        Action<string> log,
        Action<string>? warn = null,
        int watchdogSeconds = 40)
    {
        var delay = Math.Clamp(seconds, 0, 600);
        var (exitCode, output) = Shell.Run("shutdown.exe",
            $"/r /t {delay} /f /c \"{comment}\"", 30_000);

        if (exitCode == 0)
        {
            log(delay == 0
                ? "Neustart ausgelöst."
                : $"Neustart in {delay} Sekunden angefordert.");

            ArmWatchdog(delay + watchdogSeconds, log, warn);

            return (true, delay == 0
                ? "Der Rechner startet jetzt neu."
                : $"Der Rechner startet in {delay} Sekunden neu.");
        }

        var reason = string.IsNullOrWhiteSpace(output)
            ? $"Exitcode {exitCode}"
            : $"Exitcode {exitCode}: {output}";

        warn?.Invoke("shutdown.exe hat den Neustart nicht angenommen – " + reason);
        log("Ich versuche den Neustart direkt über die Windows-API ...");

        if (NativeReboot.TryRestartNow(out var error))
        {
            log("Sofortiger Neustart über die Windows-API ausgelöst.");
            return (true, "Der geplante Neustart war nicht möglich – der Rechner startet jetzt sofort neu.");
        }

        warn?.Invoke("Neustart konnte nicht ausgelöst werden: " + error);

        return (false,
            "Der Rechner konnte nicht neu gestartet werden: " + error + "\n\n" +
            "Drücke Strg+Alt+Entf und wähle rechts unten „Neu starten“ – das funktioniert auch dann, " +
            "wenn Startmenü und Taskleiste nicht mehr reagieren.");
    }

    /// <summary>
    /// Sicherheitsnetz: Windows kann einen angekündigten Neustart später verwerfen, ohne dass
    /// <c>shutdown.exe</c> das meldet. Dann erzwingt dieser Hintergrundprozess ihn nach Ablauf der Frist.
    /// </summary>
    private static void ArmWatchdog(int seconds, Action<string> log, Action<string>? warn)
    {
        var wait = Math.Clamp(seconds, 15, 900);

        try
        {
            var info = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c ping -n {wait + 1} 127.0.0.1 >nul & shutdown.exe /r /t 0 /f /c \"SID-Wechsler: Neustart erzwungen\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            Process.Start(info)?.Dispose();
            log($"Sicherheitsnetz aktiv: beginnt der Neustart nicht, wird er nach {wait} Sekunden erzwungen.");
        }
        catch (Exception ex)
        {
            warn?.Invoke("Sicherheitsnetz für den Neustart konnte nicht gestartet werden: " + ex.Message);
        }
    }
}

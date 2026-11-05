using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using SidChanger.Core.Native;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.Core.Operations;

/// <summary>Art des Sprungziels einer Vorabprüfung.</summary>
public enum PreflightActionKind
{
    /// <summary>Datei, Protokollhandler oder URI über die Shell öffnen (z. B. ms-settings:...).</summary>
    Shell = 0,

    /// <summary>Das Programm selbst mit Administratorrechten neu starten.</summary>
    RestartElevated = 1,

    /// <summary>Der UCPD-Treiber wird direkt im Programm angehalten und deaktiviert.</summary>
    StopUcpd = 2,

    /// <summary>Ein Systemeingriff aus <see cref="SystemFix"/> wird direkt ausgeführt.</summary>
    RunFix = 3,
}

/// <summary>Ein Sprungziel, das direkt zur betroffenen Windows-Einstellung führt.</summary>
public sealed record PreflightAction(
    string Label,
    PreflightActionKind Kind,
    string FileName,
    string Arguments = "",
    SystemFix? Fix = null)
{
    public static PreflightAction Open(string label, string fileName, string arguments = "") =>
        new(label, PreflightActionKind.Shell, fileName, arguments);

    public static PreflightAction RestartAsAdministrator() =>
        new("Als Administrator neu starten", PreflightActionKind.RestartElevated, string.Empty);

    public static PreflightAction StopUcpdDriver() =>
        new("UCPD jetzt anhalten", PreflightActionKind.StopUcpd, string.Empty);

    /// <summary>Führt einen Systemeingriff direkt im Programm aus (Dienste, Defender, BitLocker).</summary>
    public static PreflightAction RunSystemFix(string label, SystemFix fix) =>
        new(label, PreflightActionKind.RunFix, string.Empty, string.Empty, fix);
}

/// <summary>
/// Ergebnis einer Vorabprüfung: <paramref name="Action"/> ist der direkte Eingriff,
/// <paramref name="ManualAction"/> der manuelle Weg in die Windows-Einstellungen.
/// </summary>
public sealed record PreflightCheck(
    string Name,
    bool Passed,
    bool Blocking,
    string Message,
    PreflightAction? Action = null,
    PreflightAction? ManualAction = null);

/// <summary>
/// Prüfungen vor der SID-Änderung (Rechte, Domäne, Virenscanner, ausstehende Updates,
/// BitLocker, UCPD-Treiber, angemeldete Benutzer).
/// </summary>
public static class SystemChecks
{
    public static IReadOnlyList<PreflightCheck> Run()
    {
        var checks = new List<PreflightCheck>
        {
            CheckElevation(),
            CheckDomain(),
            CheckAntivirus(),
            CheckPendingUpdates(),
            CheckBitLocker(),
            CheckServices(),
            CheckUcpd(),
            CheckModernWindows(),
        };

        return checks;
    }

    private static PreflightCheck CheckElevation()
    {
        return TokenPrivileges.IsElevated()
            ? new PreflightCheck("Administratorrechte", true, true, "Das Programm läuft mit Administratorrechten.")
            : new PreflightCheck("Administratorrechte", false, true,
                "Das Programm muss als Administrator gestartet werden (Rechtsklick → Als Administrator ausführen).",
                PreflightAction.RestartAsAdministrator());
    }

    private static PreflightCheck CheckDomain()
    {
        var (joined, name) = NativeMethods.GetJoinInformation();

        if (!joined)
        {
            return new PreflightCheck("Domänenmitgliedschaft", true, false,
                string.IsNullOrEmpty(name) ? "Der Computer ist keiner Domäne beigetreten." : $"Arbeitsgruppe: {name}");
        }

        return new PreflightCheck("Domänenmitgliedschaft", false, true,
            $"Der Computer ist Mitglied der Domäne \"{name}\". Nach der SID-Änderung verliert er die Domänenmitgliedschaft " +
            "und muss neu beigetreten werden. Auf einem Domänencontroller ist eine SID-Änderung nicht möglich.",
            PreflightAction.Open("Systemeigenschaften öffnen (Domäne)", "sysdm.cpl"));
    }

    private static PreflightCheck CheckAntivirus()
    {
        var (exitCode, output) = Shell.RunPowerShell(
            "try { $s = Get-MpComputerStatus -ErrorAction Stop; if ($s.RealTimeProtectionEnabled) { 'AN' } else { 'AUS' } } catch { 'UNBEKANNT' }",
            30_000);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.ToUpperInvariant())
            .ToList();

        if (exitCode != 0 || lines.Count == 0 || lines.Contains("UNBEKANNT"))
        {
            return new PreflightCheck("Virenscanner", true, false,
                "Der Status von Microsoft Defender konnte nicht ermittelt werden. Bitte den Echtzeitschutz vor der Änderung manuell deaktivieren.",
                null,
                PreflightAction.Open("Defender-Einstellungen öffnen (manuell)", "ms-settings:windowsdefender"));
        }

        if (lines.Contains("AN"))
        {
            return new PreflightCheck("Virenscanner", false, true,
                "Der Echtzeitschutz von Microsoft Defender ist aktiv. Er kann die SID-Änderung mittendrin abbrechen und das System beschädigen. " +
                "Das Programm kann ihn direkt abschalten – verweigert Windows das (Manipulationsschutz), bleibt nur der Weg über die Defender-Einstellungen.",
                PreflightAction.RunSystemFix("Echtzeitschutz abschalten", SystemFix.DisableDefender),
                PreflightAction.Open("Defender-Einstellungen öffnen (manuell)", "ms-settings:windowsdefender"));
        }

        return new PreflightCheck("Virenscanner", true, false,
            lines.Contains("AUS")
                ? "Der Echtzeitschutz ist deaktiviert."
                : "Kein aktiver Echtzeitschutz erkannt.");
    }

    private static PreflightCheck CheckPendingUpdates()
    {
        var pending = new List<string>();

        if (RegistryUtil.KeyExists(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
        {
            pending.Add("Component Based Servicing");
        }

        if (RegistryUtil.KeyExists(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
        {
            pending.Add("Windows Update");
        }

        if (RegistryUtil.ReadBinary(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") is { Length: > 0 })
        {
            pending.Add("Datei-Umbenennungen");
        }

        return pending.Count == 0
            ? new PreflightCheck("Ausstehende Neustarts", true, false, "Keine ausstehenden Update- oder Neustartvorgänge gefunden.")
            : new PreflightCheck("Ausstehende Neustarts", false, true,
                $"Es sind noch Vorgänge offen ({string.Join(", ", pending)}). Bitte zuerst neu starten und die Updates abschließen, " +
                "sonst können sich Update und SID-Änderung gegenseitig stören.",
                PreflightAction.Open("Windows Update öffnen", "ms-settings:windowsupdate"));
    }

    private static PreflightCheck CheckBitLocker()
    {
        var (exitCode, output) = Shell.RunPowerShell(
            "try { $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; $v.ProtectionStatus.ToString() } catch { 'UNBEKANNT' }",
            30_000);

        var protectionOn = exitCode == 0 &&
                           output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                               .Any(line => line.Equals("On", StringComparison.OrdinalIgnoreCase));

        if (protectionOn)
        {
            return new PreflightCheck("BitLocker", false, true,
                "BitLocker ist für das Systemlaufwerk aktiv und blockiert die Änderung. Der Schutz lässt sich für die nächsten " +
                "Neustarts aussetzen – Windows startet dann ohne Schlüsselabfrage, entschlüsselt wird nichts.",
                PreflightAction.RunSystemFix("BitLocker für Neustart aussetzen", SystemFix.SuspendBitLocker),
                PreflightAction.Open("BitLocker-Verwaltung öffnen (manuell)", "control.exe",
                    "/name Microsoft.BitLockerDriveEncryption"));
        }

        return new PreflightCheck("BitLocker", true, false, "BitLocker ist nicht aktiv oder der Status ist unkritisch.");
    }

    private static PreflightCheck CheckServices()
    {
        var (exitCode, output) = Shell.RunPowerShell(
            "(Get-Service | Where-Object { $_.Status -eq 'Running' }).Count", 30_000);

        var countText = output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(line => int.TryParse(line, out _));

        if (exitCode != 0 || !int.TryParse(countText, out var count))
        {
            return new PreflightCheck("Laufende Dienste", true, false,
                "Die Anzahl laufender Dienste konnte nicht ermittelt werden.");
        }

        return count <= 40
            ? new PreflightCheck("Laufende Dienste", true, false, $"{count} Dienste laufen – unkritisch für die Änderung.")
            : new PreflightCheck("Laufende Dienste", false, false,
                $"{count} Dienste laufen. Für die SID-Änderung sollten möglichst wenige Dienste aktiv sein, " +
                "sonst bleiben Registry- und Dateisperren bestehen.",
                PreflightAction.RunSystemFix("Alle Dienste stoppen", SystemFix.StopAllServices),
                PreflightAction.Open("Dienste-Verwaltung öffnen (manuell)", "services.msc"));
    }

    private static PreflightCheck CheckUcpd()
    {
        var snapshot = UcpdController.Read();
        var (passed, message) = UcpdPolicy.Evaluate(snapshot);

        return new PreflightCheck("UCPD-Treiber", passed, false, message,
            snapshot.Running ? PreflightAction.StopUcpdDriver() : null,
            snapshot.Running
                ? PreflightAction.Open("Dienste-Verwaltung öffnen (manuell)", "services.msc")
                : null);
    }

    private static PreflightCheck CheckModernWindows()
    {
        var version = Environment.OSVersion.Version;
        return version.Build >= 7600
            ? new PreflightCheck("Windows-Version", true, false, $"Windows-Build {version.Build}.")
            : new PreflightCheck("Windows-Version", false, true, $"Windows-Build {version.Build} wird nicht unterstützt (mindestens Windows 7 / Build 7600).",
                PreflightAction.Open("Windows Update öffnen", "ms-settings:windowsupdate"));
    }
}

/// <summary>Hilfsfunktionen zum Starten von PowerShell und Konsolenprogrammen.</summary>
public static class Shell
{
    /// <summary>Führt ein PowerShell-Skript aus (ohne Fenster) und liefert Ausgabe und Exitcode.</summary>
    public static (int ExitCode, string Output) RunPowerShell(string script, int timeoutMs = 120_000)
    {
        try
        {
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            return Run("powershell.exe",
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
                timeoutMs);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }

    /// <summary>Führt ein Programm aus und liefert die kombinierte Ausgabe.</summary>
    public static (int ExitCode, string Output) Run(string fileName, string arguments, int timeoutMs = 120_000)
    {
        var info = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        using var process = new Process { StartInfo = info };
        var output = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) { output.AppendLine(e.Data); } };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) { output.AppendLine(e.Data); } };

        if (!process.Start())
        {
            return (-1, "Prozess konnte nicht gestartet werden.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        if (!process.WaitForExit(timeoutMs))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // ignorieren
            }

            return (-1, $"Zeitüberschreitung nach {timeoutMs / 1000} Sekunden: {fileName}");
        }

        process.WaitForExit();
        return (process.ExitCode, output.ToString().Trim());
    }
}

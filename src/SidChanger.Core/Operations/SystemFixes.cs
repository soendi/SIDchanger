using SidChanger.Core.Infrastructure;

namespace SidChanger.Core.Operations;

/// <summary>Direkt im Programm ausführbare Systemeingriffe der Vorabprüfung.</summary>
public enum SystemFix
{
    /// <summary>Alle nicht kritischen, laufenden Dienste beenden.</summary>
    StopAllServices = 0,

    /// <summary>Defender-Echtzeitschutz abschalten (soweit Windows es zulässt).</summary>
    DisableDefender = 1,

    /// <summary>BitLocker-Schutz für die nächsten Neustarts aussetzen (nicht entschlüsseln).</summary>
    SuspendBitLocker = 2,
}

/// <summary>Ergebnis eines Systemeingriffs.</summary>
public sealed record FixResult(bool Success, string Summary);

/// <summary>
/// Setzt die blockierenden Elemente direkt zurück: Dienste anhalten, Defender-Echtzeitschutz
/// abschalten und BitLocker für die nächsten Neustarts aussetzen. Jeder Eingriff meldet ehrlich,
/// was Windows tatsächlich zugelassen hat.
/// </summary>
public static class SystemFixes
{
    /// <summary>Führt einen Eingriff aus.</summary>
    public static FixResult Run(SystemFix fix, Action<string> log, Action<string>? warn) => fix switch
    {
        SystemFix.StopAllServices => StopAllServices(log, warn),
        SystemFix.DisableDefender => DisableDefender(log, warn),
        SystemFix.SuspendBitLocker => SuspendBitLocker(3, log, warn),
        _ => new FixResult(false, $"Unbekannter Eingriff: {fix}."),
    };

    /// <summary>Beendet alle laufenden Dienste außer den kritischen Systemdiensten.</summary>
    public static FixResult StopAllServices(Action<string> log, Action<string>? warn)
    {
        const string script = @"
$ErrorActionPreference = 'Continue'
$skip = @('RpcSs','DcomLaunch','RpcEptMapper','LSM','Power','PlugPlay','SamSs','EventLog','ProfSvc','Winmgmt','nsi','BrokerInfrastructure','SystemEventsBroker','Schedule','gpsvc','CryptSvc')
$stopped = 0; $failed = 0; $skipped = 0
foreach ($service in Get-Service) {
  if ($service.Status -ne 'Running') { continue }
  if ($skip -contains $service.Name) { $skipped++; continue }
  try { Stop-Service -Name $service.Name -Force -ErrorAction Stop; $stopped++ }
  catch { $failed++ }
}
Write-Output ""SUMME $stopped $failed $skipped""
Write-Output ""REST $((Get-Service | Where-Object { $_.Status -eq 'Running' }).Count)""
";

        var (_, output) = Shell.RunPowerShell(script, 240_000);

        var stopped = ReadNumber(output, "SUMME", 0);
        var failed = ReadNumber(output, "SUMME", 1);
        var skipped = ReadNumber(output, "SUMME", 2);
        var rest = ReadNumber(output, "REST", 0);

        log($"Dienste: {stopped} beendet, {failed} nicht beendbar, {skipped} kritische Dienste geschützt, {rest} laufen noch.");

        if (stopped == 0 && failed == 0)
        {
            warn?.Invoke("Es wurden keine Dienste beendet – bitte als Administrator ausführen.");
            return new FixResult(false, "Es konnten keine Dienste beendet werden. Bitte das Programm als Administrator starten.");
        }

        return new FixResult(true,
            $"{stopped} Dienste beendet. {rest} Dienste laufen noch (kritische Systemdienste und nicht beendbare Dienste). " +
            "Nach dem nächsten Neustart starten sie je nach Starttyp wieder.");
    }

    /// <summary>Schaltet den Defender-Echtzeitschutz ab, soweit der Manipulationsschutz es erlaubt.</summary>
    public static FixResult DisableDefender(Action<string> log, Action<string>? warn)
    {
        const string script = @"
$ErrorActionPreference = 'Continue'
$problems = @()
try {
  Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableScriptScanning $true `
    -DisableIOAVProtection $true -DisableArchiveScanning $true -DisableIntrusionPreventionSystem $true `
    -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction Stop
} catch { $problems += $_.Exception.Message }
try {
  $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
  New-Item -Path $root -Force | Out-Null
  New-ItemProperty -Path $root -Name DisableAntiSpyware -Value 1 -PropertyType DWord -Force | Out-Null
  $realtime = Join-Path $root 'Real-Time Protection'
  New-Item -Path $realtime -Force | Out-Null
  New-ItemProperty -Path $realtime -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWord -Force | Out-Null
} catch { $problems += $_.Exception.Message }
$state = 'UNBEKANNT'
try {
  $status = Get-MpComputerStatus -ErrorAction Stop
  $state = if ($status.RealTimeProtectionEnabled) { 'AN' } else { 'AUS' }
} catch { }
Write-Output ""STATUS $state""
if ($problems.Count -gt 0) { Write-Output (""FEHLER "" + ($problems -join ' | ')) }
";

        var (_, output) = Shell.RunPowerShell(script, 180_000);
        var upper = output.ToUpperInvariant();

        if (upper.Contains("STATUS AUS"))
        {
            log("Defender-Echtzeitschutz ist ausgeschaltet.");
            return new FixResult(true, "Der Defender-Echtzeitschutz ist ausgeschaltet. Windows kann ihn nach einem Neustart oder Update wieder einschalten.");
        }

        var errorLine = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(line => line.StartsWith("FEHLER", StringComparison.OrdinalIgnoreCase));

        warn?.Invoke("Defender-Echtzeitschutz konnte nicht abgeschaltet werden." +
                     (errorLine is null ? string.Empty : " " + errorLine));

        return new FixResult(false,
            "Der Echtzeitschutz läuft weiter. Meist blockiert der Manipulationsschutz von Windows die Änderung – " +
            "dieser lässt sich nur in den Defender-Einstellungen (oder per Richtlinie) abschalten.\n\n" +
            (errorLine ?? string.Empty));
    }

    /// <summary>Setzt den BitLocker-Schutz für die nächsten Neustarts aus (ohne zu entschlüsseln).</summary>
    public static FixResult SuspendBitLocker(int rebootCount, Action<string> log, Action<string>? warn)
    {
        var count = Math.Clamp(rebootCount, 1, 15);

        var script = $@"
$ErrorActionPreference = 'Continue'
try {{
  $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  if ($volume.ProtectionStatus -eq 'On') {{
    Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount {count} -ErrorAction Stop | Out-Null
  }}
  $after = Get-BitLockerVolume -MountPoint $env:SystemDrive
  Write-Output ""STATUS $($after.ProtectionStatus) $($after.VolumeStatus)""
}} catch {{
  Write-Output ""FEHLER $($_.Exception.Message)""
}}
";

        var (_, output) = Shell.RunPowerShell(script, 180_000);

        if (output.Contains("FEHLER", StringComparison.OrdinalIgnoreCase))
        {
            var errorLine = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(line => line.StartsWith("FEHLER", StringComparison.OrdinalIgnoreCase)) ?? output;

            warn?.Invoke("BitLocker konnte nicht ausgesetzt werden: " + errorLine);
            return new FixResult(false, "BitLocker ließ sich nicht aussetzen: " + errorLine);
        }

        var status = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(line => line.StartsWith("STATUS", StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

        log($"BitLocker für die nächsten {count} Neustarts ausgesetzt ({status}).");

        return new FixResult(true,
            $"Der BitLocker-Schutz ist für die nächsten {count} Neustarts ausgesetzt. Windows startet ohne " +
            "Wiederherstellungsschlüssel-Abfrage; entschlüsselt wird nichts. Nach den Neustarts schaltet sich der " +
            "Schutz automatisch wieder ein.");
    }

    private static int ReadNumber(string output, string key, int index)
    {
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!line.StartsWith(key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > index + 1 && int.TryParse(parts[index + 1], out var value))
            {
                return value;
            }
        }

        return 0;
    }
}

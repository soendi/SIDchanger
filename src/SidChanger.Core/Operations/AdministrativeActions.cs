using System.Diagnostics;
using System.Security.AccessControl;
using Microsoft.Win32;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.Core.Operations;

/// <summary>
/// Einzelne Systemeingriffe, die von den Änderungsschritten verwendet werden
/// (Computername, Info-Center, OneDrive, Apps, Suche, Standard-Apps, McAfee, Abmelden).
/// </summary>
public static class AdministrativeActions
{
    private const string ComputerNamePath = @"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName";
    private const string TcpipPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    private const string LanmanPath = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

    /// <summary>
    /// Benennt den Computer um. Es wird zuerst die Windows-eigene Umbenennung
    /// (Rename-Computer) verwendet; unabhängig davon werden die Registry-Werte gesetzt.
    /// </summary>
    public static (bool ApiSucceeded, string Detail) SetComputerName(
        string newName,
        Action<string> log,
        Action<string>? warn)
    {
        var escaped = newName.Replace("'", "''");
        var (exitCode, output) = Shell.RunPowerShell(
            $"try {{ Rename-Computer -NewName '{escaped}' -Force -ErrorAction Stop; 'ERFOLG' }} catch {{ 'FEHLER: ' + $_.Exception.Message }}",
            120_000);

        var apiSucceeded = exitCode == 0 && output.Contains("ERFOLG", StringComparison.OrdinalIgnoreCase);
        if (!apiSucceeded)
        {
            warn?.Invoke($"Windows-Umbenennung nicht möglich: {output}");
        }

        SetString(RegistryHive.LocalMachine, ComputerNamePath, "ComputerName", newName, log, warn);
        SetString(RegistryHive.LocalMachine, TcpipPath, "Hostname", newName, log, warn);
        SetString(RegistryHive.LocalMachine, TcpipPath, "NV Hostname", newName, log, warn);

        return (apiSucceeded, apiSucceeded
            ? $"Computername wird auf \"{newName}\" geändert (Neustart erforderlich)."
            : $"Computername in der Registrierung auf \"{newName}\" gesetzt; die Windows-API war nicht verfügbar. Neustart erforderlich.");
    }

    /// <summary>Setzt die Computerbeschreibung (srvcomment).</summary>
    public static void SetComputerDescription(string description, Action<string> log, Action<string>? warn)
    {
        SetString(RegistryHive.LocalMachine, LanmanPath, "srvcomment", description, log, warn);
    }

    /// <summary>Meldet alle anderen angemeldeten Benutzer ab.</summary>
    public static int LogoffOtherSessions(Action<string> log, Action<string>? warn, CancellationToken cancellationToken)
    {
        var count = 0;

        if (!NativeMethods.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var sessionCount))
        {
            warn?.Invoke("Sitzungen konnten nicht aufgezählt werden.");
            return 0;
        }

        try
        {
            var size = System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.WtsSessionInfo>();

            for (var i = 0; i < sessionCount; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var info = System.Runtime.InteropServices.Marshal.PtrToStructure<NativeMethods.WtsSessionInfo>(
                    IntPtr.Add(buffer, i * size));

                if (info.SessionId == 0 || info.State != NativeMethods.WtsActive && info.State != NativeMethods.WtsDisconnected)
                {
                    continue;
                }

                var user = QuerySessionString(info.SessionId, NativeMethods.WtsUserName);
                if (string.IsNullOrEmpty(user))
                {
                    continue;
                }

                log($"Melde Benutzer \"{user}\" (Sitzung {info.SessionId}) ab ...");

                if (NativeMethods.WTSLogoffSession(IntPtr.Zero, info.SessionId, true))
                {
                    count++;
                }
                else
                {
                    warn?.Invoke($"Sitzung {info.SessionId} konnte nicht abgemeldet werden.");
                }
            }
        }
        finally
        {
            NativeMethods.WTSFreeMemory(buffer);
        }

        return count;
    }

    private static string? QuerySessionString(uint sessionId, int infoClass)
    {
        if (!NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
        {
            return null;
        }

        try
        {
            return System.Runtime.InteropServices.Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            NativeMethods.WTSFreeMemory(buffer);
        }
    }

    /// <summary>Setzt die Info-Center-/Benachrichtigungseinstellungen zurück.</summary>
    public static int ResetActionCenter(Action<string> log, Action<string>? warn)
    {
        var changed = 0;

        foreach (var (hive, path) in new[]
                 {
                     (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"),
                     (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"),
                 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(path, writable: true);
                if (key is null)
                {
                    continue;
                }

                foreach (var name in key.GetSubKeyNames())
                {
                    key.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
                    changed++;
                }

                foreach (var name in key.GetValueNames())
                {
                    key.DeleteValue(name, throwOnMissingValue: false);
                    changed++;
                }

                log($"Benachrichtigungseinstellungen zurückgesetzt: {hive}\\{path}");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"Info-Center ({hive}\\{path}) konnte nicht zurückgesetzt werden: {ex.Message}");
            }
        }

        return changed;
    }

    /// <summary>Setzt OneDrive zurück (Konten entfernen, Einstellungen löschen, Prozesse beenden).</summary>
    public static int ResetOneDrive(Action<string> log, Action<string>? warn)
    {
        var changed = 0;

        foreach (var process in Process.GetProcessesByName("OneDrive"))
        {
            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
                log("OneDrive-Prozess beendet.");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"OneDrive-Prozess konnte nicht beendet werden: {ex.Message}");
            }
            finally
            {
                process.Dispose();
            }
        }

        changed += DeleteKeyTree(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\OneDrive\Accounts", log, warn);
        changed += DeleteKeyTree(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\OneDrive\Accounts", log, warn);
        changed += DeleteKeyTree(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\OneDrive\Accounts", log, warn);

        foreach (var path in new[]
                 {
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "OneDrive", "settings"),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "OneDrive", "sync"),
                 })
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                    changed++;
                    log($"OneDrive-Ordner gelöscht: {path}");
                }
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{path} konnte nicht gelöscht werden: {ex.Message}");
            }
        }

        return changed;
    }

    /// <summary>Setzt die Windows-Suche zurück (Dienst stoppen, Datenbank löschen).</summary>
    public static int ResetSearch(Action<string> log, Action<string>? warn)
    {
        Shell.Run("sc.exe", "stop WSearch", 60_000);

        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Search", "Data", "Applications", "Windows");

        if (!Directory.Exists(path))
        {
            return 0;
        }

        var deleted = 0;

        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                File.SetAttributes(file, FileAttributes.Normal);
                File.Delete(file);
                deleted++;
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{file}: {ex.Message}");
            }
        }

        log($"Suchdatenbank gelöscht ({deleted} Dateien). Windows baut sie beim nächsten Anmelden neu auf.");

        try
        {
            Shell.Run("sc.exe", "start WSearch", 60_000);
        }
        catch
        {
            // Dienststart ist optional
        }

        return deleted;
    }

    /// <summary>Setzt moderne Apps (Appx) anhand der Filter zurück.</summary>
    public static (int Reset, int Failed, string Output) ResetModernApps(string filters, Action<string> log, Action<string>? warn)
    {
        var include = new List<string>();
        var exclude = new List<string>();

        foreach (var part in filters.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith('-'))
            {
                exclude.Add(part[1..]);
            }
            else
            {
                include.Add(part);
            }
        }

        if (include.Count == 0)
        {
            include.Add("*");
        }

        string ToPsArray(IEnumerable<string> values) =>
            "@(" + string.Join(", ", values.Select(v => "'" + v.Replace("'", "''") + "'")) + ")";

        var script = $@"
$ErrorActionPreference = 'Continue'
$inc = {ToPsArray(include)}
$exc = {ToPsArray(exclude)}
function Test-Match($text, $patterns) {{
  foreach ($p in $patterns) {{ if ($text -like $p) {{ return $true }} }}
  return $false
}}
$ok = 0; $fail = 0
foreach ($pkg in Get-AppxPackage) {{
  $name = $pkg.Name; $family = $pkg.PackageFamilyName
  $included = ($inc -contains '*') -or (Test-Match $name $inc) -or (Test-Match $family $inc)
  if (-not $included) {{ continue }}
  if ((Test-Match $name $exc) -or (Test-Match $family $exc)) {{ continue }}
  try {{
    Reset-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
    Write-Output ""OK $family""
    $ok++
  }} catch {{
    Write-Output ""FEHLER $family $($_.Exception.Message)""
    $fail++
  }}
}}
Write-Output ""SUMME $ok $fail""
";

        var (exitCode, output) = Shell.RunPowerShell(script, 600_000);

        if (exitCode != 0)
        {
            warn?.Invoke($"Appx-Zurücksetzen mit Fehlern beendet: {output}");
        }

        var reset = 0;
        var failed = 0;

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("OK ", StringComparison.Ordinal))
            {
                reset++;
                log($"App zurückgesetzt: {line[3..].Trim()}");
            }
            else if (line.StartsWith("FEHLER ", StringComparison.Ordinal))
            {
                failed++;
                warn?.Invoke($"App nicht zurückgesetzt: {line[7..].Trim()}");
            }
        }

        return (reset, failed, output);
    }

    /// <summary>Entfernt die Dateizuordnungen des aktuellen Benutzers (Standard-Apps).</summary>
    public static int ResetDefaultApps(Action<string> log, Action<string>? warn)
    {
        var removed = 0;

        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts", writable: true);

            if (key is null)
            {
                return 0;
            }

            foreach (var ext in key.GetSubKeyNames())
            {
                using var extKey = key.OpenSubKey(ext, writable: true);
                if (extKey?.OpenSubKey("UserChoice") is null)
                {
                    continue;
                }

                extKey.DeleteSubKeyTree("UserChoice", throwOnMissingSubKey: false);
                removed++;
            }

            log($"Dateizuordnungen zurückgesetzt ({removed} Erweiterungen).");
        }
        catch (Exception ex)
        {
            warn?.Invoke($"Dateizuordnungen konnten nicht zurückgesetzt werden: {ex.Message}");
        }

        return removed;
    }

    /// <summary>Setzt die McAfee-Agent-ID zurück (nur wenn McAfee installiert ist).</summary>
    public static bool ResetMcAfeeId(Action<string> log, Action<string>? warn)
    {
        var paths = new[]
        {
            @"SOFTWARE\Network Associates\ePolicy Orchestrator\Agent",
            @"SOFTWARE\WOW6432Node\Network Associates\ePolicy Orchestrator\Agent",
        };

        var changed = false;

        foreach (var path in paths)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, writable: true);
                if (key is null)
                {
                    continue;
                }

                key.SetValue("AgentGUID", "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}", RegistryValueKind.String);
                changed = true;
                log($"McAfee-AgentGUID ersetzt: {path}");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"McAfee ({path}) konnte nicht geändert werden: {ex.Message}");
            }
        }

        return changed;
    }

    /// <summary>Führt den gewünschten Neustart bzw. das Herunterfahren aus.</summary>
    public static void SchedulePostAction(PostChangeAction action, int seconds, Action<string> log)
    {
        if (action == PostChangeAction.None)
        {
            return;
        }

        if (action == PostChangeAction.Reboot)
        {
            RebootService.RequestRestart(seconds, "SID-Wechsler: Neustart zum Abschluss der SID-Änderung", log);
            return;
        }

        log($"Herunterfahren in {seconds} Sekunden angefordert.");

        var (exitCode, output) = Shell.Run("shutdown.exe",
            $"/s /t {seconds} /f /c \"SID-Wechsler: Herunterfahren nach der SID-Änderung\"", 30_000);

        if (exitCode != 0)
        {
            log($"Windows hat das Herunterfahren nicht angenommen (Exitcode {exitCode}): {output}");
        }
    }

    private static void SetString(
        RegistryHive hive,
        string path,
        string name,
        string value,
        Action<string> log,
        Action<string>? warn)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path, writable: true) ?? baseKey.CreateSubKey(path, writable: true);
            key?.SetValue(name, value, RegistryValueKind.String);
            log($"{path}\\{name} = \"{value}\"");
        }
        catch (Exception ex)
        {
            warn?.Invoke($"{path}\\{name} konnte nicht gesetzt werden: {ex.Message}");
        }
    }

    private static int DeleteKeyTree(RegistryHive hive, string path, Action<string> log, Action<string>? warn)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            if (baseKey.OpenSubKey(path) is null)
            {
                return 0;
            }

            baseKey.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
            log($"Registrierungsschlüssel entfernt: {hive}\\{path}");
            return 1;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"{hive}\\{path} konnte nicht entfernt werden: {ex.Message}");
            return 0;
        }
    }
}

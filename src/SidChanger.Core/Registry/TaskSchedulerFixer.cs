using System.Text;
using Microsoft.Win32;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;
using SidChanger.Sid;

namespace SidChanger.Core.Registry;

/// <summary>
/// Ersetzt die alte SID in geplanten Aufgaben (XML-Dateien unter System32\Tasks und
/// im TaskCache der Registrierung), damit Aufgaben nach der SID-Änderung weiter laufen.
/// </summary>
public static class TaskSchedulerFixer
{
    private const string TaskCachePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";

    /// <summary>Pfad der Aufgaben-XML-Dateien.</summary>
    public static string TasksDirectory => Path.Combine(AppPaths.WindowsDirectory, "System32", "Tasks");

    /// <summary>Zählt Dateien, die die alte SID enthalten (für die Analyse).</summary>
    public static int CountAffectedFiles(MachineSid oldSid, Action<string>? warn)
    {
        var count = 0;

        foreach (var file in EnumerateTaskFiles(warn))
        {
            try
            {
                if (SidStringRewriter.Count(File.ReadAllText(file), oldSid) > 0)
                {
                    count++;
                }
            }
            catch
            {
                // ignorieren
            }
        }

        return count;
    }

    /// <summary>Ersetzt die alte SID in Aufgaben-XML und im TaskCache.</summary>
    public static (int Files, int RegistryValues) Apply(
        MachineSid oldSid,
        MachineSid newSid,
        BackupStore backup,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var filesChanged = 0;

        foreach (var file in EnumerateTaskFiles(warn))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var bytes = File.ReadAllBytes(file);
                var (text, encoding) = DecodeTaskXml(bytes);

                if (SidStringRewriter.Count(text, oldSid) == 0)
                {
                    continue;
                }

                var rewritten = SidStringRewriter.Rewrite(text, oldSid, newSid);
                File.WriteAllBytes(file, EncodeTaskXml(rewritten, encoding));
                filesChanged++;
                log($"Aufgabe angepasst: {file}");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"Aufgabe {file} konnte nicht angepasst werden: {ex.Message}");
            }
        }

        var registryValues = 0;

        try
        {
            using var key = RegistryKeyAccess.OpenWritable(RegistryHive.LocalMachine, TaskCachePath, log, warn);
            if (key is not null)
            {
                var patch = RegistryUtil.PatchTree(key, RegistryHive.LocalMachine, TaskCachePath, oldSid, newSid, backup, log, warn, cancellationToken);
                registryValues = patch.ValuesChanged;
            }
        }
        catch (Exception ex)
        {
            warn?.Invoke($"TaskCache konnte nicht angepasst werden: {ex.Message}");
        }

        return (filesChanged, registryValues);
    }

    private static IEnumerable<string> EnumerateTaskFiles(Action<string>? warn)
    {
        var root = TasksDirectory;
        if (!Directory.Exists(root))
        {
            yield break;
        }

        string[] files;
        try
        {
            files = Directory.GetFiles(root, "*.xml", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            warn?.Invoke($"Aufgabenordner nicht lesbar: {ex.Message}");
            yield break;
        }

        foreach (var file in files)
        {
            yield return file;
        }

        // Aufgaben ohne .xml-Endung (Windows speichert sie ohne Endung) ebenfalls prüfen.
        string[] allFiles;
        try
        {
            allFiles = Directory.GetFiles(root, "*", SearchOption.AllDirectories);
        }
        catch
        {
            yield break;
        }

        foreach (var file in allFiles)
        {
            if (!file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                yield return file;
            }
        }
    }

    private static (string Text, Encoding Encoding) DecodeTaskXml(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return (new UnicodeEncoding(false, true).GetString(bytes, 2, bytes.Length - 2), new UnicodeEncoding(false, true));
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return (Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3), new UTF8Encoding(true));
        }

        return (Encoding.UTF8.GetString(bytes), new UTF8Encoding(false));
    }

    private static byte[] EncodeTaskXml(string text, Encoding encoding)
    {
        var preamble = encoding.GetPreamble();
        var body = encoding.GetBytes(text);

        if (preamble.Length == 0)
        {
            return body;
        }

        var result = new byte[preamble.Length + body.Length];
        preamble.CopyTo(result, 0);
        body.CopyTo(result, preamble.Length);
        return result;
    }
}

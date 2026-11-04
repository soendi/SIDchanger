using SidChanger.Sid;

namespace SidChanger.Core.Files;

/// <summary>
/// Ersetzt die rohen SID-Bytes in Dateien (z. B. DPAPI-Masterkeys, Zertifikatsspeicher).
/// Es wird ausschließlich die 12-Byte-Sub-Authority-Folge ersetzt, nie ein ganzes SID-Präfix.
/// </summary>
public static class FileSidPatcher
{
    private const long MaxFileSize = 20 * 1024 * 1024;

    /// <summary>Ersetzt die SID in allen Dateien eines Ordners (rekursiv). Liefert (Dateien, Ersetzungen).</summary>
    public static (int Files, int Replacements) PatchDirectory(
        string root,
        MachineSid oldSid,
        MachineSid newSid,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(root))
        {
            return (0, 0);
        }

        var oldBytes = oldSid.ToSubAuthorityBytes();
        var newBytes = newSid.ToSubAuthorityBytes();
        var files = 0;
        var replacements = 0;

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var info = new FileInfo(file);
                if (info.Length == 0 || info.Length > MaxFileSize)
                {
                    continue;
                }

                var bytes = File.ReadAllBytes(file);
                var count = SidBinary.Count(bytes, oldBytes);
                if (count == 0)
                {
                    continue;
                }

                SidBinary.ReplaceAll(bytes, oldBytes, newBytes);
                File.WriteAllBytes(file, bytes);
                files++;
                replacements += count;
                log($"SID in Datei ersetzt ({count}x): {file}");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{file}: {ex.Message}");
            }
        }

        return (files, replacements);
    }

    /// <summary>Kopiert einen Ordner rekursiv (überschreibt vorhandene Dateien).</summary>
    public static int CopyDirectory(string source, string destination, Action<string>? warn = null)
    {
        if (!Directory.Exists(source))
        {
            return 0;
        }

        var copied = 0;

        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, directory);
            Directory.CreateDirectory(Path.Combine(destination, relative));
        }

        Directory.CreateDirectory(destination);

        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            try
            {
                var relative = Path.GetRelativePath(source, file);
                var target = Path.Combine(destination, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(file, target, overwrite: true);
                copied++;
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{file} konnte nicht kopiert werden: {ex.Message}");
            }
        }

        return copied;
    }
}

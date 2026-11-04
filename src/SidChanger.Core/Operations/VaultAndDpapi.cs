using SidChanger.Core.Files;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.Core.Operations;

/// <summary>Ein gesicherter Ordner (Quelle → Sicherungsziel).</summary>
public sealed record FolderBackup(string Source, string Destination, string Kind);

/// <summary>
/// Sichert und repariert die an die SID gebundenen Verschlüsselungsdaten:
/// Windows Vault (Anmeldeinformationsverwaltung), DPAPI-Masterkeys und Zertifikatsspeicher.
/// </summary>
public static class VaultAndDpapi
{
    /// <summary>Liefert die Vault-/Credential-Ordner aller Profile.</summary>
    public static IReadOnlyList<string> GetVaultPaths(IEnumerable<ProfileEntry> profiles)
    {
        var paths = new List<string>
        {
            Path.Combine(AppPaths.WindowsDirectory, "System32", "config", "systemprofile", "AppData", "Roaming", "Microsoft", "Vault"),
        };

        foreach (var profile in profiles.Where(p => p.Exists))
        {
            var appData = Path.Combine(profile.ImagePath, "AppData");
            paths.Add(Path.Combine(appData, "Roaming", "Microsoft", "Vault"));
            paths.Add(Path.Combine(appData, "Local", "Microsoft", "Vault"));
            paths.Add(Path.Combine(appData, "Roaming", "Microsoft", "Credentials"));
            paths.Add(Path.Combine(appData, "Local", "Microsoft", "Credentials"));
        }

        return paths.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Liefert die DPAPI-/Zertifikatsordner (System und Profile).</summary>
    public static IReadOnlyList<string> GetDpapiPaths(IEnumerable<ProfileEntry> profiles)
    {
        var paths = new List<string>
        {
            Path.Combine(AppPaths.WindowsDirectory, "System32", "Microsoft", "Protect"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Crypto"),
            Path.Combine(AppPaths.WindowsDirectory, "System32", "config", "systemprofile", "AppData", "Roaming", "Microsoft", "Protect"),
        };

        foreach (var profile in profiles.Where(p => p.Exists))
        {
            var appData = Path.Combine(profile.ImagePath, "AppData");
            paths.Add(Path.Combine(appData, "Roaming", "Microsoft", "Protect"));
            paths.Add(Path.Combine(appData, "Local", "Microsoft", "Protect"));
        }

        return paths.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Sichert die angegebenen Ordner unterhalb des Sicherungsordners.</summary>
    public static IReadOnlyList<FolderBackup> Backup(
        IEnumerable<string> sources,
        string backupRoot,
        string kind,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var backups = new List<FolderBackup>();
        var index = 0;

        foreach (var source in sources)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var destination = Path.Combine(backupRoot, kind, index++.ToString("D3"));
                var copied = FileSidPatcher.CopyDirectory(source, destination, warn);
                if (copied > 0)
                {
                    backups.Add(new FolderBackup(source, destination, kind));
                    log($"{kind}: {copied} Dateien aus {source} gesichert.");
                }
                else
                {
                    Directory.Delete(destination, recursive: true);
                }
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{source} konnte nicht gesichert werden: {ex.Message}");
            }
        }

        return backups;
    }

    /// <summary>Spielt gesicherte Ordner zurück.</summary>
    public static int Restore(
        IReadOnlyList<FolderBackup> backups,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var restored = 0;

        foreach (var backup in backups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var copied = FileSidPatcher.CopyDirectory(backup.Destination, backup.Source, warn);
                restored += copied;
                log($"{backup.Kind}: {copied} Dateien nach {backup.Source} zurückgespielt.");
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{backup.Source} konnte nicht wiederhergestellt werden: {ex.Message}");
            }
        }

        return restored;
    }

    /// <summary>
    /// Passt DPAPI-Material an die neue SID an: SID-benannte Ordner umbenennen,
    /// SID-Bytes in Schlüsseldateien ersetzen und ACLs korrigieren.
    /// </summary>
    public static (int Renamed, int Files, int Replacements, int AclObjects) FixMaterial(
        MachineSid oldSid,
        MachineSid newSid,
        IEnumerable<string> roots,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var renamed = 0;
        var files = 0;
        var replacements = 0;
        var aclObjects = 0;

        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Directory.Exists(root))
            {
                continue;
            }

            // 1) Ordner, die nach einer SID der alten Maschine benannt sind, umbenennen.
            foreach (var directory in Directory.EnumerateDirectories(root).ToList())
            {
                var name = Path.GetFileName(directory);
                if (!SidMapping.TryMap(name, oldSid, newSid, out var newName) || newName == name)
                {
                    continue;
                }

                try
                {
                    var target = Path.Combine(Path.GetDirectoryName(directory)!, newName);
                    if (Directory.Exists(target))
                    {
                        warn?.Invoke($"Ziel existiert bereits, Ordner wird zusammengeführt: {target}");
                        FileSidPatcher.CopyDirectory(directory, target, warn);
                        Directory.Delete(directory, recursive: true);
                    }
                    else
                    {
                        Directory.Move(directory, target);
                    }

                    renamed++;
                    log($"Ordner umbenannt: {name} → {newName}");
                }
                catch (Exception ex)
                {
                    warn?.Invoke($"{directory} konnte nicht umbenannt werden: {ex.Message}");
                }
            }

            // 2) SID-Bytes in den Schlüsseldateien ersetzen.
            var (patchedFiles, patchedReplacements) = FileSidPatcher.PatchDirectory(root, oldSid, newSid, log, warn, cancellationToken);
            files += patchedFiles;
            replacements += patchedReplacements;

            // 3) ACLs anpassen.
            var acl = AclFixer.FixPath(root, oldSid, newSid, recursive: true, backup: null, log, warn, cancellationToken);
            aclObjects += acl.ObjectsChanged;
        }

        return (renamed, files, replacements, aclObjects);
    }
}

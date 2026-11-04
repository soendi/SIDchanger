using System.Security.AccessControl;
using System.Security.Principal;
using SidChanger.Core.Infrastructure;
using SidChanger.Sid;

namespace SidChanger.Core.Files;

/// <summary>Ergebnis einer ACL-Anpassung.</summary>
public sealed record AclFixResult(int ObjectsChanged, int ObjectsVisited, int Errors);

/// <summary>
/// Schreibt Besitzer und Zugriffsrechte (NTFS-ACLs) von der alten auf die neue SID um.
/// Das ist nach einer SID-Änderung zwingend, sonst haben Benutzer keinen Zugriff mehr
/// auf ihre eigenen Profilordner.
/// </summary>
public static class AclFixer
{
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>Passt die ACLs eines Pfads (optional rekursiv) an.</summary>
    public static AclFixResult FixPath(
        string path,
        MachineSid oldSid,
        MachineSid newSid,
        bool recursive,
        BackupStore? backup,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var changed = 0;
        var visited = 0;
        var errors = 0;

        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path) && !File.Exists(path))
        {
            warn?.Invoke($"Pfad nicht vorhanden, übersprungen: {path}");
            return new AclFixResult(0, 0, 1);
        }

        foreach (var entry in Enumerate(path, recursive))
        {
            cancellationToken.ThrowIfCancellationRequested();
            visited++;

            try
            {
                if (FixSingleObject(entry, oldSid, newSid, backup, log, warn))
                {
                    changed++;
                }
            }
            catch (UnauthorizedAccessException)
            {
                try
                {
                    if (TryTakeOwnership(entry) && FixSingleObject(entry, oldSid, newSid, backup, log, warn))
                    {
                        changed++;
                    }
                    else
                    {
                        errors++;
                        warn?.Invoke($"Kein Zugriff auf {entry}.");
                    }
                }
                catch (Exception ex)
                {
                    errors++;
                    warn?.Invoke($"{entry}: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                errors++;
                warn?.Invoke($"{entry}: {ex.Message}");
            }

            if (visited % 500 == 0)
            {
                log($"{visited} Objekte geprüft, {changed} angepasst ...");
            }
        }

        return new AclFixResult(changed, visited, errors);
    }

    private static IEnumerable<string> Enumerate(string root, bool recursive)
    {
        yield return root;

        if (!recursive || !Directory.Exists(root))
        {
            yield break;
        }

        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var current = stack.Pop();

            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(current);
            }
            catch
            {
                continue;
            }

            foreach (var entry in entries)
            {
                // Verknüpfungen nicht verfolgen (Gefahr von Endlosschleifen).
                var isDirectory = false;
                var isReparsePoint = false;

                try
                {
                    var attributes = File.GetAttributes(entry);
                    isDirectory = (attributes & FileAttributes.Directory) != 0;
                    isReparsePoint = (attributes & FileAttributes.ReparsePoint) != 0;
                }
                catch
                {
                    // Attribut nicht lesbar → Eintrag trotzdem bearbeiten
                }

                if (isDirectory && !isReparsePoint)
                {
                    stack.Push(entry);
                }

                yield return entry;
            }
        }
    }

    private static bool FixSingleObject(
        string path,
        MachineSid oldSid,
        MachineSid newSid,
        BackupStore? backup,
        Action<string> log,
        Action<string>? warn)
    {
        if (Directory.Exists(path))
        {
            var info = new DirectoryInfo(path);
            var security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access | AccessControlSections.Audit);
            StoreBackup(backup, path, true, security);
            if (!RewriteSecurity(security, oldSid, newSid))
            {
                return false;
            }

            info.SetAccessControl(security);
            log($"ACL angepasst: {path}");
            return true;
        }

        if (File.Exists(path))
        {
            var info = new FileInfo(path);
            var security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access | AccessControlSections.Audit);
            StoreBackup(backup, path, false, security);
            if (!RewriteSecurity(security, oldSid, newSid))
            {
                return false;
            }

            info.SetAccessControl(security);
            return true;
        }

        return false;
    }

    private static void StoreBackup(BackupStore? backup, string path, bool isDirectory, FileSystemSecurity security)
    {
        if (backup is null)
        {
            return;
        }

        try
        {
            var sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
            backup.RecordAcl(path, isDirectory, sddl);
        }
        catch
        {
            // Sicherung ist optional
        }
    }

    /// <summary>Ersetzt die alte SID in Besitzer, DACL und SACL.</summary>
    private static bool RewriteSecurity(FileSystemSecurity security, MachineSid oldSid, MachineSid newSid)
    {
        var changed = false;

        try
        {
            if (security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner &&
                SidMapping.TryMap(owner.Value, oldSid, newSid, out var mappedOwner))
            {
                security.SetOwner(new SecurityIdentifier(mappedOwner));
                changed = true;
            }
        }
        catch
        {
            // Besitzer nicht lesbar
        }

        try
        {
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                if (rule.IsInherited || rule.IdentityReference is not SecurityIdentifier sid)
                {
                    continue;
                }

                if (!SidMapping.TryMap(sid.Value, oldSid, newSid, out var mapped))
                {
                    continue;
                }

                security.RemoveAccessRuleSpecific(rule);
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(mapped),
                    rule.FileSystemRights,
                    rule.InheritanceFlags,
                    rule.PropagationFlags,
                    rule.AccessControlType));
                changed = true;
            }
        }
        catch
        {
            // DACL nicht lesbar
        }

        try
        {
            foreach (FileSystemAuditRule rule in security.GetAuditRules(true, false, typeof(SecurityIdentifier)))
            {
                if (rule.IsInherited || rule.IdentityReference is not SecurityIdentifier sid)
                {
                    continue;
                }

                if (!SidMapping.TryMap(sid.Value, oldSid, newSid, out var mapped))
                {
                    continue;
                }

                security.RemoveAuditRuleSpecific(rule);
                security.AddAuditRule(new FileSystemAuditRule(
                    new SecurityIdentifier(mapped),
                    rule.FileSystemRights,
                    rule.InheritanceFlags,
                    rule.PropagationFlags,
                    rule.AuditFlags));
                changed = true;
            }
        }
        catch
        {
            // SACL nicht lesbar (SeSecurityPrivilege fehlt)
        }

        return changed;
    }

    private static bool TryTakeOwnership(string path)
    {
        if (Directory.Exists(path))
        {
            var security = new DirectorySecurity();
            security.SetOwner(Administrators);
            security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
            return true;
        }

        if (File.Exists(path))
        {
            var security = new FileSecurity();
            security.SetOwner(Administrators);
            security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
            return true;
        }

        return false;
    }
}

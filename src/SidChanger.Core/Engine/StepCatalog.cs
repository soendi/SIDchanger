using System.Net.NetworkInformation;
using System.Security.AccessControl;
using Microsoft.Win32;
using SidChanger.Core.Files;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;
using SidChanger.Core.Operations;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.Core.Engine;

/// <summary>Zeitpunkt eines Schritts innerhalb eines Laufs.</summary>
public enum StepPhase
{
    /// <summary>Vor der eigentlichen Änderung (Sicherungen anlegen).</summary>
    Prepare = 0,

    /// <summary>Eigentliche Änderung.</summary>
    Apply = 1,

    /// <summary>Nach der Änderung (Wiederherstellungen, Nacharbeiten).</summary>
    Finalize = 2,
}

/// <summary>Ein einzelner Änderungsschritt.</summary>
public sealed class ChangeStep
{
    public required ChangeFeature Feature { get; init; }

    public required string Title { get; init; }

    public StepPhase Phase { get; init; } = StepPhase.Apply;

    /// <summary>Führt den Schritt aus.</summary>
    public required Func<ChangeContext, CancellationToken, Task<StepResult>> Run { get; init; }

    /// <summary>Beschreibt für die Analyse, was der Schritt tun würde (ohne Änderung).</summary>
    public Func<ChangeContext, Task<string?>>? Analyze { get; init; }
}

/// <summary>Alle Änderungsschritte in der richtigen Reihenfolge.</summary>
public static class StepCatalog
{
    public const string ProfilesKey = "profiles";
    public const string VaultBackupsKey = "vault-backups";
    public const string DpapiBackupsKey = "dpapi-backups";
    public const string DpapiRootsKey = "dpapi-roots";

    private const string WuPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate";

    /// <summary>Baut die Schrittliste für die ausgewählten Aktionen.</summary>
    public static IReadOnlyList<ChangeStep> Build(ChangeFeature features)
    {
        var steps = new List<ChangeStep>();

        void Add(ChangeStep step)
        {
            if ((features & step.Feature) == step.Feature)
            {
                steps.Add(step);
            }
        }

        // --- Vorbereitung ----------------------------------------------------
        Add(new ChangeStep
        {
            Feature = ChangeFeature.VaultPreserve,
            Title = "Windows Vault sichern",
            Phase = StepPhase.Prepare,
            Run = BackupVaultAsync,
            Analyze = ctx => Task.FromResult<string?>($"Windows Vault von {Profiles(ctx).Count} Profil(en) wird gesichert."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.DpapiEfsKeys,
            Title = "DPAPI-/EFS-Schlüsselmaterial sichern",
            Phase = StepPhase.Prepare,
            Run = BackupDpapiAsync,
            Analyze = ctx => Task.FromResult<string?>($"DPAPI- und Zertifikatsordner ({VaultAndDpapi.GetDpapiPaths(Profiles(ctx)).Count}) werden gesichert."),
        });

        // --- Änderung --------------------------------------------------------
        Add(new ChangeStep
        {
            Feature = ChangeFeature.LogoffOtherUsers,
            Title = "Andere Benutzer abmelden",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var count = AdministrativeActions.LogoffOtherSessions(ctx.Info, ctx.Warn, ct);
                return count == 0
                    ? StepResult.Ok(ChangeFeature.LogoffOtherUsers, "Andere Benutzer abmelden", "Keine weiteren aktiven Sitzungen gefunden.")
                    : StepResult.Ok(ChangeFeature.LogoffOtherUsers, "Andere Benutzer abmelden", $"{count} Sitzung(en) abgemeldet.", count);
            }, ct),
            Analyze = _ => Task.FromResult<string?>("Angemeldete Benutzer werden abgemeldet."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.MachineSid,
            Title = "Computer-SID ersetzen",
            Run = ReplaceMachineSidAsync,
            Analyze = AnalyzeMachineSidAsync,
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ProfileAcl,
            Title = "NTFS-Rechte der Profile anpassen",
            Run = FixProfileAclsAsync,
            Analyze = ctx => Task.FromResult<string?>(
                $"{Profiles(ctx).Count(p => p.Exists)} Profilordner werden angepasst" +
                (ctx.Request.RecursiveProfileAcl ? " (rekursiv)." : " (nur Stammordner).")),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ProfileList,
            Title = "Benutzerprofile umschlüsseln",
            Run = FixProfileListAsync,
            Analyze = ctx => Task.FromResult<string?>(
                $"{ProfileListFixer.Plan(ctx.RequireOldSid(), ctx.NewSid, ctx.Warn).Count} ProfileList-Einträge werden umbenannt."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.TaskScheduler,
            Title = "Taskplaner-Aufgaben korrigieren",
            Run = FixTasksAsync,
            Analyze = ctx => Task.FromResult<string?>(
                $"{TaskSchedulerFixer.CountAffectedFiles(ctx.RequireOldSid(), ctx.Warn)} Aufgaben enthalten die alte SID."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.WsusId,
            Title = "WSUS-ID / Update-ID erneuern",
            Run = ResetWsusAsync,
            Analyze = ctx => Task.FromResult<string?>(DescribeValues(ctx, new[] { (RegistryHive.LocalMachine, WuPath, "SusClientId") })),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.MachineGuid,
            Title = "MachineGuid erneuern",
            Run = (ctx, ct) => SetGuidsAsync(ctx, ChangeFeature.MachineGuid, "MachineGuid erneuern",
                new[] { (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Cryptography", "MachineGuid") }, createIfMissing: true, braces: false),
            Analyze = ctx => Task.FromResult<string?>(DescribeValues(ctx, new[] { (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Cryptography", "MachineGuid") })),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.MachineId,
            Title = "Machine ID (SQM) erneuern",
            Run = (ctx, ct) => SetGuidsAsync(ctx, ChangeFeature.MachineId, "Machine ID (SQM) erneuern",
                new[] { (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\SQMClient", "MachineId") }, createIfMissing: true, braces: true),
            Analyze = ctx => Task.FromResult<string?>(DescribeValues(ctx, new[] { (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\SQMClient", "MachineId") })),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ModernAppsDeviceId,
            Title = "Geräte-ID moderner Apps erneuern",
            Run = (ctx, ct) => SetGuidsAsync(ctx, ChangeFeature.ModernAppsDeviceId, "Geräte-ID moderner Apps erneuern",
                DeviceIdTargets, createIfMissing: false, braces: true),
            Analyze = ctx => Task.FromResult<string?>(DescribeValues(ctx, DeviceIdTargets)),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.GlobalDeviceId,
            Title = "Globale Geräte-ID erneuern",
            Run = (ctx, ct) => SetGuidsAsync(ctx, ChangeFeature.GlobalDeviceId, "Globale Geräte-ID erneuern",
                new[] { (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Store", "GlobalDeviceId") }, createIfMissing: false, braces: true),
            Analyze = ctx => Task.FromResult<string?>(
                "Globale Geräte-ID wird ersetzt – kann die Windows-Aktivierung beeinflussen. " +
                DescribeValues(ctx, new[] { (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Store", "GlobalDeviceId") })),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.MsdtcCid,
            Title = "MSDTC-CID erneuern",
            Run = (ctx, ct) => SetGuidsAsync(ctx, ChangeFeature.MsdtcCid, "MSDTC-CID erneuern",
                new[]
                {
                    (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\MSDTC", "CID"),
                    (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\MSDTC", "CID"),
                }, createIfMissing: false, braces: true),
            Analyze = ctx => Task.FromResult<string?>(DescribeValues(ctx, new[]
            {
                (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\MSDTC", "CID"),
            })),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.Dhcpv6Duid,
            Title = "DHCPv6-DUID erneuern",
            Run = ResetDuidAsync,
            Analyze = ctx => Task.FromResult<string?>(
                RegistryUtil.ValueExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "Dhcpv6DUID")
                    ? "Die DHCPv6-DUID wird gelöscht; Windows erzeugt beim nächsten Start eine neue."
                    : "Keine DHCPv6-DUID vorhanden."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ActionCenter,
            Title = "Info-Center-Einstellungen zurücksetzen",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var changed = AdministrativeActions.ResetActionCenter(ctx.Info, ctx.Warn);
                return StepResult.Ok(ChangeFeature.ActionCenter, "Info-Center-Einstellungen zurücksetzen",
                    $"{changed} Einträge zurückgesetzt.", changed);
            }, ct),
            Analyze = _ => Task.FromResult<string?>("Benachrichtigungs- und Info-Center-Einstellungen werden zurückgesetzt."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ComputerName,
            Title = "Computernamen ändern",
            Run = SetComputerNameAsync,
            Analyze = ctx => Task.FromResult<string?>(ComputerNameDescription(ctx)),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ComputerDescription,
            Title = "Computerbeschreibung ändern",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var text = ctx.Request.NewComputerDescription ?? string.Empty;
                AdministrativeActions.SetComputerDescription(text, ctx.Info, ctx.Warn);
                return StepResult.Ok(ChangeFeature.ComputerDescription, "Computerbeschreibung ändern",
                    $"Beschreibung auf \"{text}\" gesetzt.", 1);
            }, ct),
            Analyze = ctx => Task.FromResult<string?>($"Beschreibung wird auf \"{ctx.Request.NewComputerDescription}\" gesetzt."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.McAfeeId,
            Title = "McAfee-Agent-ID zurücksetzen",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var changed = AdministrativeActions.ResetMcAfeeId(ctx.Info, ctx.Warn);
                return changed
                    ? StepResult.Ok(ChangeFeature.McAfeeId, "McAfee-Agent-ID zurücksetzen", "AgentGUID ersetzt.", 1)
                    : StepResult.NotAvailable(ChangeFeature.McAfeeId, "McAfee-Agent-ID zurücksetzen", "Kein McAfee Agent installiert.");
            }, ct),
            Analyze = _ => Task.FromResult<string?>("McAfee-AgentGUID wird ersetzt, falls McAfee installiert ist."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.OneDriveReset,
            Title = "OneDrive zurücksetzen",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var changed = AdministrativeActions.ResetOneDrive(ctx.Info, ctx.Warn);
                return StepResult.Ok(ChangeFeature.OneDriveReset, "OneDrive zurücksetzen",
                    $"{changed} Kontobindungen/Einstellungen entfernt. OneDrive-Konto muss neu angemeldet werden.", changed);
            }, ct),
            Analyze = _ => Task.FromResult<string?>("OneDrive-Kontobindung und lokale Einstellungen werden entfernt."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.SearchReset,
            Title = "Windows-Suche zurücksetzen",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var deleted = AdministrativeActions.ResetSearch(ctx.Info, ctx.Warn);
                return StepResult.Ok(ChangeFeature.SearchReset, "Windows-Suche zurücksetzen",
                    $"{deleted} Suchdatenbank-Dateien gelöscht. Neuaufbau beim nächsten Anmelden.", deleted);
            }, ct),
            Analyze = _ => Task.FromResult<string?>("Die Suchdatenbank wird gelöscht und beim nächsten Anmelden neu aufgebaut."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.ModernAppsReset,
            Title = "Moderne Apps zurücksetzen",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var (reset, failed, _) = AdministrativeActions.ResetModernApps(ctx.Request.AppxFilters, ctx.Info, ctx.Warn);
                return failed == 0
                    ? StepResult.Ok(ChangeFeature.ModernAppsReset, "Moderne Apps zurücksetzen", $"{reset} Apps zurückgesetzt.", reset)
                    : StepResult.Warn(ChangeFeature.ModernAppsReset, "Moderne Apps zurücksetzen",
                        $"{reset} Apps zurückgesetzt, {failed} fehlgeschlagen (siehe Protokoll).", reset);
            }, ct),
            Analyze = ctx => Task.FromResult<string?>($"Moderne Apps mit Filter \"{ctx.Request.AppxFilters}\" werden zurückgesetzt."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.DefaultAppsReset,
            Title = "Standard-Apps zurücksetzen",
            Run = (ctx, ct) => Task.Run(() =>
            {
                var removed = AdministrativeActions.ResetDefaultApps(ctx.Info, ctx.Warn);
                return StepResult.Ok(ChangeFeature.DefaultAppsReset, "Standard-Apps zurücksetzen",
                    $"{removed} Dateizuordnungen zurückgesetzt.", removed);
            }, ct),
            Analyze = _ => Task.FromResult<string?>("Dateizuordnungen des aktuellen Benutzers werden entfernt."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.SqlMaster,
            Title = "SQL-Server-master-Datenbank anpassen",
            Run = FixSqlMasterAsync,
            Analyze = ctx => Task.FromResult<string?>(
                SqlMasterFixer.Detect(ctx.Warn) is { } sql
                    ? $"SQL Server \"{sql.InstanceName}\" gefunden: master wird gesichert, Reparaturskript erstellt."
                    : "Kein lokaler SQL Server mit sqlcmd gefunden."),
        });

        // --- Abschluss -------------------------------------------------------
        Add(new ChangeStep
        {
            Feature = ChangeFeature.DpapiEfsKeys,
            Title = "DPAPI-/EFS-Material an neue SID anpassen",
            Phase = StepPhase.Finalize,
            Run = FinalizeDpapiAsync,
            Analyze = _ => Task.FromResult<string?>("Sicherung wird zurückgespielt, SID in Schlüsseldateien ersetzt, ACLs angepasst."),
        });

        Add(new ChangeStep
        {
            Feature = ChangeFeature.VaultPreserve,
            Title = "Windows Vault wiederherstellen",
            Phase = StepPhase.Finalize,
            Run = RestoreVaultAsync,
            Analyze = _ => Task.FromResult<string?>("Der gesicherte Windows Vault wird zurückgespielt."),
        });

        return steps;
    }

    // --- Maschinen-SID ------------------------------------------------------

    private static Task<string?> AnalyzeMachineSidAsync(ChangeContext ctx)
    {
        return Task.Run<string?>(() =>
        {
            var oldSid = ctx.RequireOldSid();
            var replacements = 0;
            var values = 0;

            using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default))
            using (var sam = baseKey.OpenSubKey(@"SAM\SAM", RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey))
            {
                if (sam is not null)
                {
                    var count = RegistryUtil.CountTree(sam, @"SAM\SAM", oldSid, CancellationToken.None);
                    replacements += count.Replacements;
                    values += count.ValuesChanged;
                }
            }

            var accounts = MachineSidReader.CountLocalAccounts(oldSid, ctx.Warn);

            return $"{replacements} SID-Vorkommen in {values} SAM-Werten, {accounts} lokale Konten. Neue SID: {ctx.NewSid.Value}";
        });
    }

    private static Task<StepResult> ReplaceMachineSidAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const ChangeFeature feature = ChangeFeature.MachineSid;
            var oldSid = ctx.RequireOldSid();
            var newSid = ctx.NewSid;

            if (oldSid.Equals(newSid))
            {
                return StepResult.Warn(feature, "Computer-SID ersetzen", "Die neue SID ist mit der alten identisch – nichts zu tun.");
            }

            ctx.Info($"Ersetze {oldSid.Value} durch {newSid.Value} ...");

            // Besitz übernehmen, damit SAM und SECURITY schreibbar sind.
            var granted = RegistryKeyAccess.GrantRecursive(RegistryHive.LocalMachine, @"SAM\SAM", ctx.Info, ctx.Warn, ct);
            ctx.Detail($"{granted} SAM-Schlüssel übernommen.");

            foreach (var path in new[] { @"SECURITY\Policy\Secrets", @"SECURITY\Cache", @"SECURITY\Policy\Accounts" })
            {
                if (RegistryUtil.KeyExists(RegistryHive.LocalMachine, path))
                {
                    granted += RegistryKeyAccess.GrantRecursive(RegistryHive.LocalMachine, path, ctx.Info, ctx.Warn, ct);
                }
            }

            ctx.Detail($"{granted} Schlüssel insgesamt übernommen.");

            var values = 0;
            var replacements = 0;
            var errors = 0;

            // 1) SAM
            using (var sam = RegistryKeyAccess.OpenWritable(RegistryHive.LocalMachine, @"SAM\SAM", ctx.Info, ctx.Warn))
            {
                if (sam is null)
                {
                    return StepResult.Error(feature, "Computer-SID ersetzen",
                        @"HKLM\SAM\SAM ist nicht schreibbar. Bitte als Administrator ausführen.");
                }

                var result = RegistryUtil.PatchTree(sam, RegistryHive.LocalMachine, @"SAM\SAM", oldSid, newSid, ctx.Backup, ctx.Info, ctx.Warn, ct);
                values += result.ValuesChanged;
                replacements += result.Replacements;
                errors += result.Errors;
                ctx.Success($"SAM: {result.Replacements} SID-Vorkommen in {result.ValuesChanged} Werten ersetzt.");
            }

            // 2) SECURITY (LSA-Secrets, Zertifikats-/Anmeldedaten)
            using (var security = RegistryKeyAccess.OpenWritable(RegistryHive.LocalMachine, @"SECURITY", ctx.Info, ctx.Warn))
            {
                if (security is null)
                {
                    ctx.Warn(@"HKLM\SECURITY ist nicht schreibbar – LSA-Daten bleiben unverändert.");
                }
                else
                {
                    var result = RegistryUtil.PatchTree(security, RegistryHive.LocalMachine, @"SECURITY", oldSid, newSid, ctx.Backup, ctx.Info, ctx.Warn, ct);
                    values += result.ValuesChanged;
                    replacements += result.Replacements;
                    errors += result.Errors;
                    ctx.Success($"SECURITY: {result.Replacements} SID-Vorkommen in {result.ValuesChanged} Werten ersetzt.");
                }
            }

            // 3) Anmeldeinformationen unter SOFTWARE (Text-SIDs, z. B. letzter angemeldeter Benutzer)
            TryPatchSoftwareKey(ctx, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication", oldSid, newSid, ref values, ref replacements, ct);

            // 4) Verifizieren
            var verified = false;
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var account = baseKey.OpenSubKey(@"SAM\SAM\Domains\Account", RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey);
                if (account?.GetValue("V") is byte[] v && SidBinary.TryFindDomainSid(v, out var readSid))
                {
                    verified = readSid is not null && readSid.Equals(newSid);
                }
            }
            catch (Exception ex)
            {
                ctx.Warn($"Verifikation nicht möglich: {ex.Message}");
            }

            if (!verified)
            {
                return StepResult.Error(feature, "Computer-SID ersetzen",
                    $"Die neue SID konnte nicht in der SAM verifiziert werden! {replacements} Vorkommen wurden ersetzt. " +
                    "Bitte Sicherung prüfen und ggf. wiederherstellen.");
            }

            ctx.Success($"Computer-SID geändert: {oldSid.Value} → {newSid.Value} (verifiziert).");

            return StepResult.Ok(feature, "Computer-SID ersetzen",
                $"Neue SID {newSid.Value} gesetzt und verifiziert ({replacements} Vorkommen in {values} Werten{(errors > 0 ? $", {errors} Fehler" : string.Empty)}).",
                values);
        }, ct);
    }

    private static void TryPatchSoftwareKey(
        ChangeContext ctx,
        string path,
        MachineSid oldSid,
        MachineSid newSid,
        ref int values,
        ref int replacements,
        CancellationToken ct)
    {
        try
        {
            using var key = RegistryKeyAccess.OpenWritable(RegistryHive.LocalMachine, path, ctx.Info, ctx.Warn);
            if (key is null)
            {
                return;
            }

            var result = RegistryUtil.PatchTree(key, RegistryHive.LocalMachine, path, oldSid, newSid, ctx.Backup, ctx.Info, ctx.Warn, ct);
            values += result.ValuesChanged;
            replacements += result.Replacements;
        }
        catch (Exception ex)
        {
            ctx.Warn($"{path} konnte nicht angepasst werden: {ex.Message}");
        }
    }

    // --- Profile ------------------------------------------------------------

    private static IReadOnlyList<ProfileEntry> Profiles(ChangeContext ctx)
    {
        if (ctx.Bag.TryGetValue(ProfilesKey, out var value) && value is IReadOnlyList<ProfileEntry> list)
        {
            return list;
        }

        return ctx.FindProfiles();
    }

    private static Task<StepResult> FixProfileListAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var changed = ProfileListFixer.Apply(ctx.RequireOldSid(), ctx.NewSid, ctx.Backup, ctx.Info, ctx.Warn, ct);
            return changed == 0
                ? StepResult.NotAvailable(ChangeFeature.ProfileList, "Benutzerprofile umschlüsseln", "Keine Profile mit der alten SID gefunden.")
                : StepResult.Ok(ChangeFeature.ProfileList, "Benutzerprofile umschlüsseln", $"{changed} ProfileList-Einträge umgeschlüsselt.", changed);
        }, ct);
    }

    private static Task<StepResult> FixProfileAclsAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var oldSid = ctx.RequireOldSid();
            var profiles = Profiles(ctx).Where(p => p.Exists).ToList();

            if (profiles.Count == 0)
            {
                return StepResult.NotAvailable(ChangeFeature.ProfileAcl, "NTFS-Rechte der Profile anpassen",
                    "Keine vorhandenen Profilordner gefunden.");
            }

            var changed = 0;
            var errors = 0;
            var visited = 0;

            foreach (var profile in profiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.Info($"Passe Berechtigungen an: {profile.ImagePath}");

                var result = AclFixer.FixPath(
                    profile.ImagePath,
                    oldSid,
                    ctx.NewSid,
                    ctx.Request.RecursiveProfileAcl,
                    ctx.Backup,
                    ctx.Info,
                    ctx.Warn,
                    ct);

                changed += result.ObjectsChanged;
                errors += result.Errors;
                visited += result.ObjectsVisited;
            }

            var message = $"{changed} von {visited} Objekten angepasst" + (errors > 0 ? $", {errors} Fehler" : string.Empty) + ".";

            return errors > 0 && changed == 0
                ? StepResult.Error(ChangeFeature.ProfileAcl, "NTFS-Rechte der Profile anpassen", message)
                : StepResult.Ok(ChangeFeature.ProfileAcl, "NTFS-Rechte der Profile anpassen", message, changed);
        }, ct);
    }

    private static Task<StepResult> FixTasksAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var (files, registryValues) = TaskSchedulerFixer.Apply(ctx.RequireOldSid(), ctx.NewSid, ctx.Backup, ctx.Info, ctx.Warn, ct);

            return files + registryValues == 0
                ? StepResult.NotAvailable(ChangeFeature.TaskScheduler, "Taskplaner-Aufgaben korrigieren", "Keine Aufgaben mit der alten SID gefunden.")
                : StepResult.Ok(ChangeFeature.TaskScheduler, "Taskplaner-Aufgaben korrigieren",
                    $"{files} Aufgabendateien und {registryValues} Registrierungswerte angepasst.", files + registryValues);
        }, ct);
    }

    // --- Kennungen ----------------------------------------------------------

    private static readonly (RegistryHive Hive, string Path, string Name)[] DeviceIdTargets =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Store", "DeviceId"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Appx", "DeviceId"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\Deployment", "DeviceId"),
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid"),
    };

    private static string DescribeValues(ChangeContext ctx, IEnumerable<(RegistryHive Hive, string Path, string Name)> targets)
    {
        var parts = new List<string>();

        foreach (var (hive, path, name) in targets)
        {
            if (RegistryUtil.ValueExists(hive, path, name))
            {
                var current = RegistryUtil.ReadString(hive, path, name);
                parts.Add($"{name} = \"{current}\"");
            }
        }

        return parts.Count == 0
            ? "Keine der bekannten Kennungen vorhanden – es wird nichts geändert."
            : "Wird ersetzt: " + string.Join(", ", parts) + ".";
    }

    private static Task<StepResult> SetGuidsAsync(
        ChangeContext ctx,
        ChangeFeature feature,
        string title,
        IEnumerable<(RegistryHive Hive, string Path, string Name)> targets,
        bool createIfMissing,
        bool braces)
    {
        return Task.Run(() =>
        {
            var changed = 0;
            var missing = new List<string>();

            foreach (var (hive, path, name) in targets)
            {
                try
                {
                    var exists = RegistryUtil.ValueExists(hive, path, name);
                    if (!exists && !createIfMissing)
                    {
                        missing.Add(name);
                        continue;
                    }

                    var value = braces
                        ? "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}"
                        : Guid.NewGuid().ToString();

                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(path, writable: true)
                                    ?? baseKey.CreateSubKey(path, writable: true);

                    if (key is null)
                    {
                        ctx.Warn($"{path} konnte nicht geöffnet werden.");
                        continue;
                    }

                    if (exists)
                    {
                        ctx.Backup.RecordRegistry(hive, path, name, key.GetValue(name), key.GetValueKind(name));
                    }

                    key.SetValue(name, value, RegistryValueKind.String);
                    changed++;
                    ctx.Info($"{path}\\{name} = {value}");
                }
                catch (Exception ex)
                {
                    ctx.Warn($"{path}\\{name} konnte nicht gesetzt werden: {ex.Message}");
                }
            }

            if (changed == 0)
            {
                return StepResult.NotAvailable(feature, title,
                    missing.Count > 0
                        ? $"Nicht vorhanden: {string.Join(", ", missing)} – es wurde nichts geändert."
                        : "Keine passenden Registrierungswerte gefunden.");
            }

            return StepResult.Ok(feature, title, $"{changed} Kennung(en) erneuert" +
                                               (missing.Count > 0 ? $", nicht vorhanden: {string.Join(", ", missing)}" : string.Empty) + ".",
                changed);
        });
    }

    private static Task<StepResult> ResetWsusAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string title = "WSUS-ID / Update-ID erneuern";

            if (!RegistryUtil.KeyExists(RegistryHive.LocalMachine, WuPath))
            {
                return StepResult.NotAvailable(ChangeFeature.WsusId, title,
                    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate nicht vorhanden.");
            }

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(WuPath, writable: true);
                if (key is null)
                {
                    return StepResult.Error(ChangeFeature.WsusId, title, "WindowsUpdate-Schlüssel ist nicht schreibbar.");
                }

                foreach (var name in new[] { "SusClientId", "PingID" })
                {
                    var existing = key.GetValue(name) as string;
                    ctx.Backup.RecordRegistry(RegistryHive.LocalMachine, WuPath, name, existing, RegistryValueKind.String);
                    key.SetValue(name, Guid.NewGuid().ToString(), RegistryValueKind.String);
                    ctx.Info($"{name} erneuert (war: {existing ?? "nicht vorhanden"}).");
                }

                if (key.GetValue("SusClientIdValidation") is byte[] validation)
                {
                    ctx.Backup.RecordRegistry(RegistryHive.LocalMachine, WuPath, "SusClientIdValidation", validation, RegistryValueKind.Binary);
                    key.DeleteValue("SusClientIdValidation", throwOnMissingValue: false);
                    ctx.Info("SusClientIdValidation entfernt.");
                }

                return StepResult.Ok(ChangeFeature.WsusId, title, "SusClientId und PingID erneuert, alte Prüfsumme entfernt.", 3);
            }
            catch (Exception ex)
            {
                return StepResult.Error(ChangeFeature.WsusId, title, ex.Message);
            }
        }, ct);
    }

    private static Task<StepResult> ResetDuidAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string path = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
            const string name = "Dhcpv6DUID";

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(path, writable: true);

                if (key?.GetValue(name) is not byte[] existing)
                {
                    return StepResult.NotAvailable(ChangeFeature.Dhcpv6Duid, "DHCPv6-DUID erneuern", "Keine DHCPv6-DUID vorhanden.");
                }

                ctx.Backup.RecordRegistry(RegistryHive.LocalMachine, path, name, existing, RegistryValueKind.Binary);
                key.DeleteValue(name, throwOnMissingValue: false);
                ctx.Info("DHCPv6-DUID gelöscht – Windows erzeugt beim nächsten Start eine neue.");

                return StepResult.Ok(ChangeFeature.Dhcpv6Duid, "DHCPv6-DUID erneuern", "DUID gelöscht (Neuerzeugung beim Neustart).", 1);
            }
            catch (Exception ex)
            {
                return StepResult.Error(ChangeFeature.Dhcpv6Duid, "DHCPv6-DUID erneuern", ex.Message);
            }
        }, ct);
    }

    // --- Computername -------------------------------------------------------

    private static string ResolveComputerName(ChangeContext ctx)
    {
        var pattern = ctx.Request.NewComputerName ?? string.Empty;
        if (pattern.Contains('?') || pattern.Contains('*'))
        {
            return ComputerNameRules.ExpandWildcards(pattern, GetMacHex());
        }

        return ComputerNameRules.Normalize(pattern);
    }

    private static string ComputerNameDescription(ChangeContext ctx)
    {
        var name = ResolveComputerName(ctx);
        var errors = ComputerNameRules.Validate(name);

        return errors.Count > 0
            ? "Ungültiger Computername: " + string.Join(" ", errors)
            : $"Computername wird von \"{ctx.ComputerName}\" auf \"{name}\" geändert (Neustart erforderlich).";
    }

    private static Task<StepResult> SetComputerNameAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string title = "Computernamen ändern";
            var name = ResolveComputerName(ctx);
            var errors = ComputerNameRules.Validate(name);

            if (errors.Count > 0)
            {
                return StepResult.Error(ChangeFeature.ComputerName, title, string.Join(" ", errors));
            }

            if (string.Equals(name, ctx.ComputerName, StringComparison.OrdinalIgnoreCase))
            {
                return StepResult.Warn(ChangeFeature.ComputerName, title,
                    $"Der Computername ist bereits \"{name}\" – keine Änderung nötig.");
            }

            var (apiOk, detail) = AdministrativeActions.SetComputerName(name, ctx.Info, ctx.Warn);
            return apiOk
                ? StepResult.Ok(ChangeFeature.ComputerName, title, detail, 1)
                : StepResult.Warn(ChangeFeature.ComputerName, title, detail, 1);
        }, ct);
    }

    private static string? GetMacHex()
    {
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up &&
                                     n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                     n.GetPhysicalAddress().GetAddressBytes().Length == 6);

            return nic?.GetPhysicalAddress().ToString();
        }
        catch
        {
            return null;
        }
    }

    // --- Vault / DPAPI ------------------------------------------------------

    private static Task<StepResult> BackupVaultAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var paths = VaultAndDpapi.GetVaultPaths(Profiles(ctx));
            if (paths.Count == 0)
            {
                return StepResult.NotAvailable(ChangeFeature.VaultPreserve, "Windows Vault sichern", "Kein Windows Vault gefunden.");
            }

            var backups = VaultAndDpapi.Backup(paths, ctx.BackupDirectory, "vault", ctx.Info, ctx.Warn, ct);
            ctx.Bag[VaultBackupsKey] = backups;

            return backups.Count == 0
                ? StepResult.Warn(ChangeFeature.VaultPreserve, "Windows Vault sichern", "Es konnten keine Vault-Daten gesichert werden.")
                : StepResult.Ok(ChangeFeature.VaultPreserve, "Windows Vault sichern",
                    $"{backups.Count} Ordner gesichert.", backups.Count);
        }, ct);
    }

    private static Task<StepResult> RestoreVaultAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            if (!ctx.Bag.TryGetValue(VaultBackupsKey, out var value) || value is not IReadOnlyList<FolderBackup> backups || backups.Count == 0)
            {
                return StepResult.NotAvailable(ChangeFeature.VaultPreserve, "Windows Vault wiederherstellen", "Keine Sicherung vorhanden.");
            }

            var restored = VaultAndDpapi.Restore(backups, ctx.Info, ctx.Warn, ct);
            VaultAndDpapi.FixMaterial(ctx.RequireOldSid(), ctx.NewSid,
                backups.Select(b => Path.GetDirectoryName(b.Source) ?? b.Source).Distinct(), ctx.Info, ctx.Warn, ct);

            return StepResult.Ok(ChangeFeature.VaultPreserve, "Windows Vault wiederherstellen",
                $"{restored} Dateien zurückgespielt.", restored);
        }, ct);
    }

    private static Task<StepResult> BackupDpapiAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var roots = VaultAndDpapi.GetDpapiPaths(Profiles(ctx));
            if (roots.Count == 0)
            {
                return StepResult.NotAvailable(ChangeFeature.DpapiEfsKeys, "DPAPI-/EFS-Schlüsselmaterial sichern",
                    "Keine DPAPI-/Zertifikatsordner gefunden.");
            }

            var backups = VaultAndDpapi.Backup(roots, ctx.BackupDirectory, "dpapi", ctx.Info, ctx.Warn, ct);
            ctx.Bag[DpapiBackupsKey] = backups;
            ctx.Bag[DpapiRootsKey] = roots;

            return backups.Count == 0
                ? StepResult.Warn(ChangeFeature.DpapiEfsKeys, "DPAPI-/EFS-Schlüsselmaterial sichern", "Keine Daten gesichert.")
                : StepResult.Ok(ChangeFeature.DpapiEfsKeys, "DPAPI-/EFS-Schlüsselmaterial sichern",
                    $"{backups.Count} Ordner gesichert.", backups.Count);
        }, ct);
    }

    private static Task<StepResult> FinalizeDpapiAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string title = "DPAPI-/EFS-Material an neue SID anpassen";

            if (ctx.Bag.TryGetValue(DpapiBackupsKey, out var value) && value is IReadOnlyList<FolderBackup> backups)
            {
                VaultAndDpapi.Restore(backups, ctx.Info, ctx.Warn, ct);
            }

            var roots = ctx.Bag.TryGetValue(DpapiRootsKey, out var rootsValue) && rootsValue is IReadOnlyList<string> list
                ? list
                : VaultAndDpapi.GetDpapiPaths(Profiles(ctx));

            var result = VaultAndDpapi.FixMaterial(ctx.RequireOldSid(), ctx.NewSid, roots, ctx.Info, ctx.Warn, ct);

            return StepResult.Ok(ChangeFeature.DpapiEfsKeys, title,
                $"{result.Renamed} Ordner umbenannt, {result.Replacements} SID-Vorkommen in {result.Files} Dateien ersetzt, {result.AclObjects} ACLs angepasst.",
                result.Files + result.Renamed);
        }, ct);
    }

    // --- SQL ----------------------------------------------------------------

    private static Task<StepResult> FixSqlMasterAsync(ChangeContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string title = "SQL-Server-master-Datenbank anpassen";

            var server = SqlMasterFixer.Detect(ctx.Warn);
            if (server is null)
            {
                return StepResult.NotAvailable(ChangeFeature.SqlMaster, title, "Kein lokaler SQL Server mit sqlcmd.exe gefunden.");
            }

            var (success, message) = SqlMasterFixer.BackupAndCreateScript(
                server, ctx.RequireOldSid(), ctx.BackupDirectory, ctx.Info, ctx.Warn, ct);

            return success
                ? StepResult.Warn(ChangeFeature.SqlMaster, title, message, 1)
                : StepResult.Error(ChangeFeature.SqlMaster, title, message);
        }, ct);
    }
}

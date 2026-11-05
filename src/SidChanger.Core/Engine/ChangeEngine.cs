using SidChanger.Core.Files;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;
using SidChanger.Core.Operations;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.Core.Engine;

/// <summary>Ergebnis einer Vorabprüfung.</summary>
public sealed record PreflightReport(IReadOnlyList<PreflightCheck> Checks, bool Blocked, string Summary);

/// <summary>Ergebnis eines Änderungslaufs.</summary>
public sealed record ChangeResult(
    bool Success,
    bool Blocked,
    IReadOnlyList<StepResult> Steps,
    string BackupDirectory,
    string Summary,
    MachineSid? OldSid,
    MachineSid NewSid);

/// <summary>
/// Führt Vorabprüfung, Analyse und die eigentliche SID-Änderung aus.
/// Die Klasse enthält keine UI-Logik und kann auch aus Tests oder der Kommandozeile genutzt werden.
/// </summary>
public sealed class ChangeEngine
{
    private readonly Action<LogEntry> _log;
    private readonly Action<StepResult>? _stepSink;
    private readonly Action<string>? _stepStarted;

    public ChangeEngine(Action<LogEntry> log, Action<StepResult>? stepSink = null, Action<string>? stepStarted = null)
    {
        _log = log;
        _stepSink = stepSink;
        _stepStarted = stepStarted;
    }

    public IReadOnlyList<PreflightCheck> Preflight { get; private set; } = Array.Empty<PreflightCheck>();

    public MachineSid? CurrentSid { get; private set; }

    public string SidSource { get; private set; } = string.Empty;

    public string BackupDirectory { get; private set; } = string.Empty;

    /// <summary>Liest die aktuelle SID und führt alle Vorabprüfungen aus.</summary>
    public async Task<PreflightReport> RunPreflightAsync(ChangeRequest request, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var errors = TokenPrivileges.EnableAllRequired();
            foreach (var error in errors)
            {
                _log(new LogEntry(DateTime.Now, LogLevel.Warning, error));
            }

            var (sid, source) = ReadCurrentSid();
            CurrentSid = sid;
            SidSource = source;

            var checks = new List<PreflightCheck>(SystemChecks.Run());
            Preflight = checks;

            var blocking = checks.Where(c => !c.Passed && c.Blocking).ToList();
            var blocked = blocking.Count > 0 && !request.IgnorePreflightWarnings;

            var summary = blocked
                ? "Vorabprüfung nicht bestanden: " + string.Join(" | ", blocking.Select(c => c.Name))
                : blocking.Count > 0
                    ? "Vorabprüfung mit überstimmten Warnungen: " + string.Join(" | ", blocking.Select(c => c.Name))
                    : "Alle Vorabprüfungen bestanden.";

            _log(new LogEntry(DateTime.Now, blocked ? LogLevel.Error : LogLevel.Success, summary));
            return new PreflightReport(checks, blocked, summary);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Liest die aktuelle Maschinen-SID neu ein (nach einer Änderung).</summary>
    public MachineSid? RefreshCurrentSid()
    {
        var (sid, source) = ReadCurrentSid();
        CurrentSid = sid;
        SidSource = source;
        return sid;
    }

    private (MachineSid? Sid, string Source) ReadCurrentSid()
    {
        var sid = MachineSidReader.TryRead(
            message => _log(new LogEntry(DateTime.Now, LogLevel.Detail, message)),
            message => _log(new LogEntry(DateTime.Now, LogLevel.Warning, message)),
            out var source);

        return (sid, source);
    }

    /// <summary>Analysiert den Auftrag, ohne etwas zu verändern.</summary>
    public async Task<IReadOnlyList<StepResult>> AnalyzeAsync(ChangeRequest request, CancellationToken cancellationToken = default)
    {
        // Ein SID-Wechsel bringt Profile, Profilrechte und Taskplaner immer mit.
        request.Features = FeatureDependencies.EnsureSidCompanions(request.Features);

        var errors = request.Validate();
        if (errors.Count > 0)
        {
            return errors.Select(e => StepResult.Error(ChangeFeature.None, "Auftrag", e)).ToList();
        }

        var oldSid = CurrentSid ?? RefreshCurrentSid();
        var newSid = request.ResolveNewSid();
        var directory = Path.Combine(AppPaths.TempDirectory, "analyse-" + DateTime.Now.ToString("HHmmss"));
        Directory.CreateDirectory(directory);

        var context = new ChangeContext(request, oldSid, newSid, directory)
        {
            Simulation = true,
            LogSink = _log,
            StepSink = _stepSink,
            PrivilegeErrors = TokenPrivileges.EnableAllRequired(),
        };

        if (oldSid is not null)
        {
            context.Bag[StepCatalog.ProfilesKey] = ProfileLocator.ReadForMachine(
                oldSid, message => _log(new LogEntry(DateTime.Now, LogLevel.Warning, message)));
        }

        var results = new List<StepResult>();

        foreach (var step in StepCatalog.Build(request.Features))
        {
            cancellationToken.ThrowIfCancellationRequested();

            _stepStarted?.Invoke(step.Title);

            try
            {
                var description = step.Analyze is null
                    ? "Wird ausgeführt."
                    : await step.Analyze(context).ConfigureAwait(false);

                var result = string.IsNullOrWhiteSpace(description)
                    ? StepResult.NotAvailable(step.Feature, step.Title, "Nicht anwendbar.")
                    : StepResult.Ok(step.Feature, step.Title, description);

                results.Add(result);
            }
            catch (Exception ex)
            {
                results.Add(StepResult.Error(step.Feature, step.Title, ex.Message));
            }
        }

        return results;
    }

    /// <summary>Führt die Änderung aus.</summary>
    public async Task<ChangeResult> ApplyAsync(ChangeRequest request, CancellationToken cancellationToken = default)
    {
        // Ein SID-Wechsel bringt Profile, Profilrechte und Taskplaner immer mit – auch wenn
        // der Auftrag nicht aus der Oberfläche kommt.
        request.Features = FeatureDependencies.EnsureSidCompanions(request.Features);

        var validation = request.Validate();
        if (validation.Count > 0)
        {
            var messages = validation.Select(v => new LogEntry(DateTime.Now, LogLevel.Error, v)).ToList();
            foreach (var message in messages)
            {
                _log(message);
            }

            return new ChangeResult(false, true, Array.Empty<StepResult>(), string.Empty,
                string.Join(" ", validation), CurrentSid, request.ResolveNewSid());
        }

        _log(new LogEntry(DateTime.Now, LogLevel.Info, "===== SID-Änderung gestartet ====="));

        var preflight = await RunPreflightAsync(request, cancellationToken).ConfigureAwait(false);
        if (preflight.Blocked)
        {
            return new ChangeResult(false, true, Array.Empty<StepResult>(), string.Empty, preflight.Summary, CurrentSid, request.ResolveNewSid());
        }

        var oldSid = CurrentSid ?? RefreshCurrentSid();
        var newSid = request.ResolveNewSid();

        if (oldSid is null)
        {
            var message = "Die aktuelle Computer-SID konnte nicht gelesen werden. Bitte als Administrator ausführen.";
            _log(new LogEntry(DateTime.Now, LogLevel.Error, message));
            return new ChangeResult(false, true, Array.Empty<StepResult>(), string.Empty, message, null, newSid);
        }

        if (oldSid.Equals(newSid))
        {
            return new ChangeResult(false, true, Array.Empty<StepResult>(), string.Empty,
                "Die neue SID entspricht der aktuellen SID.", oldSid, newSid);
        }

        BackupDirectory = AppPaths.CreateBackupDirectory(DateTime.Now);

        var context = new ChangeContext(request, oldSid, newSid, BackupDirectory)
        {
            LogSink = _log,
            StepSink = _stepSink,
            PrivilegeErrors = TokenPrivileges.EnableAllRequired(),
        };

        context.Bag[StepCatalog.ProfilesKey] = ProfileLocator.ReadForMachine(
            oldSid, message => _log(new LogEntry(DateTime.Now, LogLevel.Warning, message)));

        context.Backup.SetSids(oldSid, newSid, context.ComputerName);

        RecoveryStore.Save(new RecoveryState
        {
            OldSid = oldSid.Value,
            NewSid = newSid.Value,
            OldComputerName = context.ComputerName,
            BackupDirectory = BackupDirectory,
            Completed = false,
            Features = Enum.GetValues<ChangeFeature>()
                .Where(f => f != ChangeFeature.None && request.Has(f))
                .Select(f => f.ToString())
                .ToList(),
        });

        context.Info($"Sicherungsordner: {BackupDirectory}");
        context.Info($"Alte SID: {oldSid.Value} → neue SID: {newSid.Value}");

        var results = new List<StepResult>();
        var steps = StepCatalog.Build(request.Features)
            .OrderBy(s => (int)s.Phase)
            .ToList();

        foreach (var step in steps)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _log(new LogEntry(DateTime.Now, LogLevel.Info, $"→ {step.Title}"));
            _stepStarted?.Invoke(step.Title);

            try
            {
                var result = await step.Run(context, cancellationToken).ConfigureAwait(false);
                results.Add(result);
                context.Report(result);

                if (result.Status == StepStatus.Error && step.Feature == ChangeFeature.MachineSid)
                {
                    context.Error("Die SID-Ersetzung ist fehlgeschlagen. Weitere Schritte werden abgebrochen; " +
                                  "bitte die Sicherung im Ordner " + BackupDirectory + " prüfen.");
                    break;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                var failed = StepResult.Error(step.Feature, step.Title, ex.Message);
                results.Add(failed);
                context.Report(failed);

                if (step.Phase == StepPhase.Prepare)
                {
                    context.Warn("Ein Vorbereitungsschritt ist fehlgeschlagen – die Änderung läuft weiter, " +
                                 "die betroffenen Daten sind aber nicht gesichert.");
                }
            }
        }

        // Sicherung schreiben (auch bei Teilfehlern).
        try
        {
            context.Backup.Save();
            context.Info($"Sicherung geschrieben: {context.Backup.FilePath} ({context.Backup.RegistryCount} Werte, {context.Backup.AclCount} ACLs).");
        }
        catch (Exception ex)
        {
            context.Warn($"Sicherung konnte nicht geschrieben werden: {ex.Message}");
        }

        var failedSteps = results.Count(r => r.Status == StepStatus.Error);
        var success = failedSteps == 0;

        RecoveryStore.Save(new RecoveryState
        {
            OldSid = oldSid.Value,
            NewSid = newSid.Value,
            OldComputerName = context.ComputerName,
            BackupDirectory = BackupDirectory,
            Completed = success,
            Features = results.Select(r => r.Feature.ToString()).Distinct().ToList(),
        });

        // Neue SID einlesen (nur wenn sie geändert wurde).
        if (request.ChangesMachineSid)
        {
            var newCurrent = RefreshCurrentSid();
            context.Info($"Aktuell gelesene SID: {newCurrent?.Value ?? "unbekannt"}");
        }

        if (success && request.PostAction != PostChangeAction.None)
        {
            AdministrativeActions.SchedulePostAction(request.PostAction, 30, context.Info);
        }

        _log(new LogEntry(DateTime.Now, success ? LogLevel.Success : LogLevel.Error,
            success ? "===== SID-Änderung abgeschlossen =====" : $"===== SID-Änderung mit {failedSteps} Fehler(n) beendet ====="));

        var summary = success
            ? $"Änderung abgeschlossen. Neue SID: {newSid.Value}. Sicherung: {BackupDirectory}"
            : $"{failedSteps} Schritt(e) fehlgeschlagen. Sicherung: {BackupDirectory}";

        return new ChangeResult(success, false, results, BackupDirectory, summary, oldSid, newSid);
    }

    /// <summary>
    /// Nimmt die letzte Änderung zurück: SID, Profile und ACLs werden auf die alten Werte
    /// gesetzt und die gesicherten Registrierungswerte zurückgeschrieben.
    /// </summary>
    public async Task<ChangeResult> RevertAsync(Action<string> log, CancellationToken cancellationToken = default)
    {
        var state = RecoveryStore.Load();
        if (state is null)
        {
            throw new InvalidOperationException("Es ist kein letzter Lauf gespeichert, der zurückgenommen werden könnte.");
        }

        if (!MachineSid.TryParse(state.OldSid, out var oldSid, out var error) || oldSid is null)
        {
            throw new InvalidOperationException($"Die gespeicherte SID ist ungültig: {error}");
        }

        log($"Setze SID auf {state.OldSid} zurück ...");

        var request = new ChangeRequest
        {
            GenerateRandomSid = false,
            NewSid = oldSid,
            Features = ChangeFeature.MachineSid | ChangeFeature.ProfileList | ChangeFeature.ProfileAcl | ChangeFeature.TaskScheduler,
            PostAction = PostChangeAction.Reboot,
            RecursiveProfileAcl = true,
            BackupRegistry = false,
            IgnorePreflightWarnings = true,
        };

        var result = await ApplyAsync(request, cancellationToken).ConfigureAwait(false);

        var backupFile = Path.Combine(state.BackupDirectory, "sicherung.json");
        var document = BackupStore.Load(backupFile);
        if (document is not null)
        {
            var (restored, failed) = BackupStore.RestoreRegistry(document, log, message => log("Warnung: " + message));
            log($"{restored} Registrierungswerte zurückgeschrieben, {failed} Fehler.");
        }

        state.Reverted = true;
        state.Completed = false;
        RecoveryStore.Save(state);

        return result;
    }
}

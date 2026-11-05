using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using SidChanger.Core.Engine;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Operations;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.App.ViewModels;

/// <summary>ViewModel des Hauptfensters – verbindet Oberfläche und Änderungs-Engine.</summary>
public sealed class MainViewModel : ObservableObject
{
    private readonly StringBuilder _logBuilder = new();
    private readonly ChangeEngine _engine;
    private readonly System.Windows.Threading.Dispatcher _dispatcher;

    private string _oldSid = "wird gelesen ...";
    private string _newSid = string.Empty;
    private string _sidSource = string.Empty;
    private string _computerName = Environment.MachineName;
    private string _newComputerName = Environment.MachineName;
    private string _newComputerDescription = string.Empty;
    private string _appxFilters = "*";
    private bool _generateRandomSid = true;
    private bool _recursiveAcl = true;
    private bool _ignoreWarnings;
    private int _postActionIndex;
    private bool _isBusy;
    private string _statusText = "Bereit.";
    private string _log = string.Empty;

    public MainViewModel()
    {
        _dispatcher = Application.Current?.Dispatcher ?? System.Windows.Threading.Dispatcher.CurrentDispatcher;
        _engine = new ChangeEngine(AppendLog, AppendStep);

        Features = new ObservableCollection<FeatureOption>(
            FeatureCatalog.All.Select(info => new FeatureOption(info, info.DefaultOn)));

        foreach (var feature in Features)
        {
            feature.PropertyChanged += (_, _) =>
            {
                OnPropertyChanged(nameof(CanApply));
                OnPropertyChanged(nameof(ComputerNameFeature));
                OnPropertyChanged(nameof(DescriptionFeature));
                RaiseCommandStates();
            };
        }

        RegenerateSidCommand = new RelayCommand(RegenerateSid);
        OpenPreflightLinkCommand = new RelayCommand(OpenPreflightLink);
        AnalyzeCommand = new AsyncRelayCommand(AnalyzeAsync, () => IsNotBusy && CanApply);
        ApplyCommand = new AsyncRelayCommand(ApplyAsync, () => IsNotBusy && CanApply);
        RevertCommand = new AsyncRelayCommand(RevertAsync, () => IsNotBusy && HasLastRun);
        OpenBackupFolderCommand = new RelayCommand(OpenBackupFolder);
        SaveLogCommand = new RelayCommand(SaveLog, () => _logBuilder.Length > 0);

        RegenerateSid();
    }

    // --- Zustand -------------------------------------------------------------

    public ObservableCollection<FeatureOption> Features { get; }

    public ObservableCollection<PreflightItem> Preflight { get; } = new();

    public ObservableCollection<StepItem> Steps { get; } = new();

    /// <summary>Mögliche Aktionen nach der Änderung (Reihenfolge entspricht PostActionIndex).</summary>
    public IReadOnlyList<string> PostActionOptions { get; } = new[]
    {
        "Neu starten (empfohlen)",
        "Herunterfahren",
        "Nichts tun",
    };

    public string OldSid
    {
        get => _oldSid;
        private set => SetProperty(ref _oldSid, value);
    }

    public string NewSid
    {
        get => _newSid;
        set => SetProperty(ref _newSid, value);
    }

    public string SidSource
    {
        get => _sidSource;
        private set => SetProperty(ref _sidSource, value);
    }

    public string ComputerName
    {
        get => _computerName;
        private set => SetProperty(ref _computerName, value);
    }

    public string NewComputerName
    {
        get => _newComputerName;
        set => SetProperty(ref _newComputerName, value);
    }

    public string NewComputerDescription
    {
        get => _newComputerDescription;
        set => SetProperty(ref _newComputerDescription, value);
    }

    public string AppxFilters
    {
        get => _appxFilters;
        set => SetProperty(ref _appxFilters, value);
    }

    public bool GenerateRandomSid
    {
        get => _generateRandomSid;
        set
        {
            if (SetProperty(ref _generateRandomSid, value))
            {
                if (value)
                {
                    RegenerateSid();
                }

                OnPropertyChanged(nameof(IsCustomSidEnabled));
            }
        }
    }

    public bool IsCustomSidEnabled => !GenerateRandomSid;

    public bool RecursiveAcl
    {
        get => _recursiveAcl;
        set => SetProperty(ref _recursiveAcl, value);
    }

    public bool IgnoreWarnings
    {
        get => _ignoreWarnings;
        set => SetProperty(ref _ignoreWarnings, value);
    }

    public int PostActionIndex
    {
        get => _postActionIndex;
        set => SetProperty(ref _postActionIndex, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(IsNotBusy));
                RaiseCommandStates();
            }
        }
    }

    public bool IsNotBusy => !IsBusy;

    public string StatusText
    {
        get => _statusText;
        private set => SetProperty(ref _statusText, value);
    }

    public string Log
    {
        get => _log;
        private set => SetProperty(ref _log, value);
    }

    public bool HasLastRun => RecoveryStore.Load() is not null;

    public FeatureOption? ComputerNameFeature => Features.FirstOrDefault(f => f.Feature == ChangeFeature.ComputerName);

    public FeatureOption? DescriptionFeature => Features.FirstOrDefault(f => f.Feature == ChangeFeature.ComputerDescription);

    public bool CanApply => Features.Any(f => f.IsSelected);

    public string FooterHint =>
        "Änderung nur auf Klonen/Images verwenden. Vorher Virenscanner deaktivieren, BitLocker aussetzen und andere Benutzer abmelden.";

    // --- Kommandos -----------------------------------------------------------

    public RelayCommand RegenerateSidCommand { get; }

    public RelayCommand OpenPreflightLinkCommand { get; }

    public AsyncRelayCommand AnalyzeCommand { get; }

    public AsyncRelayCommand ApplyCommand { get; }

    public AsyncRelayCommand RevertCommand { get; }

    public RelayCommand OpenBackupFolderCommand { get; }

    public RelayCommand SaveLogCommand { get; }

    // --- Ablauf --------------------------------------------------------------

    public async Task InitializeAsync()
    {
        IsBusy = true;
        StatusText = "Lese Computer-SID und prüfe das System ...";

        try
        {
            var report = await _engine.RunPreflightAsync(new ChangeRequest { IgnorePreflightWarnings = IgnoreWarnings });
            ApplyPreflight(report);
            RefreshSid();
            StatusText = report.Blocked
                ? "Blockierende Vorabprüfungen gefunden – bitte Punkte rechts prüfen."
                : "Bereit. Bitte Aktionen auswählen und mit „Analyse starten“ prüfen.";
        }
        catch (Exception ex)
        {
            StatusText = "Fehler beim Initialisieren.";
            AppendLog(new LogEntry(DateTime.Now, LogLevel.Error, ex.Message));
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RegenerateSid()
    {
        NewSid = SidGenerator.CreateRandom().Value;
    }

    private ChangeRequest? BuildRequest(bool reportErrors)
    {
        var features = ChangeFeature.None;
        foreach (var feature in Features.Where(f => f.IsSelected))
        {
            features |= feature.Feature;
        }

        if (features == ChangeFeature.None)
        {
            if (reportErrors)
            {
                MessageBox.Show("Bitte mindestens eine Aktion auswählen.", "SID-Wechsler",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }

            return null;
        }

        MachineSid? newSid = null;
        if (features.HasFlag(ChangeFeature.MachineSid))
        {
            if (!MachineSid.TryParse(NewSid, out newSid, out var error))
            {
                if (reportErrors)
                {
                    MessageBox.Show(error, "Ungültige SID", MessageBoxButton.OK, MessageBoxImage.Warning);
                }

                return null;
            }
        }

        var request = new ChangeRequest
        {
            GenerateRandomSid = false,
            NewSid = newSid,
            Features = features,
            NewComputerName = NewComputerName,
            NewComputerDescription = NewComputerDescription,
            RecursiveProfileAcl = RecursiveAcl,
            IgnorePreflightWarnings = IgnoreWarnings,
            AppxFilters = AppxFilters,
            BackupRegistry = true,
            PostAction = PostActionIndex switch
            {
                0 => PostChangeAction.Reboot,
                1 => PostChangeAction.Shutdown,
                _ => PostChangeAction.None,
            },
        };

        if (reportErrors)
        {
            var errors = request.Validate();
            if (errors.Count > 0)
            {
                MessageBox.Show(string.Join(Environment.NewLine, errors), "Auftrag unvollständig",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }
        }

        return request;
    }

    private async Task AnalyzeAsync()
    {
        var request = BuildRequest(reportErrors: true);
        if (request is null)
        {
            return;
        }

        IsBusy = true;
        Steps.Clear();
        StatusText = "Analyse läuft ...";
        AppendLog(new LogEntry(DateTime.Now, LogLevel.Info, "===== Analyse gestartet ====="));

        try
        {
            var preflight = await _engine.RunPreflightAsync(request);
            ApplyPreflight(preflight);
            RefreshSid();

            var results = await _engine.AnalyzeAsync(request);
            Steps.Clear();
            foreach (var result in results)
            {
                Steps.Add(new StepItem(result.Title, result.Status, result.Message, result.Changes));
            }

            var errors = results.Count(r => r.Status == StepStatus.Error);
            StatusText = errors == 0
                ? "Analyse abgeschlossen. Es wurde nichts verändert."
                : $"Analyse mit {errors} Fehler(n) abgeschlossen.";
        }
        catch (Exception ex)
        {
            StatusText = "Analyse fehlgeschlagen.";
            AppendLog(new LogEntry(DateTime.Now, LogLevel.Error, ex.Message));
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ApplyAsync()
    {
        var request = BuildRequest(reportErrors: true);
        if (request is null)
        {
            return;
        }

        if (!Confirm(request))
        {
            return;
        }

        IsBusy = true;
        Steps.Clear();
        StatusText = "SID-Änderung läuft – bitte nicht unterbrechen ...";

        try
        {
            var result = await _engine.ApplyAsync(request);
            ApplyPreflight(new PreflightReport(_engine.Preflight, false, string.Empty));
            RefreshSid();

            Steps.Clear();
            foreach (var step in result.Steps)
            {
                Steps.Add(new StepItem(step.Title, step.Status, step.Message, step.Changes));
            }

            StatusText = result.Blocked
                ? "Durch die Vorabprüfung blockiert – es wurde nichts geändert."
                : result.Success
                    ? "Änderung abgeschlossen. Bitte neu starten."
                    : "Änderung mit Fehlern beendet – bitte Protokoll und Sicherung prüfen.";

            ShowResult(result);
        }
        catch (Exception ex)
        {
            StatusText = "Änderung abgebrochen.";
            AppendLog(new LogEntry(DateTime.Now, LogLevel.Error, "Abbruch: " + ex));
            MessageBox.Show("Die Änderung wurde abgebrochen:\n\n" + ex.Message, "SID-Wechsler – Fehler",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
            RaiseCommandStates();
        }
    }

    private async Task RevertAsync()
    {
        var state = RecoveryStore.Load();
        if (state is null)
        {
            MessageBox.Show("Es ist kein letzter Lauf gespeichert.", "SID-Wechsler",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var answer = MessageBox.Show(
            $"Die letzte Änderung wird zurückgenommen:\n\n" +
            $"  aktuelle SID:  {state.NewSid}\n" +
            $"  alte SID:      {state.OldSid}\n" +
            $"  Sicherung:     {state.BackupDirectory}\n\n" +
            "Dabei werden SID, Profilzuordnungen und Profilrechte zurückgesetzt und die gesicherten " +
            "Registrierungswerte zurückgeschrieben. Anschließend ist ein Neustart erforderlich.\n\nFortfahren?",
            "Letzte Änderung zurücknehmen",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        IsBusy = true;
        Steps.Clear();
        StatusText = "Änderung wird zurückgenommen ...";

        try
        {
            var result = await _engine.RevertAsync(message => AppendLog(new LogEntry(DateTime.Now, LogLevel.Info, message)));
            RefreshSid();
            Steps.Clear();
            foreach (var step in result.Steps)
            {
                Steps.Add(new StepItem(step.Title, step.Status, step.Message, step.Changes));
            }

            StatusText = result.Success ? "Änderung zurückgenommen. Bitte neu starten." : "Rücknahme mit Fehlern beendet.";
            MessageBox.Show(result.Summary, "SID-Wechsler", MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            StatusText = "Rücknahme fehlgeschlagen.";
            MessageBox.Show(ex.Message, "SID-Wechsler – Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
            RaiseCommandStates();
        }
    }

    private bool Confirm(ChangeRequest request)
    {
        var selected = Features.Where(f => f.IsSelected).Select(f => "  • " + f.Title);
        var rebootText = request.PostAction switch
        {
            PostChangeAction.Reboot => "Der Computer wird nach Abschluss automatisch neu gestartet.",
            PostChangeAction.Shutdown => "Der Computer wird nach Abschluss automatisch heruntergefahren.",
            _ => "Der Computer muss anschließend manuell neu gestartet werden.",
        };

        var text =
            "Folgende Aktionen werden jetzt ausgeführt:\n\n" +
            string.Join(Environment.NewLine, selected) + "\n\n" +
            (request.ChangesMachineSid ? $"Neue Computer-SID: {request.ResolveNewSid().Value}\n\n" : string.Empty) +
            "Vorher wird eine Sicherung unter C:\\ProgramData\\SidChanger\\Backups angelegt.\n" +
            rebootText + "\n\n" +
            "Wichtig: Nicht unterbrechen, nicht abmelden und während der Änderung nichts am Computer tun.\n\n" +
            "Wirklich fortfahren?";

        return MessageBox.Show(text, "SID-Änderung bestätigen", MessageBoxButton.YesNo,
                   MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    private void ShowResult(ChangeResult result)
    {
        if (result.Blocked)
        {
            MessageBox.Show(result.Summary + "\n\nBitte die Vorabprüfungen rechts beachten.",
                "Durch Vorabprüfung blockiert", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var failed = result.Steps.Where(s => s.Status == StepStatus.Error).ToList();
        var text = result.Summary;

        if (failed.Count > 0)
        {
            text += "\n\nFehlgeschlagene Schritte:\n" + string.Join(Environment.NewLine, failed.Select(f => "  • " + f.Title + ": " + f.Message));
            text += "\n\nEine Rücknahme ist über „Letzte Änderung zurücknehmen“ möglich.";
        }
        else if (result.Success && result.Steps.Any(s => s.Status == StepStatus.Warning))
        {
            text += "\n\nHinweise:\n" + string.Join(Environment.NewLine, result.Steps
                .Where(s => s.Status == StepStatus.Warning)
                .Select(s => "  • " + s.Title + ": " + s.Message));
        }

        text += "\n\nSicherung: " + result.BackupDirectory;

        MessageBox.Show(text, result.Success ? "SID-Änderung abgeschlossen" : "SID-Änderung mit Fehlern",
            MessageBoxButton.OK, result.Success ? MessageBoxImage.Information : MessageBoxImage.Error);
    }

    private void ApplyPreflight(PreflightReport report)
    {
        Preflight.Clear();
        foreach (var check in report.Checks)
        {
            Preflight.Add(new PreflightItem(check.Name, check.Passed, check.Blocking, check.Message, check.Action));
        }
    }

    private void RefreshSid()
    {
        var sid = _engine.RefreshCurrentSid();
        OldSid = sid?.Value ?? "nicht ermittelbar";
        SidSource = _engine.SidSource;
        ComputerName = Environment.MachineName;

        if (string.IsNullOrWhiteSpace(NewComputerName) ||
            NewComputerName.Equals(_computerName, StringComparison.OrdinalIgnoreCase))
        {
            NewComputerName = Environment.MachineName;
        }
    }

    /// <summary>Öffnet das zu einer Vorabprüfung gehörende Fenster in Windows.</summary>
    private void OpenPreflightLink(object? parameter)
    {
        if (parameter is not PreflightItem { Action: { } action })
        {
            return;
        }

        try
        {
            if (action.Kind == PreflightActionKind.StopUcpd)
            {
                StopUcpd();
                return;
            }

            if (action.Kind == PreflightActionKind.RestartElevated)
            {
                var executable = Environment.ProcessPath;
                if (string.IsNullOrEmpty(executable))
                {
                    MessageBox.Show(
                        "Der Programmpfad ist unbekannt. Bitte das Programm über das Startmenü als Administrator öffnen.",
                        "SID-Wechsler", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                Process.Start(new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" });
                Application.Current?.Shutdown();
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = action.FileName,
                Arguments = action.Arguments,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"„{action.Label}“ konnte nicht geöffnet werden:\n\n{ex.Message}",
                "SID-Wechsler", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Hält den UCPD-Treiber direkt aus der Vorabprüfung heraus an und deaktiviert ihn.</summary>
    private async void StopUcpd()
    {
        IsBusy = true;
        StatusText = "UCPD-Treiber wird angehalten ...";

        try
        {
            var outcome = await Task.Run(() => UcpdController.StopAndDisable(
                    message => AppendLog(new LogEntry(DateTime.Now, LogLevel.Info, message)),
                    message => AppendLog(new LogEntry(DateTime.Now, LogLevel.Warning, message))))
                .ConfigureAwait(true);

            var report = await _engine
                .RunPreflightAsync(new ChangeRequest { IgnorePreflightWarnings = IgnoreWarnings })
                .ConfigureAwait(true);

            ApplyPreflight(report);

            StatusText = outcome.Stopped
                ? "UCPD-Treiber angehalten."
                : "UCPD-Treiber ist als deaktiviert eingetragen – nach dem Neustart bleibt er aus.";

            MessageBox.Show(outcome.Message, "UCPD-Treiber", MessageBoxButton.OK,
                outcome.Stopped || outcome.Disabled ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            StatusText = "UCPD-Treiber konnte nicht angehalten werden.";
            AppendLog(new LogEntry(DateTime.Now, LogLevel.Error, "UCPD: " + ex.Message));
            MessageBox.Show("Der UCPD-Treiber konnte nicht angehalten werden:\n\n" + ex.Message,
                "SID-Wechsler", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void OpenBackupFolder()
    {
        try
        {
            Directory.CreateDirectory(AppPaths.BackupRoot);
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "\"" + AppPaths.BackupRoot + "\"",
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show("Sicherungsordner konnte nicht geöffnet werden: " + ex.Message,
                "SID-Wechsler", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void SaveLog()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Protokoll speichern",
            Filter = "Textdatei (*.txt)|*.txt|Alle Dateien (*.*)|*.*",
            FileName = $"sid-wechsler-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            File.WriteAllText(dialog.FileName, _logBuilder.ToString());
        }
        catch (Exception ex)
        {
            MessageBox.Show("Protokoll konnte nicht gespeichert werden: " + ex.Message,
                "SID-Wechsler", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // --- Protokoll -----------------------------------------------------------

    private void AppendLog(LogEntry entry)
    {
        if (_dispatcher is not null && !_dispatcher.CheckAccess())
        {
            _dispatcher.BeginInvoke(new Action(() => AppendLog(entry)));
            return;
        }

        _logBuilder.AppendLine(entry.ToString());
        Log = _logBuilder.ToString();
    }

    private void AppendStep(StepResult result)
    {
        if (_dispatcher is not null && !_dispatcher.CheckAccess())
        {
            _dispatcher.BeginInvoke(new Action(() => AppendStep(result)));
            return;
        }

        Steps.Add(new StepItem(result.Title, result.Status, result.Message, result.Changes));
    }

    private void RaiseCommandStates()
    {
        AnalyzeCommand.RaiseCanExecuteChanged();
        ApplyCommand.RaiseCanExecuteChanged();
        RevertCommand.RaiseCanExecuteChanged();
        SaveLogCommand.RaiseCanExecuteChanged();
    }
}

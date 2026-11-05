using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Media;
using SidChanger.Core.Operations;
using SidChanger.Sid;

namespace SidChanger.App.ViewModels;

/// <summary>Zustand eines Punkts im Fortschrittsfenster.</summary>
public enum ProgressState
{
    Waiting,
    Running,
    Done,
    Warning,
    Failed,
    Skipped,
}

/// <summary>Ein Punkt im Fortschrittsfenster mit eigenem Balken und Status.</summary>
public sealed class ProgressStepItem : ObservableObject
{
    private ProgressState _state = ProgressState.Waiting;
    private string _message = string.Empty;

    public ProgressStepItem(string title, string? hint)
    {
        Title = title;
        Hint = string.IsNullOrWhiteSpace(hint) ? string.Empty : hint!;
    }

    public string Title { get; }

    /// <summary>Hinweis für Punkte, die länger dauern können.</summary>
    public string Hint { get; }

    public bool HasHint => Hint.Length > 0;

    public ProgressState State
    {
        get => _state;
        set
        {
            if (!SetProperty(ref _state, value))
            {
                return;
            }

            OnPropertyChanged(nameof(Icon));
            OnPropertyChanged(nameof(Brush));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(BarValue));
            OnPropertyChanged(nameof(IsRunning));
            OnPropertyChanged(nameof(IsWaiting));
        }
    }

    /// <summary>Ergebnis des Punkts, sobald er gelaufen ist.</summary>
    public string Message
    {
        get => _message;
        set
        {
            if (SetProperty(ref _message, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(HasMessage));
            }
        }
    }

    public bool HasMessage => Message.Length > 0;

    public string Icon => State switch
    {
        ProgressState.Running => "▶",
        ProgressState.Done => "✓",
        ProgressState.Warning => "!",
        ProgressState.Failed => "✕",
        ProgressState.Skipped => "–",
        _ => "·",
    };

    public string StatusText => State switch
    {
        ProgressState.Running => "läuft ...",
        ProgressState.Done => "erledigt",
        ProgressState.Warning => "mit Hinweis",
        ProgressState.Failed => "Fehler",
        ProgressState.Skipped => "nicht vorhanden",
        _ => "wartet",
    };

    public bool IsRunning => State == ProgressState.Running;

    public bool IsWaiting => State == ProgressState.Waiting;

    /// <summary>Balkenwert: 0 solange der Punkt wartet, 100 sobald er gelaufen ist.</summary>
    public double BarValue => State == ProgressState.Waiting ? 0 : 100;

    public Brush Brush => State switch
    {
        ProgressState.Done => new SolidColorBrush(Color.FromRgb(0x6F, 0xC2, 0x7A)),
        ProgressState.Running => new SolidColorBrush(Color.FromRgb(0x3F, 0xA3, 0x4D)),
        ProgressState.Warning => new SolidColorBrush(Color.FromRgb(0xE0, 0xA0, 0x30)),
        ProgressState.Failed => new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x60)),
        _ => new SolidColorBrush(Color.FromRgb(0x8B, 0x97, 0xA3)),
    };
}

/// <summary>
/// Fortschritt eines laufenden Vorgangs (Vorbereiten, Analyse, Ändern): Gesamtbalken,
/// je Punkt ein eigener Balken und am Ende eine Abschlussmeldung, die mit „OK“ bestätigt wird.
/// </summary>
public sealed class OperationProgress : ObservableObject
{
    private string _footer;
    private string _overallText = string.Empty;
    private double _overallPercent;
    private string? _error;
    private bool _isFinished;
    private string _resultText = string.Empty;

    public OperationProgress(
        string headline,
        string intro,
        string footer,
        IEnumerable<(string Title, string? Hint)> steps)
    {
        Headline = headline;
        Intro = intro;
        _footer = footer;
        Steps = new ObservableCollection<ProgressStepItem>(
            steps.Select(step => new ProgressStepItem(step.Title, step.Hint)));

        UpdateOverall();
    }

    public string Headline { get; }

    public string Intro { get; }

    public ObservableCollection<ProgressStepItem> Steps { get; }

    public string Footer
    {
        get => _footer;
        set => SetProperty(ref _footer, value);
    }

    public string OverallText
    {
        get => _overallText;
        private set => SetProperty(ref _overallText, value);
    }

    public double OverallPercent
    {
        get => _overallPercent;
        private set => SetProperty(ref _overallPercent, value);
    }

    /// <summary>Wahr, sobald der Vorgang durch ist – dann lässt sich das Fenster mit „OK“ schließen.</summary>
    public bool IsFinished
    {
        get => _isFinished;
        private set
        {
            if (SetProperty(ref _isFinished, value))
            {
                OnPropertyChanged(nameof(IsRunning));
            }
        }
    }

    public bool IsRunning => !IsFinished;

    /// <summary>Abschlussmeldung: was geklappt hat und was nicht.</summary>
    public string ResultText
    {
        get => _resultText;
        private set => SetProperty(ref _resultText, value);
    }

    public string ResultIcon => Steps.Any(s => s.State == ProgressState.Failed) || _error is not null
        ? "✕"
        : Steps.Any(s => s.State == ProgressState.Warning)
            ? "!"
            : "✓";

    public Brush ResultBrush => ResultIcon switch
    {
        "✕" => new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x60)),
        "!" => new SolidColorBrush(Color.FromRgb(0xE0, 0xA0, 0x30)),
        _ => new SolidColorBrush(Color.FromRgb(0x6F, 0xC2, 0x7A)),
    };

    /// <summary>Markiert einen Punkt als laufend; vorher laufende Punkte gelten als erledigt.</summary>
    public void Start(string title)
    {
        // Ein verspätet zugestellter Start darf einen abgeschlossenen Vorgang nicht mehr verändern.
        if (IsFinished)
        {
            return;
        }

        foreach (var running in Steps.Where(s => s.State == ProgressState.Running))
        {
            running.State = ProgressState.Done;
        }

        // Nur wartende Punkte werden gestartet – ein bereits erledigter oder fehlgeschlagener
        // Punkt springt dadurch nicht wieder auf „läuft“ zurück.
        if (Find(title) is { State: ProgressState.Waiting } item)
        {
            item.State = ProgressState.Running;
            item.Message = string.Empty;
        }

        UpdateOverall();
    }

    /// <summary>Übernimmt das Ergebnis eines Punkts samt Meldung.</summary>
    public void Complete(StepResult result)
    {
        if (IsFinished || Find(result.Title) is not { } item)
        {
            return;
        }

        item.State = result.Status switch
        {
            StepStatus.Ok => ProgressState.Done,
            StepStatus.Warning => ProgressState.Warning,
            StepStatus.Error => ProgressState.Failed,
            StepStatus.NotAvailable => ProgressState.Skipped,
            _ => ProgressState.Done,
        };

        item.Message = result.Message;
        UpdateOverall();
    }

    /// <summary>Schließt alle noch offenen Punkte ab (für Abläufe ohne Einzelergebnis).</summary>
    public void CompleteAll()
    {
        foreach (var step in Steps.Where(s => s.State is ProgressState.Waiting or ProgressState.Running))
        {
            step.State = ProgressState.Done;
        }

        UpdateOverall();
    }

    /// <summary>Markiert den laufenden Punkt als fehlgeschlagen und die übrigen als nicht gelaufen.</summary>
    public void Fail(string message)
    {
        _error = message;

        if (Steps.FirstOrDefault(s => s.State == ProgressState.Running) is { } running)
        {
            running.State = ProgressState.Failed;
            running.Message = message;
        }

        foreach (var waiting in Steps.Where(s => s.State == ProgressState.Waiting))
        {
            waiting.State = ProgressState.Skipped;
        }

        UpdateOverall();
    }

    /// <summary>
    /// Erzeugt die Abschlussmeldung (was funktioniert hat und was nicht) und gibt „OK“ frei.
    /// </summary>
    public void Finish()
    {
        foreach (var running in Steps.Where(s => s.State == ProgressState.Running))
        {
            running.State = ProgressState.Done;
        }

        var total = Steps.Count;
        var done = Steps.Count(s => s.State == ProgressState.Done);
        var warnings = Steps.Count(s => s.State == ProgressState.Warning);
        var failed = Steps.Count(s => s.State == ProgressState.Failed);
        var skipped = Steps.Count(s => s.State == ProgressState.Skipped);

        var text = new StringBuilder();
        text.Append($"{done} von {total} Punkt(en) erledigt");

        if (warnings > 0)
        {
            text.Append($", {warnings} mit Hinweis");
        }

        if (failed > 0)
        {
            text.Append($", {failed} fehlgeschlagen");
        }

        if (skipped > 0)
        {
            text.Append($", {skipped} nicht vorhanden oder nicht gelaufen");
        }

        text.Append('.');

        if (_error is not null)
        {
            text.AppendLine();
            text.AppendLine();
            text.Append("Abgebrochen: " + _error);
        }

        var problems = Steps.Where(s => s.State is ProgressState.Failed or ProgressState.Warning).ToList();

        if (problems.Count > 0)
        {
            text.AppendLine();
            text.AppendLine();
            text.AppendLine(failed > 0 ? "Das hat nicht geklappt:" : "Darauf bitte achten:");

            foreach (var problem in problems)
            {
                text.AppendLine();
                text.Append("• " + problem.Title + (problem.HasMessage ? ": " + problem.Message : string.Empty));
            }
        }
        else if (failed == 0)
        {
            text.AppendLine();
            text.AppendLine();
            text.Append("Alles, was geplant war, hat geklappt.");
        }

        ResultText = text.ToString().TrimEnd();
        OnPropertyChanged(nameof(ResultIcon));
        OnPropertyChanged(nameof(ResultBrush));

        UpdateOverall();
        IsFinished = true;
    }

    private ProgressStepItem? Find(string title) => Steps.FirstOrDefault(s => s.Title == title);

    private void UpdateOverall()
    {
        if (Steps.Count == 0)
        {
            OverallText = string.Empty;
            OverallPercent = 0;
            return;
        }

        var finished = Steps.Count(s => s.State is ProgressState.Done or ProgressState.Warning
            or ProgressState.Failed or ProgressState.Skipped);
        var running = Steps.Count(s => s.State == ProgressState.Running);

        OverallPercent = Math.Min(100, (finished + (running * 0.5)) / Steps.Count * 100);
        OverallText = $"{finished} von {Steps.Count} Schritten";
    }
}

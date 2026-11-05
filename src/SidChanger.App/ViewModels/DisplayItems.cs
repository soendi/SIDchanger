using System.Windows.Media;
using SidChanger.Core.Operations;
using SidChanger.Sid;

namespace SidChanger.App.ViewModels;

/// <summary>Ein Vorabprüfungs-Ergebnis für die Anzeige.</summary>
public sealed class PreflightItem
{
    public PreflightItem(
        string name,
        bool passed,
        bool blocking,
        string message,
        PreflightAction? action = null,
        PreflightAction? manualAction = null)
    {
        Name = name;
        Passed = passed;
        Blocking = blocking;
        Message = message;
        Action = action;
        ManualAction = manualAction;
    }

    public string Name { get; }

    public bool Passed { get; }

    public bool Blocking { get; }

    public string Message { get; }

    /// <summary>Direkter Sprung in die betroffene Windows-Einstellung, falls vorhanden.</summary>
    public PreflightAction? Action { get; }

    public bool HasAction => Action is not null;

    public string ActionLabel => Action?.Label ?? string.Empty;

    /// <summary>Manueller Weg über die Windows-Einstellungen, wenn der direkte Eingriff nicht klappt.</summary>
    public PreflightAction? ManualAction { get; }

    public bool HasManualAction => ManualAction is not null;

    public string ManualLabel => ManualAction?.Label ?? string.Empty;

    public string Icon => Passed ? "✓" : Blocking ? "✕" : "!";

    public Brush Brush => Passed
        ? new SolidColorBrush(Color.FromRgb(0x6F, 0xC2, 0x7A))
        : Blocking
            ? new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x60))
            : new SolidColorBrush(Color.FromRgb(0xE0, 0xA0, 0x30));
}

/// <summary>Ein Schritt-Ergebnis für die Anzeige.</summary>
public sealed class StepItem
{
    public StepItem(string title, StepStatus status, string message, int changes)
    {
        Title = title;
        Status = status;
        Message = message;
        Changes = changes;
    }

    public string Title { get; }

    public StepStatus Status { get; }

    public string Message { get; }

    public int Changes { get; }

    public string Icon => Status switch
    {
        StepStatus.Ok => "✓",
        StepStatus.Warning => "!",
        StepStatus.Error => "✕",
        StepStatus.NotAvailable => "–",
        _ => "·",
    };

    public string StatusText => Status switch
    {
        StepStatus.Ok => "erledigt",
        StepStatus.Warning => "Hinweis",
        StepStatus.Error => "Fehler",
        StepStatus.NotAvailable => "nicht vorhanden",
        _ => "übersprungen",
    };

    public Brush Brush => Status switch
    {
        StepStatus.Ok => new SolidColorBrush(Color.FromRgb(0x6F, 0xC2, 0x7A)),
        StepStatus.Warning => new SolidColorBrush(Color.FromRgb(0xE0, 0xA0, 0x30)),
        StepStatus.Error => new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x60)),
        _ => new SolidColorBrush(Color.FromRgb(0x8B, 0x97, 0xA3)),
    };
}

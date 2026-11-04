using System.Windows.Media;
using SidChanger.Sid;

namespace SidChanger.App.ViewModels;

/// <summary>Eine auswählbare Aktion in der Oberfläche.</summary>
public sealed class FeatureOption : ObservableObject
{
    private bool _isSelected;

    public FeatureOption(FeatureInfo info, bool isSelected)
    {
        Info = info;
        _isSelected = isSelected;
    }

    public FeatureInfo Info { get; }

    public ChangeFeature Feature => Info.Feature;

    public string Title => Info.Title;

    public string Description => Info.Description;

    /// <summary>Zusätzliche Hinweise (Risiko, Neustart, Registry-Pfad).</summary>
    public string Details =>
        $"{Info.RegistrySummary}" +
        (Info.RequiresReboot ? " · Neustart erforderlich" : string.Empty);

    public string RiskText => Info.Risk switch
    {
        RiskLevel.Niedrig => "geringes Risiko",
        RiskLevel.Mittel => "mittleres Risiko",
        _ => "hohes Risiko",
    };

    public Brush RiskBrush => Info.Risk switch
    {
        RiskLevel.Niedrig => new SolidColorBrush(Color.FromRgb(0x6F, 0xC2, 0x7A)),
        RiskLevel.Mittel => new SolidColorBrush(Color.FromRgb(0xE0, 0xA0, 0x30)),
        _ => new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x60)),
    };

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}

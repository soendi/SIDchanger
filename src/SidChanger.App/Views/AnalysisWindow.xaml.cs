using System.Collections.Generic;
using System.Windows;
using SidChanger.App.ViewModels;

namespace SidChanger.App.Views;

/// <summary>
/// Zeigt vor der Analyse alle geplanten Schritte und lässt sie bestätigen oder abbrechen.
/// </summary>
public partial class AnalysisWindow : Window
{
    public AnalysisWindow(string summary, IReadOnlyList<AnalysisStepItem> steps)
    {
        InitializeComponent();
        SummaryText.Text = summary;
        StepList.ItemsSource = steps;
    }

    private void Ok_OnClick(object sender, RoutedEventArgs e) => DialogResult = true;

    private void Cancel_OnClick(object sender, RoutedEventArgs e) => DialogResult = false;
}

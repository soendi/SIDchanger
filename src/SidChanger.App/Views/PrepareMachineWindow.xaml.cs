using System.Collections.Generic;
using System.Windows;
using SidChanger.Core.Operations;

namespace SidChanger.App.Views;

/// <summary>
/// Zeigt vor dem Vorbereiten alle geplanten Eingriffe und lässt sie bestätigen oder abbrechen.
/// </summary>
public partial class PrepareMachineWindow : Window
{
    public PrepareMachineWindow(IReadOnlyList<PrepareStepInfo> steps)
    {
        InitializeComponent();
        StepList.ItemsSource = steps;
    }

    private void Ok_OnClick(object sender, RoutedEventArgs e) => DialogResult = true;

    private void Cancel_OnClick(object sender, RoutedEventArgs e) => DialogResult = false;
}

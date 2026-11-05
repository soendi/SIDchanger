using System;
using System.Threading.Tasks;
using System.Windows;

namespace SidChanger.App.Views;

/// <summary>
/// Zeigt während eines Laufs jeden Punkt mit eigenem Fortschrittsbalken an. Am Ende bleibt
/// das Fenster offen, zeigt die Abschlussmeldung und wird erst mit „OK“ geschlossen.
/// </summary>
public partial class ProgressWindow : Window
{
    private readonly TaskCompletionSource<bool> _closed =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ProgressWindow()
    {
        InitializeComponent();
    }

    /// <summary>Wird fertig, sobald der Benutzer das Fenster bestätigt oder schließt.</summary>
    public Task WaitForCloseAsync() => _closed.Task;

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        _closed.TrySetResult(true);
    }

    private void Ok_OnClick(object sender, RoutedEventArgs e) => Close();
}

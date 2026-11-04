using System.Windows;
using System.Windows.Threading;

namespace SidChanger.App;

/// <summary>Anwendungseinstieg; fängt unbehandelte Fehler ab und zeigt sie auf Deutsch.</summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
            {
                ShowError(exception);
            }
        };
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ShowError(e.Exception);
        e.Handled = true;
    }

    private static void ShowError(Exception exception)
    {
        MessageBox.Show(
            "Es ist ein unerwarteter Fehler aufgetreten:\n\n" + exception.Message +
            "\n\nBitte das Programm beenden und das Protokoll unter\n" +
            @"C:\ProgramData\SidChanger\Logs prüfen.",
            "SID-Wechsler – Fehler",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }
}

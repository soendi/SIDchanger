using System.Windows;
using System.Windows.Threading;
using SidChanger.Core.Infrastructure;

namespace SidChanger.App;

/// <summary>Anwendungseinstieg; protokolliert unbehandelte Fehler und zeigt sie auf Deutsch.</summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AppLog.Info($"===== Start {AppPaths.ProductName} {typeof(App).Assembly.GetName().Version} =====");
        AppLog.Info($"System: {Environment.OSVersion} · .NET {Environment.Version} · " +
                    $"{(Environment.Is64BitProcess ? "64-bit" : "32-bit")}");

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ShowError(e.Exception, "Unbehandelter Fehler in der Oberfläche");
        e.Handled = true;
    }

    private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            ShowError(exception, "Unbehandelter Fehler (Hintergrund)");
        }
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        AppLog.WriteException("Unbeobachteter Task-Fehler", e.Exception);
        e.SetObserved();
    }

    private static void ShowError(Exception exception, string context)
    {
        var root = Unwrap(exception);
        AppLog.WriteException(context, exception);

        var message =
            "Es ist ein unerwarteter Fehler aufgetreten:\n\n" + root.Message +
            "\n\nFehlerart: " + root.GetType().Name +
            "\n\nProtokoll:\n" + AppLog.FilePath;

        if (AppLog.LastError is { } problem)
        {
            message += "\n\nHinweis: Das Protokoll konnte nicht geschrieben werden (" + problem + ").";
        }

        MessageBox.Show(message, "SID-Wechsler – Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    /// <summary>
    /// Liefert die eigentliche Ursache: WPF verpackt Ausnahmen beim Erzeugen von Fenstern
    /// in eine <see cref="System.Reflection.TargetInvocationException"/>.
    /// </summary>
    private static Exception Unwrap(Exception exception)
    {
        while (true)
        {
            if (exception is AggregateException { InnerExceptions.Count: 1 } aggregate)
            {
                exception = aggregate.InnerExceptions[0];
                continue;
            }

            if (exception is System.Reflection.TargetInvocationException { InnerException: { } inner })
            {
                exception = inner;
                continue;
            }

            return exception;
        }
    }
}

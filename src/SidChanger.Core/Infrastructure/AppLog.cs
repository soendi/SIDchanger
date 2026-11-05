using System.Text;

namespace SidChanger.Core.Infrastructure;

/// <summary>
/// Schreibt Protokoll und Absturzberichte dauerhaft in den Ordner
/// <c>C:\ProgramData\SidChanger\Logs</c>. Ist dieser Ordner nicht beschreibbar, wird
/// ersatzweise <c>%TEMP%\SidChanger\Logs</c> verwendet. Schreibfehler werden nie
/// weitergereicht – die Protokollierung darf das Programm nicht stören.
/// </summary>
public static class AppLog
{
    private static readonly object Gate = new();
    private static string? _logDirectory;

    /// <summary>Ordner der Protokolldateien (ProgramData, sonst %TEMP%).</summary>
    public static string LogDirectory => _logDirectory ?? AppPaths.LogDirectory;

    /// <summary>Pfad der heutigen Protokolldatei.</summary>
    public static string FilePath => Path.Combine(LogDirectory, $"sid-wechsler-{DateTime.Now:yyyyMMdd}.log");

    /// <summary>Letzter Schreibfehler; null, solange das Schreiben funktioniert.</summary>
    public static string? LastError { get; private set; }

    public static void Info(string message) => Write("INFO", message);

    public static void Warn(string message) => Write("WARN", message);

    public static void Error(string message) => Write("ERROR", message);

    /// <summary>Schreibt eine einzelne Zeile in die Tagesdatei.</summary>
    public static void Write(string category, string message) =>
        Append($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{category}] {message}");

    /// <summary>Schreibt eine Ausnahme samt innerer Ausnahmen und Aufrufliste.</summary>
    public static void WriteException(string context, Exception exception)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [ABSTURZ] {context}");
        Describe(builder, exception, 0);
        Append(builder.ToString().TrimEnd());
    }

    private static void Describe(StringBuilder builder, Exception exception, int depth)
    {
        var indent = new string(' ', depth * 2);
        builder.AppendLine($"{indent}{exception.GetType().FullName}: {exception.Message}");

        if (exception is AggregateException aggregate)
        {
            foreach (var inner in aggregate.InnerExceptions)
            {
                Describe(builder, inner, depth + 1);
            }
        }
        else if (exception.InnerException is { } inner)
        {
            Describe(builder, inner, depth + 1);
        }

        if (!string.IsNullOrWhiteSpace(exception.StackTrace))
        {
            foreach (var line in exception.StackTrace.Split('\n'))
            {
                builder.AppendLine($"{indent}  {line.TrimEnd()}");
            }
        }
    }

    private static void Append(string text)
    {
        var path = Path.Combine(EnsureDirectory(), $"sid-wechsler-{DateTime.Now:yyyyMMdd}.log");

        try
        {
            lock (Gate)
            {
                File.AppendAllText(path, text + Environment.NewLine, Encoding.UTF8);
            }

            LastError = null;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
    }

    private static string EnsureDirectory()
    {
        if (_logDirectory is not null)
        {
            return _logDirectory;
        }

        lock (Gate)
        {
            if (_logDirectory is not null)
            {
                return _logDirectory;
            }

            foreach (var candidate in Candidates())
            {
                try
                {
                    System.IO.Directory.CreateDirectory(candidate);
                    _logDirectory = candidate;
                    return candidate;
                }
                catch
                {
                    // Nächster Kandidat.
                }
            }

            _logDirectory = AppPaths.LogDirectory;
            return _logDirectory;
        }
    }

    private static IEnumerable<string> Candidates()
    {
        yield return AppPaths.LogDirectory;
        yield return Path.Combine(Path.GetTempPath(), "SidChanger", "Logs");
    }
}

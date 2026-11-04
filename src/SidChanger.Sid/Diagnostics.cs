namespace SidChanger.Sid;

/// <summary>Ergebniszustand eines Einzelschritts.</summary>
public enum StepStatus
{
    /// <summary>Schritt war erfolgreich bzw. würde erfolgreich ausgeführt.</summary>
    Ok = 0,

    /// <summary>Ausgeführt, aber mit Hinweisen.</summary>
    Warning = 1,

    /// <summary>Fehlgeschlagen.</summary>
    Error = 2,

    /// <summary>Nicht ausgewählt oder nicht anwendbar.</summary>
    Skipped = 3,

    /// <summary>Voraussetzung fehlt (z. B. SQL Server nicht installiert).</summary>
    NotAvailable = 4,
}

/// <summary>Ergebnis eines Einzelschritts.</summary>
public sealed record StepResult(
    ChangeFeature Feature,
    string Title,
    StepStatus Status,
    string Message,
    int Changes = 0)
{
    public static StepResult Skip(ChangeFeature feature, string title) =>
        new(feature, title, StepStatus.Skipped, "Nicht ausgewählt.");

    public static StepResult Ok(ChangeFeature feature, string title, string message, int changes = 0) =>
        new(feature, title, StepStatus.Ok, message, changes);

    public static StepResult Warn(ChangeFeature feature, string title, string message, int changes = 0) =>
        new(feature, title, StepStatus.Warning, message, changes);

    public static StepResult Error(ChangeFeature feature, string title, string message) =>
        new(feature, title, StepStatus.Error, message);

    public static StepResult NotAvailable(ChangeFeature feature, string title, string message) =>
        new(feature, title, StepStatus.NotAvailable, message);
}

/// <summary>Schweregrad einer Protokollzeile.</summary>
public enum LogLevel
{
    Info,
    Detail,
    Success,
    Warning,
    Error,
}

/// <summary>Eine Protokollzeile für die Oberfläche und die Protokolldatei.</summary>
public sealed record LogEntry(DateTime Timestamp, LogLevel Level, string Message)
{
    public override string ToString() =>
        $"{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level}] {Message}";
}

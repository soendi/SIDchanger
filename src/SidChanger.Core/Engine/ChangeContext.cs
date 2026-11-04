using SidChanger.Core.Infrastructure;
using SidChanger.Core.Registry;
using SidChanger.Sid;

namespace SidChanger.Core.Engine;

/// <summary>
/// Gemeinsamer Zustand eines Änderungslaufs: Auftrag, alte/neue SID, Sicherung und Protokoll.
/// </summary>
public sealed class ChangeContext
{
    public ChangeContext(ChangeRequest request, MachineSid? oldSid, MachineSid newSid, string backupDirectory)
    {
        Request = request;
        OldSid = oldSid;
        NewSid = newSid;
        BackupDirectory = backupDirectory;
        Backup = new BackupStore(backupDirectory);
        ComputerName = Environment.MachineName;
        WindowsDirectory = AppPaths.WindowsDirectory;
    }

    public ChangeRequest Request { get; }

    public MachineSid? OldSid { get; }

    public MachineSid NewSid { get; }

    public string BackupDirectory { get; }

    public BackupStore Backup { get; }

    public string WindowsDirectory { get; }

    public string ComputerName { get; set; }

    /// <summary>Simulation: Schritte melden nur, was sie tun würden.</summary>
    public bool Simulation { get; init; }

    public Action<LogEntry>? LogSink { get; init; }

    public Action<StepResult>? StepSink { get; init; }

    /// <summary>Fehlermeldungen beim Aktivieren von Privilegien (leer = alles aktiv).</summary>
    public IReadOnlyList<string> PrivilegeErrors { get; set; } = Array.Empty<string>();

    /// <summary>Zwischenspeicher für Schritt-Daten (z. B. Liste der Sicherungen).</summary>
    public IDictionary<string, object?> Bag { get; } = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Die alte SID, ohne die keine SID-Ersetzung möglich ist.</summary>
    public MachineSid RequireOldSid()
    {
        return OldSid ?? throw new InvalidOperationException(
            "Die aktuelle Computer-SID konnte nicht gelesen werden. Ohne sie ist keine Änderung möglich.");
    }

    public void Log(LogLevel level, string message)
    {
        var entry = new LogEntry(DateTime.Now, level, message);
        LogSink?.Invoke(entry);
        AppPaths.AppendLog(BackupDirectory, entry.ToString());
    }

    public void Info(string message) => Log(LogLevel.Info, message);
    public void Detail(string message) => Log(LogLevel.Detail, message);
    public void Success(string message) => Log(LogLevel.Success, message);
    public void Warn(string message) => Log(LogLevel.Warning, message);
    public void Error(string message) => Log(LogLevel.Error, message);

    public void Report(StepResult result)
    {
        StepSink?.Invoke(result);
        Log(result.Status switch
        {
            StepStatus.Ok => LogLevel.Success,
            StepStatus.Warning => LogLevel.Warning,
            StepStatus.Error => LogLevel.Error,
            _ => LogLevel.Detail,
        }, $"{result.Title}: {result.Message}");
    }

    /// <summary>Alle Profile, die zur alten Maschinen-SID gehören.</summary>
    public IReadOnlyList<ProfileEntry> FindProfiles() =>
        OldSid is null ? Array.Empty<ProfileEntry>() : ProfileLocator.ReadForMachine(OldSid, Warn);
}

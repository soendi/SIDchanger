namespace SidChanger.Core.Infrastructure;

/// <summary>Zentrale Pfade für Sicherungen, Protokolle und Zustandsdateien.</summary>
public static class AppPaths
{
    public const string ProductName = "SID-Wechsler";

    public static string ProgramDataDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SidChanger");

    public static string BackupRoot { get; } = Path.Combine(ProgramDataDirectory, "Backups");

    public static string StateFile { get; } = Path.Combine(ProgramDataDirectory, "zustand.json");

    public static string LogDirectory { get; } = Path.Combine(ProgramDataDirectory, "Logs");

    public static string TempDirectory { get; } = Path.Combine(ProgramDataDirectory, "Temp");

    public static string WindowsDirectory { get; } = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public static string SystemDrive { get; } =
        Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\";

    /// <summary>Erzeugt einen neuen, eindeutigen Sicherungsordner.</summary>
    public static string CreateBackupDirectory(DateTime timestamp)
    {
        var name = timestamp.ToString("yyyyMMdd-HHmmss");
        var path = Path.Combine(BackupRoot, name);
        var counter = 1;

        while (Directory.Exists(path))
        {
            path = Path.Combine(BackupRoot, $"{name}-{counter++}");
        }

        Directory.CreateDirectory(path);
        Directory.CreateDirectory(LogDirectory);
        return path;
    }

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(ProgramDataDirectory);
        Directory.CreateDirectory(BackupRoot);
        Directory.CreateDirectory(LogDirectory);
        Directory.CreateDirectory(TempDirectory);
    }

    /// <summary>Schreibt eine Protokollzeile zusätzlich in eine Datei.</summary>
    public static void AppendLog(string backupDirectory, string line)
    {
        try
        {
            File.AppendAllText(Path.Combine(backupDirectory, "protokoll.txt"), line + Environment.NewLine);
        }
        catch
        {
            // Protokollierung darf den Ablauf nie stoppen.
        }
    }
}

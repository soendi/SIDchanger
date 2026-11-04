using System.Text.Json;
using SidChanger.Core.Infrastructure;

namespace SidChanger.Core.Engine;

/// <summary>Zustand eines Laufs, damit eine Änderung nachvollzogen oder zurückgenommen werden kann.</summary>
public sealed class RecoveryState
{
    public string CreatedUtc { get; set; } = DateTime.UtcNow.ToString("O");

    public string OldSid { get; set; } = string.Empty;

    public string NewSid { get; set; } = string.Empty;

    public string? OldComputerName { get; set; }

    public string BackupDirectory { get; set; } = string.Empty;

    public bool Completed { get; set; }

    public bool Reverted { get; set; }

    public List<string> Features { get; set; } = new();
}

/// <summary>Speichert und liest den Zustand des letzten Laufs.</summary>
public static class RecoveryStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string FilePath => Path.Combine(AppPaths.ProgramDataDirectory, "letzter-lauf.json");

    public static void Save(RecoveryState state)
    {
        AppPaths.EnsureDirectories();
        File.WriteAllText(FilePath, JsonSerializer.Serialize(state, Options));
    }

    public static RecoveryState? Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<RecoveryState>(File.ReadAllText(FilePath), Options)
                : null;
        }
        catch
        {
            return null;
        }
    }

    public static void Clear()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }
        catch
        {
            // ignorieren
        }
    }
}

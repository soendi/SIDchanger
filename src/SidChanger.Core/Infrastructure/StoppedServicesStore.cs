using System.Text.Json;
using SidChanger.Core.Infrastructure;

namespace SidChanger.Core.Infrastructure;

/// <summary>
/// Merkt sich die Dienste, die das Programm beendet hat, damit der Abschluss der
/// SID-Änderung sie wieder starten kann – auch über einen Neustart hinweg.
/// </summary>
public static class StoppedServicesStore
{
    public static string FilePath => Path.Combine(AppPaths.ProgramDataDirectory, "gestoppte-dienste.json");

    /// <summary>Ergänzt die Liste um beendete Dienste (doppelte Einträge werden zusammengefasst).</summary>
    public static void Add(IEnumerable<string> names)
    {
        var merged = Load().ToList();

        foreach (var name in names)
        {
            if (!string.IsNullOrWhiteSpace(name) &&
                !merged.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                merged.Add(name);
            }
        }

        Save(merged);
    }

    public static IReadOnlyList<string> Load()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return Array.Empty<string>();
            }

            return JsonSerializer.Deserialize<List<string>>(File.ReadAllText(FilePath)) ?? new List<string>();
        }
        catch
        {
            return Array.Empty<string>();
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
            // Aufräumen darf nie stören.
        }
    }

    private static void Save(IReadOnlyList<string> names)
    {
        try
        {
            if (names.Count == 0)
            {
                Clear();
                return;
            }

            Directory.CreateDirectory(AppPaths.ProgramDataDirectory);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(names, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // Ohne gespeicherte Liste startet der Abschluss nichts – kein Grund abzubrechen.
        }
    }
}

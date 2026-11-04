using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using SidChanger.Core.Native;
using SidChanger.Sid;

namespace SidChanger.Core.Infrastructure;

/// <summary>Gesicherter Registrierungswert.</summary>
public sealed record RegistryValueSnapshot(
    string Hive,
    string KeyPath,
    string? ValueName,
    string Kind,
    string Data,
    string Encoding);

/// <summary>Gesicherte Dateisystem-Berechtigung (SDDL).</summary>
public sealed record AclSnapshot(string Path, bool IsDirectory, string Sddl);

/// <summary>Sicherungsdatei mit allen vor der Änderung erfassten Werten.</summary>
public sealed class BackupDocument
{
    public string CreatedUtc { get; set; } = DateTime.UtcNow.ToString("O");
    public string? OldSid { get; set; }
    public string? NewSid { get; set; }
    public string? ComputerName { get; set; }
    public List<RegistryValueSnapshot> Registry { get; set; } = new();
    public List<AclSnapshot> Acls { get; set; } = new();
}

/// <summary>
/// Sichert Registrierungswerte und ACLs vor der Änderung und kann sie wiederherstellen.
/// Die Daten liegen als JSON im Sicherungsordner.
/// </summary>
public sealed class BackupStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly BackupDocument _document = new();
    private readonly HashSet<string> _registryKeys = new(StringComparer.OrdinalIgnoreCase);

    public BackupStore(string rootDirectory)
    {
        RootDirectory = rootDirectory;
        Directory.CreateDirectory(rootDirectory);
    }

    public string RootDirectory { get; }

    public string FilePath => Path.Combine(RootDirectory, "sicherung.json");

    public int RegistryCount => _document.Registry.Count;
    public int AclCount => _document.Acls.Count;

    public void SetSids(MachineSid? oldSid, MachineSid newSid, string? computerName)
    {
        _document.OldSid = oldSid?.Value;
        _document.NewSid = newSid.Value;
        _document.ComputerName = computerName;
    }

    /// <summary>Merkt sich den aktuellen Wert eines Registrierungswerts (nur beim ersten Mal).</summary>
    public void RecordRegistry(RegistryHive hive, string keyPath, string? valueName, object? value, RegistryValueKind kind)
    {
        var identity = $"{hive}|{keyPath}|{valueName}|{kind}";
        if (!_registryKeys.Add(identity))
        {
            return;
        }

        var (data, encoding) = SerializeValue(value, kind);
        _document.Registry.Add(new RegistryValueSnapshot(hive.ToString(), keyPath, valueName, kind.ToString(), data, encoding));
    }

    public void RecordAcl(string path, bool isDirectory, string sddl)
    {
        if (_document.Acls.Any(a => string.Equals(a.Path, path, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        _document.Acls.Add(new AclSnapshot(path, isDirectory, sddl));
    }

    private static (string Data, string Encoding) SerializeValue(object? value, RegistryValueKind kind)
    {
        switch (kind)
        {
            case RegistryValueKind.Binary:
                return (Convert.ToBase64String((byte[])(value ?? Array.Empty<byte>())), "base64");
            case RegistryValueKind.DWord:
            case RegistryValueKind.QWord:
                return (Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty, "numeric");
            case RegistryValueKind.MultiString:
                return (string.Join("\n", (string[])(value ?? Array.Empty<string>())), "multistring");
            default:
                return (Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty, "text");
        }
    }

    public void Save()
    {
        File.WriteAllText(FilePath, JsonSerializer.Serialize(_document, JsonOptions));
    }

    public static BackupDocument? Load(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return null;
        }

        return JsonSerializer.Deserialize<BackupDocument>(File.ReadAllText(filePath), JsonOptions);
    }

    /// <summary>
    /// Stellt alle gesicherten Registrierungswerte wieder her.
    /// Liefert (wiederhergestellt, Fehler).
    /// </summary>
    public static (int Restored, int Failed) RestoreRegistry(BackupDocument document, Action<string> log, Action<string>? warn)
    {
        var restored = 0;
        var failed = 0;

        foreach (var entry in document.Registry)
        {
            try
            {
                if (!Enum.TryParse<RegistryHive>(entry.Hive, out var hive) ||
                    !Enum.TryParse<RegistryValueKind>(entry.Kind, out var kind))
                {
                    failed++;
                    continue;
                }

                using var key = RegistryKeyAccess.OpenWritable(hive, entry.KeyPath, log, warn);
                if (key is null)
                {
                    failed++;
                    warn?.Invoke($"Wert {entry.KeyPath}\\{entry.ValueName} konnte nicht geschrieben werden.");
                    continue;
                }

                var value = DeserializeValue(entry);
                if (value is null)
                {
                    key.DeleteValue(entry.ValueName ?? string.Empty, throwOnMissingValue: false);
                }
                else
                {
                    key.SetValue(entry.ValueName ?? string.Empty, value, kind);
                }

                restored++;
            }
            catch (Exception ex)
            {
                failed++;
                warn?.Invoke($"Wiederherstellen von {entry.KeyPath}\\{entry.ValueName} fehlgeschlagen: {ex.Message}");
            }
        }

        return (restored, failed);
    }

    private static object? DeserializeValue(RegistryValueSnapshot entry)
    {
        return entry.Encoding switch
        {
            "base64" => Convert.FromBase64String(entry.Data),
            "numeric" when entry.Kind == nameof(RegistryValueKind.QWord) => ulong.Parse(entry.Data, System.Globalization.CultureInfo.InvariantCulture),
            "numeric" => uint.Parse(entry.Data, System.Globalization.CultureInfo.InvariantCulture),
            "multistring" => entry.Data.Split('\n'),
            _ => entry.Data,
        };
    }
}

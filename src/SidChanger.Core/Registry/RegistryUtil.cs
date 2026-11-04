using System.Security.AccessControl;
using Microsoft.Win32;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;
using SidChanger.Sid;

namespace SidChanger.Core.Registry;

/// <summary>Ergebnis eines SID-Ersetzungslaufs über einen Registrierungsschlüssel.</summary>
public sealed record SidPatchResult(int ValuesChanged, int Replacements, int KeysVisited, int Errors);

/// <summary>
/// Hilfsfunktionen, um SIDs in Registrierungsbäumen zu ersetzen: in binären Werten
/// (SAM, SECURITY, TaskCache) und in Textwerten (SID-Strings).
/// </summary>
public static class RegistryUtil
{
    private const int MaxValueSize = 8 * 1024 * 1024;

    /// <summary>
    /// Durchläuft den Schlüsselbaum und ersetzt die Maschinen-SID in allen Werten.
    /// </summary>
    public static SidPatchResult PatchTree(
        RegistryKey root,
        RegistryHive hive,
        string keyPath,
        MachineSid oldSid,
        MachineSid newSid,
        BackupStore? backup,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        var result = new SidPatchResult(0, 0, 0, 0);
        var accumulator = new PatchAccumulator(result);
        PatchKeyRecursive(root, hive, keyPath, oldSid, newSid, backup, log, warn, cancellationToken, accumulator);
        return accumulator.ToResult();
    }

    private sealed class PatchAccumulator
    {
        public PatchAccumulator(SidPatchResult initial) => Current = initial;

        public SidPatchResult Current;

        public SidPatchResult ToResult() => Current;
    }

    private static void PatchKeyRecursive(
        RegistryKey key,
        RegistryHive hive,
        string keyPath,
        MachineSid oldSid,
        MachineSid newSid,
        BackupStore? backup,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken,
        PatchAccumulator accumulator)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var visited = accumulator.Current.KeysVisited + 1;
        var changed = accumulator.Current.ValuesChanged;
        var replacements = accumulator.Current.Replacements;
        var errors = accumulator.Current.Errors;

        var oldBytes = oldSid.ToSubAuthorityBytes();
        var newBytes = newSid.ToSubAuthorityBytes();

        string[] valueNames;
        try
        {
            valueNames = key.GetValueNames();
        }
        catch (Exception ex)
        {
            warn?.Invoke($"{keyPath}: Werte nicht lesbar ({ex.Message}).");
            accumulator.Current = new SidPatchResult(changed, replacements, visited, errors + 1);
            return;
        }

        foreach (var valueName in valueNames)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var kind = key.GetValueKind(valueName);
                var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

                if (kind == RegistryValueKind.Binary && value is byte[] bytes && bytes.Length is > 0 and <= MaxValueSize)
                {
                    var count = SidBinary.Count(bytes, oldBytes);
                    if (count == 0)
                    {
                        continue;
                    }

                    backup?.RecordRegistry(hive, keyPath, valueName, bytes, kind);
                    var copy = (byte[])bytes.Clone();
                    SidBinary.ReplaceAll(copy, oldBytes, newBytes);
                    key.SetValue(valueName, copy, RegistryValueKind.Binary);
                    changed++;
                    replacements += count;
                    log($"{keyPath}\\{valueName}: {count} SID-Vorkommen ersetzt.");
                }
                else if (kind is RegistryValueKind.String or RegistryValueKind.ExpandString && value is string text)
                {
                    var rewritten = SidStringRewriter.Rewrite(text, oldSid, newSid);
                    if (string.Equals(rewritten, text, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    backup?.RecordRegistry(hive, keyPath, valueName, text, kind);
                    key.SetValue(valueName, rewritten, kind);
                    changed++;
                    replacements += SidStringRewriter.Count(text, oldSid);
                    log($"{keyPath}\\{valueName}: SID-Text ersetzt.");
                }
                else if (kind == RegistryValueKind.MultiString && value is string[] lines)
                {
                    var rewritten = lines.Select(l => SidStringRewriter.Rewrite(l, oldSid, newSid)).ToArray();
                    if (rewritten.SequenceEqual(lines, StringComparer.Ordinal))
                    {
                        continue;
                    }

                    backup?.RecordRegistry(hive, keyPath, valueName, lines, kind);
                    key.SetValue(valueName, rewritten, RegistryValueKind.MultiString);
                    changed++;
                    replacements += lines.Sum(l => SidStringRewriter.Count(l, oldSid));
                }
            }
            catch (Exception ex)
            {
                errors++;
                warn?.Invoke($"{keyPath}\\{valueName}: {ex.Message}");
            }
        }

        accumulator.Current = new SidPatchResult(changed, replacements, visited, errors);

        string[] children;
        try
        {
            children = key.GetSubKeyNames();
        }
        catch (Exception ex)
        {
            warn?.Invoke($"{keyPath}: Unterschlüssel nicht lesbar ({ex.Message}).");
            accumulator.Current = accumulator.Current with { Errors = accumulator.Current.Errors + 1 };
            return;
        }

        foreach (var child in children)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var childKey = key.OpenSubKey(child, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryKeyAccess.WritableRights);
                if (childKey is null)
                {
                    warn?.Invoke($"{keyPath}\\{child}: nicht schreibbar, übersprungen.");
                    accumulator.Current = accumulator.Current with { Errors = accumulator.Current.Errors + 1 };
                    continue;
                }

                PatchKeyRecursive(childKey, hive, keyPath + "\\" + child, oldSid, newSid, backup, log, warn, cancellationToken, accumulator);
            }
            catch (Exception ex)
            {
                warn?.Invoke($"{keyPath}\\{child}: {ex.Message}");
                accumulator.Current = accumulator.Current with { Errors = accumulator.Current.Errors + 1 };
            }
        }
    }

    /// <summary>Zählt betroffene Werte, ohne etwas zu ändern (für die Analyse).</summary>
    public static SidPatchResult CountTree(RegistryKey root, string keyPath, MachineSid oldSid, CancellationToken cancellationToken)
    {
        var result = new SidPatchResult(0, 0, 0, 0);
        var oldBytes = oldSid.ToSubAuthorityBytes();
        CountKeyRecursive(root, oldSid, oldBytes, cancellationToken, ref result, keyPath);
        return result;
    }

    private static void CountKeyRecursive(
        RegistryKey key,
        MachineSid oldSid,
        byte[] oldBytes,
        CancellationToken cancellationToken,
        ref SidPatchResult result,
        string keyPath)
    {
        cancellationToken.ThrowIfCancellationRequested();
        result = result with { KeysVisited = result.KeysVisited + 1 };

        string[] valueNames;
        try
        {
            valueNames = key.GetValueNames();
        }
        catch
        {
            result = result with { Errors = result.Errors + 1 };
            return;
        }

        foreach (var valueName in valueNames)
        {
            try
            {
                var kind = key.GetValueKind(valueName);
                var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

                if (kind == RegistryValueKind.Binary && value is byte[] bytes)
                {
                    var count = SidBinary.Count(bytes, oldBytes);
                    if (count > 0)
                    {
                        result = result with
                        {
                            ValuesChanged = result.ValuesChanged + 1,
                            Replacements = result.Replacements + count,
                        };
                    }
                }
                else if (value is string text && SidStringRewriter.Count(text, oldSid) > 0)
                {
                    result = result with { ValuesChanged = result.ValuesChanged + 1 };
                }
            }
            catch
            {
                // Analyse soll nicht abbrechen
            }
        }

        string[] children;
        try
        {
            children = key.GetSubKeyNames();
        }
        catch
        {
            return;
        }

        foreach (var child in children)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var childKey = key.OpenSubKey(child, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey);
                if (childKey is not null)
                {
                    CountKeyRecursive(childKey, oldSid, oldBytes, cancellationToken, ref result, keyPath + "\\" + child);
                }
            }
            catch
            {
                result = result with { Errors = result.Errors + 1 };
            }
        }
    }

    /// <summary>Liest einen Zeichenkettenwert (auch mit Expansion).</summary>
    public static string? ReadString(RegistryHive hive, string path, string name)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            return key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Liest einen Binärwert.</summary>
    public static byte[]? ReadBinary(RegistryHive hive, string path, string name)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            return key?.GetValue(name) as byte[];
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Prüft, ob ein Registrierungsschlüssel existiert.</summary>
    public static bool KeyExists(RegistryHive hive, string path)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            return key is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Prüft, ob ein Wert existiert.</summary>
    public static bool ValueExists(RegistryHive hive, string path, string name)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            return key?.GetValue(name) is not null;
        }
        catch
        {
            return false;
        }
    }
}

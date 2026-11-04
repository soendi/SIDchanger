namespace SidChanger.Sid;

/// <summary>Bildet beliebige SIDs (mit RID) von der alten auf die neue Maschinen-SID ab.</summary>
public static class SidMapping
{
    /// <summary>
    /// Versucht eine SID umzuschreiben. Nur SIDs, die zur alten Maschinen-SID gehören,
    /// werden verändert; RID und Nachkommastellen bleiben erhalten.
    /// </summary>
    public static bool TryMap(string? sidText, MachineSid oldSid, MachineSid newSid, out string mapped)
    {
        mapped = sidText ?? string.Empty;

        if (string.IsNullOrEmpty(sidText))
        {
            return false;
        }

        var text = sidText.Trim();

        if (text.Equals(oldSid.Value, StringComparison.OrdinalIgnoreCase))
        {
            mapped = newSid.Value;
            return true;
        }

        var prefix = oldSid.Value + "-";
        if (!text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var remainder = text[oldSid.Value.Length..]; // beginnt mit '-'
        var ridPart = remainder[1..];

        if (ridPart.Length == 0 || !ridPart.All(char.IsAsciiDigit))
        {
            return false;
        }

        mapped = newSid.Value + remainder;
        return true;
    }

    /// <summary>Prüft, ob eine SID zur angegebenen Maschinen-SID gehört.</summary>
    public static bool BelongsToMachine(string? sidText, MachineSid machineSid)
    {
        if (string.IsNullOrEmpty(sidText))
        {
            return false;
        }

        var text = sidText.Trim();
        return text.Equals(machineSid.Value, StringComparison.OrdinalIgnoreCase) ||
               text.StartsWith(machineSid.Value + "-", StringComparison.OrdinalIgnoreCase);
    }
}

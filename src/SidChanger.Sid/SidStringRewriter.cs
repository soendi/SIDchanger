using System.Text.RegularExpressions;

namespace SidChanger.Sid;

/// <summary>
/// Ersetzt Text-SIDs der alten Maschinen-SID durch die neue, z. B. in Aufgaben-XML,
/// Registrierungswerten oder Konfigurationsdateien.
/// </summary>
public static partial class SidStringRewriter
{
    /// <summary>Ersetzt alle Vorkommen von <paramref name="oldSid"/> (auch mit RID) durch die neue SID.</summary>
    public static string Rewrite(string? text, MachineSid oldSid, MachineSid newSid)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var oldPrefix = oldSid.Value;
        if (text.IndexOf(oldPrefix, StringComparison.OrdinalIgnoreCase) < 0)
        {
            return text;
        }

        // Nur an einer RID-Grenze ersetzen, damit S-1-5-21-1-2-3 nicht in S-1-5-21-1-2-30 trifft.
        return Regex.Replace(
            text,
            Regex.Escape(oldPrefix) + @"(?![\d])",
            newSid.Value,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>Zählt, wie viele Text-SIDs der Maschinen-SID in einem Text enthalten sind.</summary>
    public static int Count(string? text, MachineSid oldSid)
    {
        if (string.IsNullOrEmpty(text))
        {
            return 0;
        }

        return Regex.Matches(
            text,
            Regex.Escape(oldSid.Value) + @"(?![\d])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).Count;
    }
}

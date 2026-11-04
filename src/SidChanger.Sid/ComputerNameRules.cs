namespace SidChanger.Sid;

/// <summary>Prüft Computernamen nach den Regeln von Windows (NetBIOS, max. 15 Zeichen).</summary>
public static class ComputerNameRules
{
    public const int MaxLength = 15;

    private static readonly char[] ForbiddenChars = { '\\', '/', ':', '*', '?', '"', '<', '>', '|', ' ', ',', ';', '=', '+', '[', ']', '@', '!', '#', '$', '%', '&', '\'', '(', ')', '~', '`', '{', '}' };

    /// <summary>
    /// Prüft einen Computernamen und liefert eine Liste von Fehlern (leer = gültig).
    /// </summary>
    public static IReadOnlyList<string> Validate(string? name)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(name))
        {
            errors.Add("Der Computername darf nicht leer sein.");
            return errors;
        }

        var trimmed = name.Trim();

        if (trimmed.Length > MaxLength)
        {
            errors.Add($"Der Computername darf maximal {MaxLength} Zeichen lang sein (NetBIOS-Grenze).");
        }

        if (trimmed.IndexOfAny(ForbiddenChars) >= 0)
        {
            errors.Add("Der Computername enthält unzulässige Zeichen (erlaubt sind Buchstaben, Ziffern und Bindestriche).");
        }

        if (trimmed.All(char.IsDigit))
        {
            errors.Add("Der Computername darf nicht ausschließlich aus Ziffern bestehen.");
        }

        if (trimmed.StartsWith('-') || trimmed.EndsWith('-'))
        {
            errors.Add("Der Computername darf nicht mit einem Bindestrich beginnen oder enden.");
        }

        if (trimmed.Any(c => c > 127))
        {
            errors.Add("Der Computername darf nur ASCII-Zeichen enthalten (keine Umlaute oder Sonderzeichen).");
        }

        if (trimmed.StartsWith('.') || trimmed.EndsWith('.'))
        {
            errors.Add("Der Computername darf nicht mit einem Punkt beginnen oder enden.");
        }

        return errors;
    }

    public static bool IsValid(string? name) => Validate(name).Count == 0;

    /// <summary>Entfernt Leerraum und wandelt in Großbuchstaben (Windows-Konvention).</summary>
    public static string Normalize(string? name) =>
        string.IsNullOrWhiteSpace(name) ? string.Empty : name.Trim().ToUpperInvariant();

    /// <summary>
    /// Ersetzt Platzhalter wie bei SIDCHG: '?' = zufälliges Hex-Zeichen,
    /// '*' = MAC-Adresse des ersten aktiven Adapters (hex, ohne Trenner).
    /// </summary>
    public static string ExpandWildcards(string? pattern, string? macAddressHex)
    {
        if (string.IsNullOrEmpty(pattern))
        {
            return string.Empty;
        }

        var mac = (macAddressHex ?? string.Empty).Replace(":", string.Empty).Replace("-", string.Empty);
        var builder = new System.Text.StringBuilder();

        foreach (var c in pattern)
        {
            switch (c)
            {
                case '?':
                    builder.Append("0123456789ABCDEF"[Random.Shared.Next(16)]);
                    break;
                case '*':
                    builder.Append(mac);
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        var result = builder.ToString();
        return result.Length > MaxLength ? result[..MaxLength] : result;
    }
}

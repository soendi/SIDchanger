namespace SidChanger.Sid;

/// <summary>
/// Byte-Operationen, mit denen die Sub-Authorities einer Maschinen-SID in beliebigen
/// Binärblobs (SAM, SECURITY, DPAPI-Masterkeys, ...) gesucht und ersetzt werden.
/// </summary>
public static class SidBinary
{
    /// <summary>Zählt das Vorkommen eines Musters.</summary>
    public static int Count(ReadOnlySpan<byte> data, ReadOnlySpan<byte> pattern)
    {
        if (pattern.IsEmpty || data.Length < pattern.Length)
        {
            return 0;
        }

        var count = 0;
        var offset = 0;
        while (offset <= data.Length - pattern.Length)
        {
            var index = data[offset..].IndexOf(pattern);
            if (index < 0)
            {
                break;
            }

            count++;
            offset += index + pattern.Length;
        }

        return count;
    }

    /// <summary>Ersetzt alle Vorkommen eines Musters gleicher Länge.</summary>
    public static int ReplaceAll(Span<byte> data, ReadOnlySpan<byte> oldPattern, ReadOnlySpan<byte> newPattern)
    {
        if (oldPattern.Length != newPattern.Length)
        {
            throw new ArgumentException("Altes und neues Muster müssen gleich lang sein.", nameof(newPattern));
        }

        if (oldPattern.IsEmpty || data.Length < oldPattern.Length)
        {
            return 0;
        }

        var replacements = 0;
        var offset = 0;
        while (offset <= data.Length - oldPattern.Length)
        {
            var index = data[offset..].IndexOf(oldPattern);
            if (index < 0)
            {
                break;
            }

            var absolute = offset + index;
            newPattern.CopyTo(data.Slice(absolute, newPattern.Length));
            replacements++;
            offset = absolute + oldPattern.Length;
        }

        return replacements;
    }

    /// <summary>
    /// Sucht die erste vollständige Domänen-SID (24 Byte, Präfix 01 04 .. 05 15 ..) im Blob.
    /// </summary>
    public static bool TryFindDomainSid(ReadOnlySpan<byte> data, out MachineSid? sid)
    {
        sid = null;
        var prefix = MachineSid.DomainPrefix;
        var start = 0;

        while (start <= data.Length - MachineSid.BinaryLength)
        {
            var index = data[start..].IndexOf(prefix);
            if (index < 0)
            {
                return false;
            }

            var absolute = start + index;
            if (absolute + MachineSid.BinaryLength <= data.Length &&
                MachineSid.TryFromBinary(data.Slice(absolute, MachineSid.BinaryLength), out sid))
            {
                return true;
            }

            start = absolute + 1;
        }

        return false;
    }
}

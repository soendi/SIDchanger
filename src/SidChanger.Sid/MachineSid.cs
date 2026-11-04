using System.Globalization;

namespace SidChanger.Sid;

/// <summary>
/// Lokale Computer-SID ("Maschinen-SID") im Format S-1-5-21-A-B-C (ohne RID).
/// Binär besteht sie aus 24 Byte: Revision, Anzahl Sub-Authorities, 6-Byte-Authority (NT = 5)
/// und vier Little-Endian-DWORDs (21, A, B, C).
/// </summary>
public sealed class MachineSid : IEquatable<MachineSid>
{
    /// <summary>Länge der vollständigen Domänen-SID in Byte (ohne RID).</summary>
    public const int BinaryLength = 24;

    /// <summary>Länge der drei variablen Sub-Authorities in Byte (A, B, C).</summary>
    public const int SubAuthorityLength = 12;

    /// <summary>Byte-Präfix jeder lokalen Domänen-SID: 01 04 00 00 00 00 00 05 15 00 00 00.</summary>
    public static ReadOnlySpan<byte> DomainPrefix => new byte[]
    {
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00
    };

    public MachineSid(uint authority1, uint authority2, uint authority3)
    {
        Authority1 = authority1;
        Authority2 = authority2;
        Authority3 = authority3;
    }

    public uint Authority1 { get; }
    public uint Authority2 { get; }
    public uint Authority3 { get; }

    /// <summary>Die drei Sub-Authorities als Little-Endian-Bytes (12 Byte).</summary>
    public byte[] ToSubAuthorityBytes()
    {
        var buffer = new byte[SubAuthorityLength];
        BitConverter.TryWriteBytes(buffer.AsSpan(0, 4), Authority1);
        BitConverter.TryWriteBytes(buffer.AsSpan(4, 4), Authority2);
        BitConverter.TryWriteBytes(buffer.AsSpan(8, 4), Authority3);
        return buffer;
    }

    /// <summary>Vollständige 24-Byte-Domänen-SID.</summary>
    public byte[] ToBinary()
    {
        var buffer = new byte[BinaryLength];
        DomainPrefix.CopyTo(buffer);
        ToSubAuthorityBytes().CopyTo(buffer, DomainPrefix.Length);
        return buffer;
    }

    /// <summary>SID des lokalen Kontos mit dem angegebenen RID, z. B. S-1-5-21-A-B-C-500.</summary>
    public string WithRid(uint rid) => Value + "-" + rid.ToString(CultureInfo.InvariantCulture);

    /// <summary>Textform ohne RID, z. B. S-1-5-21-1-2-3.</summary>
    public string Value =>
        string.Create(CultureInfo.InvariantCulture,
            $"S-1-5-21-{Authority1}-{Authority2}-{Authority3}");

    public bool Equals(MachineSid? other) =>
        other is not null &&
        Authority1 == other.Authority1 &&
        Authority2 == other.Authority2 &&
        Authority3 == other.Authority3;

    public override bool Equals(object? obj) => Equals(obj as MachineSid);

    public override int GetHashCode() => HashCode.Combine(Authority1, Authority2, Authority3);

    public override string ToString() => Value;

    /// <summary>
    /// Liest die Domänen-SID aus einem binären SID-Blob (24 Byte oder länger, z. B. 28 Byte mit RID).
    /// </summary>
    public static bool TryFromBinary(ReadOnlySpan<byte> binary, out MachineSid? sid)
    {
        sid = null;
        if (binary.Length < BinaryLength)
        {
            return false;
        }

        if (!binary[..DomainPrefix.Length].SequenceEqual(DomainPrefix))
        {
            return false;
        }

        sid = new MachineSid(
            BitConverter.ToUInt32(binary.Slice(12, 4)),
            BitConverter.ToUInt32(binary.Slice(16, 4)),
            BitConverter.ToUInt32(binary.Slice(20, 4)));
        return true;
    }

    /// <summary>Parst eine Text-SID der Form S-1-5-21-A-B-C (RID ist nicht erlaubt).</summary>
    public static bool TryParse(string? text, out MachineSid? sid, out string error)
    {
        sid = null;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "Die SID ist leer.";
            return false;
        }

        var parts = text.Trim().Split('-');
        if (parts.Length != 7)
        {
            error = "Die SID muss die Form S-1-5-21-A-B-C haben (ohne RID am Ende).";
            return false;
        }

        if (!string.Equals(parts[0], "S", StringComparison.OrdinalIgnoreCase) || parts[1] != "1")
        {
            error = "Die SID muss mit \"S-1-\" beginnen.";
            return false;
        }

        if (parts[2] != "5" || parts[3] != "21")
        {
            error = "Es wird eine lokale Computer-SID (S-1-5-21-...) erwartet.";
            return false;
        }

        if (!uint.TryParse(parts[4], NumberStyles.None, CultureInfo.InvariantCulture, out var a) ||
            !uint.TryParse(parts[5], NumberStyles.None, CultureInfo.InvariantCulture, out var b) ||
            !uint.TryParse(parts[6], NumberStyles.None, CultureInfo.InvariantCulture, out var c))
        {
            error = "A, B und C müssen ganze Zahlen zwischen 0 und 4294967295 sein.";
            return false;
        }

        if (a == 0 && b == 0 && c == 0)
        {
            error = "A, B und C dürfen nicht alle 0 sein.";
            return false;
        }

        sid = new MachineSid(a, b, c);
        return true;
    }

    /// <summary>
    /// Prüft, ob die Text-SID zum Schema einer lokalen Domänen-SID passt (auch mit RID).
    /// </summary>
    public static bool LooksLikeLocalSid(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Trim().StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);
    }
}

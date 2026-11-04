using System.Security.Cryptography;

namespace SidChanger.Sid;

/// <summary>Erzeugt kryptografisch zufällige lokale Computer-SIDs.</summary>
public static class SidGenerator
{
    /// <summary>
    /// Erzeugt eine zufällige Maschinen-SID. Die drei Sub-Authorities sind niemals
    /// alle 0 und niemals identisch (das wäre keine gültige, eindeutige SID).
    /// </summary>
    public static MachineSid CreateRandom()
    {
        while (true)
        {
            var bytes = new byte[MachineSid.SubAuthorityLength];
            RandomNumberGenerator.Fill(bytes);

            var a = BitConverter.ToUInt32(bytes, 0);
            var b = BitConverter.ToUInt32(bytes, 4);
            var c = BitConverter.ToUInt32(bytes, 8);

            if (a == 0 && b == 0 && c == 0)
            {
                continue;
            }

            if (a == b && b == c)
            {
                continue;
            }

            return new MachineSid(a, b, c);
        }
    }
}
